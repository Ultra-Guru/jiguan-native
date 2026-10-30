//! AOB (Array-of-Bytes) 特征扫描。
//!
//! - [`parse_pattern`]: `"DE AD ?? ?? EF"` 风格模式 → `Vec<Option<u8>>`
//!   (`??` 通配; 支持小写 / 1~2 位单字节 / 无空格紧凑串如 `DEAD??EF`);
//! - [`scan_buffer`]: 首锚点跳优朴素扫描 —— 以模式中第一个确定字节做快筛,
//!   确定性足够、无边界陷阱, 配合 1MB 分块吞吐可观;
//! - [`scan_memory`]: 遍历 [`crate::proc::scan_regions`] 区域,
//!   1MB 分块 + 跨块重叠读取, 输出绝对地址; 逐区域容错 (3 次读失败即跳过)。

use std::fmt;
use std::io;
use std::io::{Error, ErrorKind};

use crate::mem::MemHandle;
use crate::proc;

/// 每块读取的字节数 (1 MiB)。
pub const CHUNK_SIZE: usize = 1024 * 1024;
/// 单区域最大连续读失败次数, 超过即跳过该区域 (如 vvar 类特殊映射)。
pub const MAX_REGION_READ_ERRORS: usize = 3;

/// 模式解析错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// 空模式 (trim 后没有任何 token)
    EmptyPattern,
    /// 非法 token, 携带原文
    InvalidToken(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::EmptyPattern => write!(f, "空扫描模式"),
            ScanError::InvalidToken(t) => write!(f, "非法模式片段: {t:?}"),
        }
    }
}

impl std::error::Error for ScanError {}

/// 解析 AOB 模式串。
///
/// 规则 (确定性优先):
/// - 空白分隔 token; `??` 恰好一个通配字节;
/// - 1~2 位十六进制 (大小写不敏感) 是一个确定字节;
/// - 偶数长度的更长 token 按字节对展开 (支持 `DEAD??EF` 紧凑写法);
/// - 奇数长度、非十六进制字符、孤立的 `?` 均为 `InvalidToken`;
/// - 解析结果为空 → `EmptyPattern`。
pub fn parse_pattern(pattern: &str) -> Result<Vec<Option<u8>>, ScanError> {
    let mut out = Vec::new();
    for tok in pattern.split_whitespace() {
        push_token(&mut out, tok)?;
    }
    if out.is_empty() {
        return Err(ScanError::EmptyPattern);
    }
    Ok(out)
}

/// 展开 token 为字节 (含通配)。
fn push_token(out: &mut Vec<Option<u8>>, tok: &str) -> Result<(), ScanError> {
    let bytes = tok.as_bytes();
    match bytes.len() {
        // split_whitespace 不会给出空 token, 0 分支防御性处理
        0 => Ok(()),
        1..=2 => {
            if tok == "??" {
                out.push(None);
                Ok(())
            } else if tok.contains('?') {
                Err(ScanError::InvalidToken(tok.to_string()))
            } else {
                out.push(Some(hex_byte(tok).ok_or_else(|| ScanError::InvalidToken(tok.to_string()))?));
                Ok(())
            }
        }
        _ => {
            if bytes.len() % 2 != 0 {
                return Err(ScanError::InvalidToken(tok.to_string()));
            }
            for pair in bytes.chunks_exact(2) {
                let s = std::str::from_utf8(pair)
                    .map_err(|_| ScanError::InvalidToken(tok.to_string()))?;
                if s == "??" {
                    out.push(None);
                } else if s.contains('?') {
                    return Err(ScanError::InvalidToken(tok.to_string()));
                } else {
                    out.push(Some(
                        hex_byte(s).ok_or_else(|| ScanError::InvalidToken(tok.to_string()))?,
                    ));
                }
            }
            Ok(())
        }
    }
}

/// 单字节十六进制解析; 长度必须为 1~2。
fn hex_byte(s: &str) -> Option<u8> {
    if s.is_empty() || s.len() > 2 {
        return None;
    }
    u8::from_str_radix(s, 16).ok()
}

/// 在缓冲中找出全部命中偏移。
///
/// 算法: 取模式中**第一个确定字节**为锚点 (全通配时锚在 0 位),
/// 逐位快筛锚字节, 命中后再整模式比对 —— 最坏 O(n·m),
/// 实际模式首字节多为确定字节, 吞吐接近 memchr。
///
/// 空模式是调用方 bug, 返回 `Err(EmptyPattern)`; 干草堆短于模式返回空集。
pub fn scan_buffer(hay: &[u8], pattern: &[Option<u8>]) -> Result<Vec<usize>, ScanError> {
    if pattern.is_empty() {
        return Err(ScanError::EmptyPattern);
    }
    if hay.len() < pattern.len() {
        return Ok(Vec::new());
    }
    let anchor_idx = pattern.iter().position(|b| b.is_some()).unwrap_or(0);
    let anchor = pattern[anchor_idx];
    let mut out = Vec::new();
    let last = hay.len() - pattern.len();
    let mut i = 0usize;
    while i <= last {
        // 锚点快筛: 锚位字节不匹配则滑动 1
        if let Some(a) = anchor {
            if hay[i + anchor_idx] != a {
                i += 1;
                continue;
            }
        }
        let mut matched = true;
        for (k, p) in pattern.iter().enumerate() {
            if let Some(v) = *p {
                if hay[i + k] != v {
                    matched = false;
                    break;
                }
            }
        }
        if matched {
            out.push(i);
        }
        i += 1;
    }
    Ok(out)
}

/// 遍历目标进程的可扫区域执行 AOB 扫描, 返回命中绝对地址 (升序)。
///
/// - 每区域按 [`CHUNK_SIZE`] 分块, 块尾附加 (模式长-1) 重叠字节,
///   保证跨块边界的命中不丢失; 主区命中即刻收录, 重叠区命中留给下一块,
///   天然去重;
/// - 命中数达到 `max_results` 提前收工;
/// - 单区域累计 3 次读错误即跳过 (特殊映射不拖垮全局扫描)。
pub fn scan_memory(
    handle: &MemHandle,
    pattern: &[Option<u8>],
    max_results: usize,
) -> io::Result<Vec<u64>> {
    if pattern.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, ScanError::EmptyPattern.to_string()));
    }
    if max_results == 0 {
        return Ok(Vec::new());
    }
    let overlap = pattern.len() - 1;
    let regions = proc::scan_regions(handle.pid())?;
    let mut hits: Vec<u64> = Vec::new();
    for region in regions {
        let mut read_errors = 0usize;
        let mut base = region.start;
        while base < region.end && hits.len() < max_results {
            let main = ((region.end - base) as usize).min(CHUNK_SIZE);
            let total = (main + overlap).min((region.end - base) as usize);
            match handle.read(base, total) {
                Ok(buf) => {
                    if let Ok(offsets) = scan_buffer(&buf, pattern) {
                        for off in offsets {
                            // 只收主区 (off < main) 命中; 重叠区命中由下一块主区收录
                            if off < main {
                                hits.push(base + off as u64);
                                if hits.len() >= max_results {
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    read_errors += 1;
                    log::debug!("scan: 区域 {base:#x} 读取失败({e}), 第 {read_errors} 次");
                    if read_errors >= MAX_REGION_READ_ERRORS {
                        break;
                    }
                }
            }
            base += main as u64;
        }
        if hits.len() >= max_results {
            break;
        }
    }
    Ok(hits)
}

/// 便捷入口: 解析模式串并执行扫描。
/// 模式非法折叠为 `EINVAL` IO 错误 (JNI 边界据此返回 null)。
pub fn scan_memory_pattern(
    handle: &MemHandle,
    pattern: &str,
    max_results: usize,
) -> io::Result<Vec<u64>> {
    let parsed = parse_pattern(pattern)
        .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?;
    scan_memory(handle, &parsed, max_results)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 扫描靶场: 非零初值落在 .data (rw-), 保证被 scan_regions 收录。
    /// 唯一特征序列 CA FE 13 37 BA BE 埋在 0x11 填充里, 偏移 16。
    static mut SCAN_HAYSTACK: [u8; 64] = {
        let mut a = [0x11u8; 64];
        a[16] = 0xCA;
        a[17] = 0xFE;
        a[18] = 0x13;
        a[19] = 0x37;
        a[20] = 0xBA;
        a[21] = 0xBE;
        a
    };

    #[test]
    fn parse_pattern_with_wildcards() {
        let p = parse_pattern("DE AD ?? ?? EF").expect("标准模式");
        assert_eq!(p, vec![Some(0xDE), Some(0xAD), None, None, Some(0xEF)]);
    }

    #[test]
    fn parse_pattern_lowercase_and_single_digits() {
        let p = parse_pattern("de ad be ef").expect("小写");
        assert_eq!(p, vec![Some(0xDE), Some(0xAD), Some(0xBE), Some(0xEF)]);
        let p2 = parse_pattern("D E A D 0 1").expect("单字符 token");
        assert_eq!(p2, vec![Some(0x0D), Some(0x0E), Some(0x0A), Some(0x0D), Some(0x00), Some(0x01)]);
    }

    #[test]
    fn parse_pattern_compact_mixed() {
        // 无空格紧凑写法: 确定字节与通配混排
        let p = parse_pattern("DEAD??EF").expect("紧凑模式");
        assert_eq!(p, vec![Some(0xDE), Some(0xAD), None, Some(0xEF)]);
        let p2 = parse_pattern("cafe????beef").expect("长紧凑模式");
        assert_eq!(p2, vec![Some(0xCA), Some(0xFE), None, None, Some(0xBE), Some(0xEF)]);
    }

    #[test]
    fn parse_pattern_errors() {
        assert_eq!(parse_pattern(""), Err(ScanError::EmptyPattern));
        assert_eq!(parse_pattern("   \t "), Err(ScanError::EmptyPattern));
        assert_eq!(parse_pattern("ZZ"), Err(ScanError::InvalidToken("ZZ".into())));
        assert_eq!(parse_pattern("DE Q1"), Err(ScanError::InvalidToken("Q1".into())));
        // 孤立 ? / 三个 ? / 奇数长度紧凑串都非法
        assert_eq!(parse_pattern("?"), Err(ScanError::InvalidToken("?".into())));
        assert_eq!(parse_pattern("???"), Err(ScanError::InvalidToken("???".into())));
        assert_eq!(parse_pattern("ABC"), Err(ScanError::InvalidToken("ABC".into())));
        // 错误信息可读
        let msg = parse_pattern("XYZ").unwrap_err().to_string();
        assert!(msg.contains("XYZ"), "错误信息应包含原文: {msg}");
    }

    #[test]
    fn scan_buffer_finds_all_fixed() {
        let hay = b"ABCABCXABC";
        let pat = parse_pattern("41 42 43").unwrap(); // "ABC"
        let hits = scan_buffer(hay, &pat).unwrap();
        assert_eq!(hits, vec![0, 3, 7]);
    }

    #[test]
    fn scan_buffer_respects_wildcards() {
        // ?? 匹配任意字节
        let hay = [0x10u8, 0x20, 0x30, 0x40, 0x99, 0x20, 0x30, 0x50];
        let pat = vec![Some(0x20), None, Some(0x30)];
        let hits = scan_buffer(&hay, &pat).unwrap();
        assert_eq!(hits, vec![1, 4]);
        // 全通配模式匹配所有位置
        let all_wild = vec![None, None];
        let hits2 = scan_buffer(&hay[..4], &all_wild).unwrap();
        assert_eq!(hits2, vec![0, 1, 2]);
    }

    #[test]
    fn scan_buffer_empty_pattern_is_error() {
        let err = scan_buffer(b"anything", &[]).unwrap_err();
        assert_eq!(err, ScanError::EmptyPattern);
    }

    #[test]
    fn scan_buffer_haystack_shorter_than_pattern() {
        let pat = vec![Some(0xAA), Some(0xBB)];
        assert_eq!(scan_buffer(&[0xAA], &pat).unwrap(), Vec::<usize>::new());
        assert_eq!(scan_buffer(&[], &pat).unwrap(), Vec::<usize>::new());
    }

    #[test]
    fn scan_buffer_overlapping_matches() {
        // 重叠命中全部收录 (AAA 在 AAAAA 中命中 3 次)
        let pat = vec![Some(0x41), Some(0x41), Some(0x41)];
        let hits = scan_buffer(b"AAAAA", &pat).unwrap();
        assert_eq!(hits, vec![0, 1, 2]);
    }

    /// 端到端: 扫描自身进程, 特征串埋在 .data 静态靶场, 命中地址必须精确。
    #[test]
    fn scan_memory_finds_static_haystack_in_own_process() {
        let pid = std::process::id() as i32;
        let handle = crate::mem::MemHandle::open(pid).expect("打开自身进程");
        // SAFETY(测试): addr_of_mut! 不创建引用, 仅取静态地址
        let hay_addr = std::ptr::addr_of_mut!(SCAN_HAYSTACK) as usize as u64;
        // 通配符参与, 锁定 16 偏移处的 CA FE ?? ?? BA BE
        let hits =
            scan_memory_pattern(&handle, "CA FE ?? ?? BA BE", 8).expect("扫描自身进程");
        let expected = hay_addr + 16;
        assert!(
            hits.contains(&expected),
            "应命中靶场 {expected:#x}, 实得 {hits:#x?}"
        );
        assert!(hits.len() <= 8, "命中数不应超过 max_results");
        // 升序
        let mut sorted = hits.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, hits);
    }

    /// max_results = 0 直接空手而归; 非法模式报 EINVAL。
    #[test]
    fn scan_memory_caps_and_validates() {
        let pid = std::process::id() as i32;
        let handle = crate::mem::MemHandle::open(pid).expect("打开自身进程");
        assert!(scan_memory_pattern(&handle, "??", 0).unwrap().is_empty());
        let err = scan_memory_pattern(&handle, "not-hex", 4).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
