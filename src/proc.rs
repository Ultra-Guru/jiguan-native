//! /proc 文件系统解析 —— 零依赖手写解析器。
//!
//! - [`list_processes`]: 枚举 /proc 下全部进程 (cmdline 优先, comm 兜底);
//! - [`parse_maps`]: 解析 /proc/<pid>/maps 文本;
//! - [`scan_regions`]: 过滤出可扫描区域 (rw- 与 r-x)。
//!
//! maps 行格式 (内核 seq_file 输出, 路径字段可含空格, 可缺省):
//!
//! ```text
//! 55d1a2b6b000-55d1a2b8c000 r--p 00000000 fd:01 1234567   /usr/bin/cat
//! 7ffd1c5a1000-7ffd1c5c2000 rw-p 00000000 00:00 0          [heap]
//! 7f2c1a000000-7f2c1a021000 rw-p 00000000 00:00 0
//! ```

use std::fs;
use std::io;

/// 一个进程的概要信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// 进程 id
    pub pid: i32,
    /// 进程名: 优先 cmdline 的 argv[0], 内核线程回退 comm
    pub name: String,
}

/// /proc/<pid>/maps 中的一行区域。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapsRegion {
    /// 起始地址 (含)
    pub start: u64,
    /// 结束地址 (不含)
    pub end: u64,
    /// 权限串, 如 "rw-p" / "r-xp" / "rwxs"
    pub perms: String,
    /// 文件内偏移 (十六进制)
    pub offset: u64,
    /// 设备号 "major:minor"
    pub dev: String,
    /// inode
    pub inode: u64,
    /// 映射路径; 匿名映射为空串, 伪文件为 "[heap]" / "[stack]" / "[vdso]" 等
    pub path: String,
}

impl MapsRegion {
    /// 区域字节大小。
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    /// 是否可写 (rw-*)。
    pub fn is_writable(&self) -> bool {
        self.perms.starts_with("rw")
    }

    /// 是否可执行 (r-x*)。
    pub fn is_executable(&self) -> bool {
        self.perms.starts_with('r') && self.perms.contains('x')
    }

    /// 是否为内存扫描目标区域: rw- (数值区) 或 r-x (代码区)。
    ///
    /// 刻意排除: r-- 只读数据 (含 ELF 头, 值不变化) 与 --- 保护区。
    pub fn is_scan_target(&self) -> bool {
        self.is_writable() || self.is_executable()
    }

    /// 还原为一行标准 maps 格式 (与内核 `%016lx-%016lx` 对齐),
    /// 供 JNI `scanRegions` 逐行返回给 Kotlin 侧。
    pub fn to_map_line(&self) -> String {
        let mut line = format!(
            "{:016x}-{:016x} {} {:08x} {} {}",
            self.start, self.end, self.perms, self.offset, self.dev, self.inode
        );
        if !self.path.is_empty() {
            line.push(' ');
            line.push_str(&self.path);
        }
        line
    }
}

/// 枚举 /proc 下全部进程, 按 pid 升序。
pub fn list_processes() -> io::Result<Vec<ProcessInfo>> {
    let mut out = Vec::new();
    for entry in fs::read_dir("/proc")?.flatten() {
        let fname = entry.file_name();
        let Some(name) = fname.to_str() else { continue };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if pid <= 0 {
            continue;
        }
        out.push(ProcessInfo {
            pid,
            name: read_process_name(pid),
        });
    }
    out.sort_unstable_by_key(|p| p.pid);
    Ok(out)
}

/// 进程名: cmdline 的 argv[0] 优先, 回退 comm, 再兜底空串。
fn read_process_name(pid: i32) -> String {
    if let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) {
        // cmdline 以 NUL 分隔参数; 取 argv[0] 并容忍尾部脏字节
        if let Some(first) = raw.split(|&b| b == 0).next() {
            let s = String::from_utf8_lossy(first).trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    if let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) {
        let s = comm.trim();
        if !s.is_empty() {
            return s.to_string();
        }
    }
    String::new()
}

/// 读取 /proc/<pid>/maps 全文。
pub fn read_maps(pid: i32) -> io::Result<String> {
    fs::read_to_string(format!("/proc/{pid}/maps"))
}

/// 解析 maps 文本; 无法解析的行静默跳过 (内核保证格式, 容错防炸)。
pub fn parse_maps(text: &str) -> Vec<MapsRegion> {
    text.lines().filter_map(parse_map_line).collect()
}

/// 解析单行 maps。手写分词: 前 5 个字段定长语义,
/// 第 6 个字段 (路径) 允许包含空格, 因此不能简单 split_whitespace。
fn parse_map_line(line: &str) -> Option<MapsRegion> {
    let (f_addr, rest) = next_token(line)?;
    let (f_perms, rest) = next_token(rest)?;
    let (f_offset, rest) = next_token(rest)?;
    let (f_dev, rest) = next_token(rest)?;
    let (f_inode, rest) = next_token(rest)?;
    let path = rest.trim_start();

    // perms 必须是 4 个合法字符 (r/w/x/- + s/p 组合)
    if f_perms.len() != 4
        || !f_perms
            .bytes()
            .all(|b| matches!(b, b'r' | b'w' | b'x' | b'-' | b's' | b'p'))
    {
        return None;
    }
    let (start_s, end_s) = f_addr.split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end = u64::from_str_radix(end_s, 16).ok()?;
    if end <= start {
        return None;
    }
    let offset = u64::from_str_radix(f_offset, 16).ok()?;
    let inode = f_inode.parse::<u64>().ok()?;
    if !f_dev.contains(':') {
        return None;
    }
    Some(MapsRegion {
        start,
        end,
        perms: f_perms.to_string(),
        offset,
        dev: f_dev.to_string(),
        inode,
        path: path.to_string(),
    })
}

/// 取出下一个空白分隔 token, 返回 (token, 余下原文)。
fn next_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    Some((&s[..end], &s[end..]))
}

/// 列出可扫描区域 (rw- 与 r-x), 保持 maps 原始顺序。
///
/// 供 JNI `scanRegions` 与 [`crate::scan::scan_memory`] 使用。
pub fn scan_regions(pid: i32) -> io::Result<Vec<MapsRegion>> {
    let text = read_maps(pid)?;
    Ok(parse_maps(&text)
        .into_iter()
        .filter(MapsRegion::is_scan_target)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实世界样本: 文件映射 / 匿名区 / [heap] / 伪文件 / 多空格对齐。
    const SAMPLE: &str = "\
55d1a2b6b000-55d1a2b8c000 r--p 00000000 fd:01 1234567   /usr/bin/cat
55d1a2b8c000-55d1a2b92000 r-xp 00021000 fd:01 1234567   /usr/bin/cat
55d1a2b92000-55d1a2b97000 rw-p 00026000 fd:01 1234567   /usr/bin/cat
7f2c1a000000-7f2c1a021000 rw-p 00000000 00:00 0
7f2c1a021000-7f2c1a06d000 ---p 00000000 00:00 0
7ffd1c5a1000-7ffd1c5c2000 rw-p 00000000 00:00 0    [heap]
7ffd1c5c2000-7ffd1c5c3000 r-xp 00000000 00:00 0    [vdso]
7ffd1c5c3000-7ffd1c5c5000 r--p 00000000 00:00 0    [vvar]
";

    #[test]
    fn parse_maps_full_file_backed_line() {
        let regions = parse_maps(SAMPLE);
        assert_eq!(regions.len(), 8);
        let first = &regions[0];
        assert_eq!(first.start, 0x55d1a2b6b000);
        assert_eq!(first.end, 0x55d1a2b8c000);
        assert_eq!(first.perms, "r--p");
        assert_eq!(first.offset, 0);
        assert_eq!(first.dev, "fd:01");
        assert_eq!(first.inode, 1234567);
        assert_eq!(first.path, "/usr/bin/cat");
        assert_eq!(first.size(), 0x21000);
    }

    #[test]
    fn parse_maps_anonymous_and_pseudo_regions() {
        let regions = parse_maps(SAMPLE);
        // 匿名区: 路径为空
        let anon = &regions[3];
        assert_eq!(anon.perms, "rw-p");
        assert!(anon.path.is_empty());
        assert_eq!(anon.inode, 0);
        // [heap] 与 [vdso] 路径保留
        assert_eq!(regions[5].path, "[heap]");
        assert_eq!(regions[6].path, "[vdso]");
    }

    #[test]
    fn parse_maps_malformed_lines_are_skipped() {
        let bad = "this is not a map line\n\
                   30-12 r--p 00000000 fd:01 1 /tmp/x\n\
                   100-200 zzzz 00000000 fd:01 1 /tmp/x\n\
                   100-200 r--p 00000000 fd01 1 /tmp/x\n\
                   100-200 r--p ZZ 00:01 1 /tmp/x\n\
                   100-200 r--p 00000000 fd:01 notaninode /tmp/x\n";
        assert!(parse_maps(bad).is_empty());
        // 混在正常行中不影响其它行解析
        let mixed = format!("{bad}100-200 r--p 00000000 fd:01 1 /tmp/ok");
        assert_eq!(parse_maps(&mixed).len(), 1);
    }

    #[test]
    fn maps_roundtrip_to_map_line() {
        let regions = parse_maps(SAMPLE);
        // 重新解析 to_map_line 输出应得到等价区域 (单空格规范化)
        let relines: Vec<String> = regions.iter().map(MapsRegion::to_map_line).collect();
        let reparsed = parse_maps(&relines.join("\n"));
        assert_eq!(reparsed.len(), regions.len());
        for (a, b) in regions.iter().zip(reparsed.iter()) {
            assert_eq!(a, b);
        }
        // 文件映射行格式抽查
        assert_eq!(
            regions[0].to_map_line(),
            "55d1a2b6b000-55d1a2b8c000 r--p 00000000 fd:01 1234567 /usr/bin/cat"
        );
        // 匿名行不带尾随空格
        assert_eq!(
            regions[3].to_map_line(),
            "7f2c1a000000-7f2c1a021000 rw-p 00000000 00:00 0"
        );
    }

    #[test]
    fn scan_target_filter_keeps_rw_and_rx() {
        let regions = parse_maps(SAMPLE);
        let targets: Vec<&MapsRegion> = regions.iter().filter(|r| r.is_scan_target()).collect();
        // r-- 与 --- 被排除; rw-(3 处) 与 r-x(2 处) 保留
        assert_eq!(targets.len(), 5);
        assert!(targets.iter().all(|r| r.is_writable() || r.is_executable()));
        // scan_regions 与过滤逻辑一致地作用于自身进程
        let mine = scan_regions(std::process::id() as i32).expect("读取自身 maps");
        assert!(!mine.is_empty());
        assert!(mine.iter().all(MapsRegion::is_scan_target));
        // [vvar] (r--) 这类区域必然不在其中
        assert!(!mine.iter().any(|r| r.path == "[vvar]"));
    }

    #[test]
    fn list_processes_includes_self() {
        let procs = list_processes().expect("枚举 /proc");
        let me = std::process::id() as i32;
        let found = procs
            .iter()
            .find(|p| p.pid == me)
            .expect("必须能枚举到自身");
        assert!(!found.name.is_empty(), "自身进程名不应为空");
    }
}
