//! arm64 跳板编码与内联钩子登记。
//!
//! ## Trampoline (16 字节绝对跳转)
//!
//! ```text
//! 偏移  字节              指令            语义
//! 0x00  50 00 00 58      LDR X16, #8    从 PC+8 载入 8 字节立即数到 X16
//! 0x04  00 02 1F D6      BR  X16        绝对跳转 X16
//! 0x08  <target 低 64 位, 小端>          跳转目标地址
//! ```
//!
//! - `LDR X16, #8` 编码 `0x58000050`: LDR (literal, 64-bit) 即
//!   `01011000 imm19 Rt`, 其中 imm19 = 8/4 = 2, Rt = X16 = 16;
//! - `BR X16` 编码 `0xD61F0200`: `D61F0000 | (16 << 5)`;
//! - Kotlin 侧用 [`arm64_trampoline`] 生成 hook 桩 / 校验编码,
//!   确保两侧指令序列逐字节一致。

use std::io;

/// 跳板字节数。
pub const TRAMPOLINE_LEN: usize = 16;

/// `LDR X16, #8` 机器码 (小端字节序)。
const LDR_X16: [u8; 4] = [0x50, 0x00, 0x00, 0x58];
/// `BR X16` 机器码 (小端字节序)。
const BR_X16: [u8; 4] = [0x00, 0x02, 0x1F, 0xD6];

/// 生成 16 字节 arm64 绝对跳转跳板 (纯函数, 任何目标平台可调用)。
pub fn arm64_trampoline(target: u64) -> [u8; TRAMPOLINE_LEN] {
    let mut out = [0u8; TRAMPOLINE_LEN];
    out[0..4].copy_from_slice(&LDR_X16);
    out[4..8].copy_from_slice(&BR_X16);
    out[8..16].copy_from_slice(&target.to_le_bytes());
    out
}

/// 从跳板字节还原目标地址; 长度或前 8 字节编码不符返回 `None`。
///
/// 与 [`arm64_trampoline`] 互为逆运算, 供单测与 Kotlin 侧对拍校验。
pub fn decode_trampoline(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != TRAMPOLINE_LEN {
        return None;
    }
    if bytes[0..4] != LDR_X16 || bytes[4..8] != BR_X16 {
        return None;
    }
    let mut target = [0u8; 8];
    target.copy_from_slice(&bytes[8..16]);
    Some(u64::from_le_bytes(target))
}

/// 把 `[addr, addr+len)` 所在页改判为 RWX。
///
/// 内联钩子写代码段的前置条件; 调用方负责恢复语义 (见 docs/SAFETY.md)。
pub fn mprotect_rwx(addr: usize, len: usize) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: mprotect 仅修改页保护属性, 不访问内存内容;
    // addr/len 由调用方保证为本进程合法用户态区间
    let rc = unsafe {
        libc::mprotect(
            addr as *mut libc::c_void,
            len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// 指令缓存同步: 改写代码后**必须**刷新 icache, 否则取指可能命中旧指令。
///
/// - Android / aarch64 Linux: 调用 libgcc/compiler-rt 的 `__clear_cache`;
/// - x86 宿主: 硬件维护 icache 一致性, 显式刷新为 no-op (架构语义保证)。
pub fn flush_icache(addr: usize, len: usize) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    flush_icache_impl(addr, len)
}

#[cfg(any(
    target_os = "android",
    all(target_os = "linux", target_arch = "aarch64")
))]
fn flush_icache_impl(addr: usize, len: usize) -> io::Result<()> {
    extern "C" {
        /// libgcc / compiler-rt 提供的 icache 同步例程
        fn __clear_cache(beg: *const u8, end: *const u8);
    }
    let end = addr
        .checked_add(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "地址区间溢出"))?;
    // SAFETY: __clear_cache 只做缓存维护, 不读写内存内容
    unsafe { __clear_cache(addr as *const u8, end as *const u8) };
    Ok(())
}

#[cfg(not(any(
    target_os = "android",
    all(target_os = "linux", target_arch = "aarch64")
)))]
fn flush_icache_impl(_addr: usize, _len: usize) -> io::Result<()> {
    // x86: icache 自动一致性, 显式刷新为 no-op
    Ok(())
}

#[cfg(target_os = "android")]
mod inline_hook {
    //! 进程内联钩子登记簿 (仅 Android 目标编译)。
    //!
    //! install: 页改 RWX → 抢救原始 16 字节 → 写入跳板 → 刷 icache → 登记;
    //! remove:  恢复原始字节 → 刷 icache。页保护保持 RWX 语义
    //! (完整恢复原始保护位需解析 maps, 由上层按需补齐, 见 docs/SAFETY.md)。

    use super::{arm64_trampoline, flush_icache, mprotect_rwx, TRAMPOLINE_LEN};
    use std::io;
    use std::io::{Error, ErrorKind};

    /// 一枚已安装的内联钩子。
    #[derive(Debug, Clone)]
    pub struct HookRecord {
        /// 登记自增 id
        pub id: u32,
        /// 被改写的目标地址 (函数入口)
        pub target: usize,
        /// 跳转目的地 (detour 处理函数地址)
        pub handler: usize,
        /// 写入目标的 16 字节跳板
        pub trampoline: [u8; TRAMPOLINE_LEN],
        /// 抢救下来的原始 16 字节 (卸载时恢复)
        pub original: [u8; TRAMPOLINE_LEN],
        /// 当前是否生效
        pub enabled: bool,
    }

    /// 内联钩子登记簿。
    ///
    /// 线程约定: 登记簿自身非线程安全, 需要上层串行化
    /// (Kotlin 侧对单一 handle 的调用同样应串行, 见 docs/SAFETY.md)。
    #[derive(Debug)]
    pub struct HookRegistry {
        hooks: Vec<HookRecord>,
        next_id: u32,
    }

    impl HookRegistry {
        /// 创建空登记簿。
        pub fn new() -> Self {
            Self {
                hooks: Vec::new(),
                next_id: 1,
            }
        }

        /// 在本进程 `target` 处安装指向 `handler` 的绝对跳转。
        ///
        /// 前置条件: `target` 与 `handler` 为本进程有效地址,
        /// `target` 起至少 16 字节可读。
        pub fn install(&mut self, target: usize, handler: usize) -> io::Result<u32> {
            let (span_start, span_len) = page_span(target, TRAMPOLINE_LEN);
            mprotect_rwx(span_start, span_len)?;

            let tp = target as *mut u8;
            let mut original = [0u8; TRAMPOLINE_LEN];
            // SAFETY: 页已改 RWX; 读 target 起 16 字节, 前置条件保证区间有效
            unsafe {
                std::ptr::copy_nonoverlapping(tp, original.as_mut_ptr(), TRAMPOLINE_LEN);
            }

            let tramp = arm64_trampoline(handler as u64);
            // SAFETY: 同上; 写 target 起 16 字节跳板
            unsafe {
                std::ptr::copy_nonoverlapping(tramp.as_ptr(), tp, TRAMPOLINE_LEN);
            }
            // arm64: 改代码后必须同步 icache, 否则核间可能取到旧指令
            flush_icache(target, TRAMPOLINE_LEN)?;

            let id = self.next_id;
            self.next_id = self
                .next_id
                .checked_add(1)
                .ok_or_else(|| io::Error::other("钩子 id 耗尽"))?;
            self.hooks.push(HookRecord {
                id,
                target,
                handler,
                trampoline: tramp,
                original,
                enabled: true,
            });
            Ok(id)
        }

        /// 卸载钩子并恢复原始指令字节。
        pub fn remove(&mut self, id: u32) -> io::Result<()> {
            let idx = self
                .hooks
                .iter()
                .position(|h| h.id == id)
                .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("钩子 {id} 不存在")))?;
            let rec = self.hooks.remove(idx);
            let (span_start, span_len) = page_span(rec.target, TRAMPOLINE_LEN);
            // 尽力而为: 页保护可能已被他人改回只读
            let _ = mprotect_rwx(span_start, span_len);
            // SAFETY: 把登记时抢救的原始字节写回 target
            unsafe {
                std::ptr::copy_nonoverlapping(
                    rec.original.as_ptr(),
                    rec.target as *mut u8,
                    TRAMPOLINE_LEN,
                );
            }
            flush_icache(rec.target, TRAMPOLINE_LEN)?;
            Ok(())
        }

        /// 查询登记记录。
        pub fn get(&self, id: u32) -> Option<&HookRecord> {
            self.hooks.iter().find(|h| h.id == id)
        }

        /// 全部登记记录。
        pub fn hooks(&self) -> &[HookRecord] {
            &self.hooks
        }
    }

    impl Default for HookRegistry {
        fn default() -> Self {
            Self::new()
        }
    }

    /// 系统页大小。
    fn page_size() -> usize {
        // SAFETY: sysconf 查询常量, 无副作用
        unsafe { libc::sysconf(libc::_SC_PAGESIZE).max(1) as usize }
    }

    /// 计算覆盖 `[addr, addr+len)` 的页对齐区间 (start, len)。
    /// u128 中间量防御性避开加法溢出。
    fn page_span(addr: usize, len: usize) -> (usize, usize) {
        let page = page_size() as u128;
        let start = (addr as u128) & !(page - 1);
        let end = ((addr as u128 + len as u128).div_ceil(page)) * page;
        (start as usize, (end - start) as usize)
    }
}

#[cfg(target_os = "android")]
pub use inline_hook::{HookRecord, HookRegistry};

#[cfg(test)]
mod tests {
    use super::*;

    /// 精确字节编码: 目标 0x1234567890abcdef 的 16 字节跳板逐字节断言。
    #[test]
    fn trampoline_exact_encoding() {
        let t = arm64_trampoline(0x1234567890abcdef);
        assert_eq!(
            t,
            [
                0x50, 0x00, 0x00, 0x58, // LDR X16, #8
                0x00, 0x02, 0x1F, 0xD6, // BR X16
                0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, // target LE
            ]
        );
        // 首指令字 = 0x58000050, 次指令字 = 0xD61F0200
        assert_eq!(u32::from_le_bytes([t[0], t[1], t[2], t[3]]), 0x58000050);
        assert_eq!(u32::from_le_bytes([t[4], t[5], t[6], t[7]]), 0xD61F0200);
    }

    /// 编码 ↔ 解码往返。
    #[test]
    fn trampoline_decode_roundtrip() {
        for target in [0u64, 1, 0x1234567890abcdef, u64::MAX, 0x7FFF_FFFF_F000] {
            let t = arm64_trampoline(target);
            assert_eq!(decode_trampoline(&t), Some(target), "target={target:#x}");
        }
    }

    /// 非法跳板 (错误指令 / 错误长度) 必须被解码器拒绝。
    #[test]
    fn trampoline_decode_rejects_invalid() {
        let mut t = arm64_trampoline(0xDEADBEEF);
        t[0] = 0x51; // 破坏 LDR 编码
        assert_eq!(decode_trampoline(&t), None);
        let mut t2 = arm64_trampoline(0xDEADBEEF);
        t2[7] ^= 0xFF; // 破坏 BR 编码
        assert_eq!(decode_trampoline(&t2), None);
        assert_eq!(decode_trampoline(&t[..15]), None); // 长度不足
        assert_eq!(decode_trampoline(&[]), None);
    }
}
