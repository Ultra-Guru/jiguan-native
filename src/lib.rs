//! # 机关 (Jiguan) Native Core —— Rust 原生加速核心
//!
//! **机关 (Jiguan) V3.0** 的动力室: 通用系统级 Android 智能体终端
//! (*Universal system-level Android agent terminal*) 的原生加速层。
//!
//! 机关的使命: 让 Android 智能体像「机关术」一样精密 ——
//! 以原生速度读写进程内存、扫描特征、布设钩子与断点,
//! 并在原生通道不可用时由 Kotlin 宿主优雅降级到 shell 路径。
//!
//! The Kotlin host (Ultra-Guru/Android-Guru-Agent) implements graceful
//! shell-based fallbacks; this crate provides the **fast native path**
//! via JNI:
//!
//! - 进程内存读写 (`/proc/<pid>/mem` + `process_vm_readv/writev` 双通道)
//! - `/proc` maps 解析与进程枚举 (零依赖手写解析器)
//! - AOB (Array-of-Bytes) 特征扫描, 支持 `??` 通配符
//! - arm64 绝对跳转 trampoline 生成 (`LDR X16, #8; BR X16`)
//! - 内联钩子登记簿 (Android 目标)
//! - aarch64 硬件断点 (ptrace + NT_ARM_HW_BREAK, Android/aarch64 目标)
//!
//! ## 设计纪律 (Design discipline)
//!
//! - **绝不 panic 穿越 FFI** —— JNI 边界全部 `catch_unwind`,
//!   出错返回安全默认值 (`-1` / `null` / `false` / 空串);
//! - **错误一律 `Result`** —— 非测试代码路径零 `unwrap`/`expect`;
//! - **unsafe 块必须带 SAFETY 注释** —— 说明每一条不变量;
//! - **零额外依赖** —— 仅 `jni` / `libc` / `log`, 交叉编译依赖面最小。
//!
//! ## 模块一览
//!
//! | 模块 | 职责 |
//! |------|------|
//! | [`mem`] | 进程内存句柄与双通道读写 |
//! | [`proc`] | /proc 解析: 进程枚举 / maps / 可扫区域过滤 |
//! | [`scan`] | AOB 模式解析与内存扫描 |
//! | [`hook`] | arm64 trampoline 编码 / mprotect / icache / 钩子登记 |
//! | [`hwbp`] | aarch64 ptrace 硬件断点 (非 Android/aarch64 目标为桩) |
//! | [`jni`] | JNI 导出边界 (符号与 Kotlin 契约一一对应) |

#![deny(clippy::all)]
#![warn(missing_docs)]

pub mod hook;
// hwbp: android+aarch64 真实现 (src/hwbp.rs) / 其它目标桩 (src/hwbp_stub.rs)
// —— 同名公共 API, 宿主 cargo test 可编译可测试。
#[cfg(all(target_os = "android", target_arch = "aarch64"))]
pub mod hwbp;
#[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
#[path = "hwbp_stub.rs"]
pub mod hwbp;
pub mod jni;
pub mod mem;
pub mod proc;
pub mod scan;

/// 库版本, 与 `Cargo.toml` 保持同步。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 原生库标识串 —— JNI `nativeVersion()` 的返回值,
/// Kotlin 侧用于诊断当前加载的原生核心版本。
///
/// 形如 `"jiguan-native/0.1.0"`。
pub fn native_version() -> &'static str {
    concat!("jiguan-native/", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 版本串必须形如 jiguan-native/x.y.z, 且与 Cargo.toml 同步。
    #[test]
    fn native_version_format() {
        let v = native_version();
        assert!(v.starts_with("jiguan-native/"), "版本串前缀错误: {v}");
        assert_eq!(v, "jiguan-native/0.1.0");
        assert_eq!(VERSION, "0.1.0");
        // 语义化版本三段式
        let tail = v.strip_prefix("jiguan-native/").unwrap_or_default();
        let parts: Vec<&str> = tail.split('.').collect();
        assert_eq!(parts.len(), 3, "版本号必须是 x.y.z: {tail}");
        assert!(parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())));
    }
}
