//! hwbp 桩模块 —— 非 Android/aarch64 目标。
//!
//! 与 [`crate::hwbp`]/`src/hwbp.rs` 保持同名公共 API,
//! 但全部操作返回 `Unsupported` 错误, 保证宿主
//! `cargo test` / `cargo clippy` 可编译可测试。
//! 由 lib.rs 的 cfg 分派加载:

use std::io;
use std::io::{Error, ErrorKind};
use std::time::Duration;

/// 断点 id (与真实模块同型)。
pub type BreakpointId = u32;

/// 一次命中事件 (与真实模块同型)。
#[derive(Debug, Clone, Copy)]
pub struct HwBreakHit {
    /// 触发地址
    pub addr: u64,
    /// 触发线程 tid
    pub tid: i32,
}

/// 硬件断点会话桩: 任何操作都返回 `Unsupported`。
pub struct HwBreakpointSession {
    /// 永不构造成功的占位
    _never: (),
}

impl HwBreakpointSession {
    /// 本平台不支持硬件断点。
    pub fn attach(_pid: i32) -> io::Result<Self> {
        unsupported()
    }

    /// 本平台不支持硬件断点。
    pub fn install(&mut self, _addr: u64) -> io::Result<BreakpointId> {
        unsupported()
    }

    /// 本平台不支持硬件断点。
    pub fn remove(&mut self, _id: BreakpointId) -> io::Result<()> {
        unsupported()
    }

    /// 本平台不支持硬件断点。
    pub fn cont(&mut self) -> io::Result<()> {
        unsupported()
    }

    /// 本平台不支持硬件断点。
    pub fn wait_hit(&mut self, _timeout: Duration) -> io::Result<HwBreakHit> {
        unsupported()
    }

    /// 桩会话无需分离。
    pub fn detach(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn unsupported<T>() -> io::Result<T> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "硬件断点仅在 Android/aarch64 目标可用",
    ))
}
