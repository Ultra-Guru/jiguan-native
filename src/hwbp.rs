//! aarch64 硬件断点 —— ptrace + NT_ARM_HW_BREAK 寄存器组。
//!
//! 仅在 `android + aarch64` 目标编译 (由 lib.rs 的 cfg 分派);
//! 其它平台加载 [`crate::hwbp`] 桩模块, 返回 `Unsupported`。
//!
//! ## 内核 ABI (arm64 ptrace)
//!
//! `PTRACE_GETREGSET / PTRACE_SETREGSET` 携带 `NT_ARM_HW_BREAK = 0x402`:
//!
//! ```text
//! struct user_hwdebug_state {   // 未经校准的内核原始布局
//!     u64 dbg_info;             // 资源信息 (槽数/调试架构版本)
//!     struct { u64 addr; u32 ctrl; u32 pad; } slots[16];
//! }
//! ```
//!
//! GETREGSET 后 `iov_len` 被内核改写为实际大小 —— 槽数 = (len-8)/16,
//! SETREGSET 时**原样回传同一长度**, 避免越权写槽。
//!
//! ## BCR (断点控制寄存器) 编码
//!
//! `E=1 | PMC=0b11 (EL0+EL1) | BAS=0xFF (8 字节全选)` = `0x205`。
//!
//! ## 会话礼仪 (见 docs/SAFETY.md)
//!
//! attach → 布断点 → cont → waitpid 捕 SIGTRAP(si_code == TRAP_HWBKPT)
//! → GETSIGINFO 读命中地址; Drop 兜底: 清槽 + PTRACE_DETACH,
//! 绝不让目标进程停留在 stop 状态; 非 trap 信号原样重新注入, 不吞信号。

use std::fs;
use std::io;
use std::io::{Error, ErrorKind};
use std::time::{Duration, Instant};

/// 一次会话最多占用的断点槽位 (ARMv8 实现常见 4~6 BRP, 保守取 4)。
pub const MAX_HW_BREAKPOINTS: usize = 4;

/// NT_ARM_HW_BREAK (linux elf.h: 0x402)
const NT_HW_BREAKPOINT: usize = 0x402;

// ptrace 请求号 (libc 对 android/aarch64 同样提供, 这里显式钉死防漂移)
const PT_GETREGSET: libc::c_int = 0x4204;
const PT_SETREGSET: libc::c_int = 0x4205;
const PT_GETSIGINFO: libc::c_int = 0x4202;

/// SIGTRAP 的 si_code: 命中硬件断点
const TRAP_HWBKPT: i32 = 4;

/// waitpid 的 __WALL 标志 (线程组事件); 不直接用 libc::__WALL,
/// 显式钉死值防各目标平台常量漂移
const WAIT_WALL: libc::c_int = 0x40000000;

/// 断点 id (会话内自增)。
pub type BreakpointId = u32;

/// 硬件断点寄存器槽位 (addr, ctrl, pad)。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct HwBpSlot {
    addr: u64,
    ctrl: u32,
    pad: u32,
}

impl HwBpSlot {
    /// 空闲槽位判定。
    fn is_free(&self) -> bool {
        self.ctrl == 0 && self.addr == 0
    }
}

/// GETREGSET/SETREGSET 载荷: 资源信息 + 16 槽 (容量上限, 实长由内核决定)。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct HwBpRegs {
    dbg_info: u64,
    slots: [HwBpSlot; 16],
}

impl Default for HwBpRegs {
    fn default() -> Self {
        Self {
            dbg_info: 0,
            slots: [HwBpSlot::default(); 16],
        }
    }
}

/// 一枚已安装的硬件断点。
#[derive(Debug, Clone)]
pub struct HwBreakpoint {
    /// 会话内唯一 id
    pub id: BreakpointId,
    /// 监视地址
    pub addr: u64,
    /// 内核槽位下标
    pub slot: usize,
    /// 是否生效
    pub enabled: bool,
}

/// 一次命中事件。
#[derive(Debug, Clone, Copy)]
pub struct HwBreakHit {
    /// 触发地址 (siginfo si_addr)
    pub addr: u64,
    /// 触发线程 tid
    pub tid: i32,
}

/// ptrace 硬件断点会话。
///
/// 生命周期: [`HwBreakpointSession::attach`] → [`install`](HwBreakpointSession::install)
/// ×N → [`cont`](HwBreakpointSession::cont) → [`wait_hit`](HwBreakpointSession::wait_hit)
/// 循环 → [`detach`](HwBreakpointSession::detach) (Drop 兜底执行)。
pub struct HwBreakpointSession {
    pid: libc::pid_t,
    attached: bool,
    next_id: BreakpointId,
    breakpoints: Vec<HwBreakpoint>,
}

impl HwBreakpointSession {
    /// 附着目标进程 (PTRACE_ATTACH + 阻塞等待其进入 stop)。
    pub fn attach(pid: i32) -> io::Result<Self> {
        let mut session = Self {
            pid,
            attached: false,
            next_id: 1,
            breakpoints: Vec::new(),
        };
        ptrace_call(libc::PTRACE_ATTACH, pid, 0, 0)?;
        let mut status: libc::c_int = 0;
        // SAFETY: 阻塞 waitpid 等待 attach 生效; WAIT_WALL 覆盖线程组事件
        let r = unsafe { libc::waitpid(pid, &mut status, WAIT_WALL) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        if !stopped(status) {
            return Err(io::Error::other("目标进程在 attach 后未进入 stop"));
        }
        session.attached = true;
        Ok(session)
    }

    fn assert_attached(&self) -> io::Result<()> {
        if self.attached {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::NotConnected, "会话未附着目标进程"))
        }
    }

    /// 在 `addr` 安装执行断点 (全线程生效), 返回断点 id。
    ///
    /// 槽位以主线程寄存器组为准选取, 随后同槽写入所有线程 ——
    /// 硬件断点是 per-thread 资源, 漏写线程会漏掉命中。
    pub fn install(&mut self, addr: u64) -> io::Result<BreakpointId> {
        self.assert_attached()?;
        if self.breakpoints.len() >= MAX_HW_BREAKPOINTS {
            return Err(Error::other("断点槽数已用满 (最多 4)"));
        }
        let (regs, slot_count) = read_dbg_regs(self.pid)?;
        let usable = slot_count.min(MAX_HW_BREAKPOINTS);
        let slot = (0..usable)
            .find(|&i| regs.slots[i].is_free())
            .ok_or_else(|| Error::other("内核无空闲断点槽位"))?;
        let ctrl = bcr_execute();
        for tid in list_tids(self.pid)? {
            write_dbg_regs(tid, &regs, slot_count, slot, addr, ctrl)?;
        }
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("断点 id 耗尽"))?;
        self.breakpoints.push(HwBreakpoint {
            id,
            addr,
            slot,
            enabled: true,
        });
        Ok(id)
    }

    /// 移除断点, 清理所有线程上的对应槽位。
    pub fn remove(&mut self, id: BreakpointId) -> io::Result<()> {
        self.assert_attached()?;
        let idx = self
            .breakpoints
            .iter()
            .position(|b| b.id == id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("断点 {id} 不存在")))?;
        let bp = self.breakpoints.remove(idx);
        let (regs, slot_count) = read_dbg_regs(self.pid)?;
        for tid in list_tids(self.pid)? {
            write_dbg_regs(tid, &regs, slot_count, bp.slot, 0, 0)?;
        }
        Ok(())
    }

    /// 让目标进程继续运行 (PTRACE_CONT)。
    pub fn cont(&mut self) -> io::Result<()> {
        self.assert_attached()?;
        ptrace_call(libc::PTRACE_CONT, self.pid, 0, 0)
    }

    /// 等待硬件断点命中; 超时返回 `TimedOut`。
    ///
    /// 循环语义:
    /// - SIGTRAP + si_code == TRAP_HWBKPT → 返回命中 (目标保持 stop,
    ///   由调用方决定 cont / 读取寄存器 / detach);
    /// - 其它 SIGTRAP (软件断点 / 单步) → 继续运行, 不注入信号;
    /// - 非 trap 信号 → PTRACE_CONT 时原样注入, **不吞目标进程的信号**。
    pub fn wait_hit(&mut self, timeout: Duration) -> io::Result<HwBreakHit> {
        self.assert_attached()?;
        let deadline = Instant::now() + timeout;
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: WNOHANG 轮询 + WAIT_WALL 线程组事件
            let r = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG | WAIT_WALL) };
            if r < 0 {
                return Err(io::Error::last_os_error());
            }
            if r == 0 {
                if Instant::now() >= deadline {
                    return Err(Error::new(ErrorKind::TimedOut, "等待断点命中超时"));
                }
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            if exited(status) {
                return Err(Error::new(ErrorKind::BrokenPipe, "目标进程已退出"));
            }
            if stopped(status) {
                let sig = stop_sig(status);
                let tid = r as i32;
                if sig == libc::SIGTRAP {
                    let mut si: libc::siginfo_t = {
                        // SAFETY: siginfo_t 全零是合法初始态, 随后由内核填充
                        unsafe { std::mem::zeroed() }
                    };
                    // SAFETY: GETSIGINFO 以 tid 为目标填充 si
                    let rc = unsafe {
                        libc::ptrace(
                            PT_GETSIGINFO,
                            tid,
                            std::ptr::null_mut(),
                            &mut si as *mut libc::siginfo_t as *mut libc::c_void,
                        )
                    };
                    if rc == 0 && si_code(&si) == TRAP_HWBKPT {
                        return Ok(HwBreakHit {
                            addr: si_addr(&si),
                            tid,
                        });
                    }
                    // 其它 trap: 继续, 不注入
                    ptrace_call(libc::PTRACE_CONT, tid, 0, 0)?;
                } else {
                    // 原样转发信号, 保持目标进程信号语义完整
                    ptrace_call(libc::PTRACE_CONT, tid, 0, sig as usize)?;
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::new(ErrorKind::TimedOut, "等待断点命中超时"));
            }
        }
    }

    /// 清空断点并分离; 目标进程恢复运行。
    pub fn detach(&mut self) -> io::Result<()> {
        if !self.attached {
            return Ok(());
        }
        // 尽力清槽: 失败也继续走 DETACH, 不把目标留在脏状态
        let ids: Vec<BreakpointId> = self.breakpoints.iter().map(|b| b.id).collect();
        for id in ids {
            if let Err(e) = self.remove(id) {
                log::warn!("hwbp: 清除断点 {id} 失败: {e}");
            }
        }
        let r = ptrace_call(libc::PTRACE_DETACH, self.pid, 0, 0);
        self.attached = false;
        r
    }

    /// 当前断点列表。
    pub fn breakpoints(&self) -> &[HwBreakpoint] {
        &self.breakpoints
    }
}

impl Drop for HwBreakpointSession {
    fn drop(&mut self) {
        // ptrace 礼仪: 任何退出路径都不把目标留在 stop/attached 状态
        let _ = self.detach();
    }
}

/// BCR: 执行断点, EL0+EL1, 8 字节全选。
/// `E(1) | PMC(0b11 << 1) | BAS(0xFF << 5)` = 0x205
const fn bcr_execute() -> u32 {
    0x1 | (0b11 << 1) | (0xFF << 5)
}

/// waitpid 状态解析 (libc 的 W* 宏在 Rust 侧即函数)。
fn stopped(status: libc::c_int) -> bool {
    libc::WIFSTOPPED(status)
}
fn exited(status: libc::c_int) -> bool {
    libc::WIFEXITED(status) || libc::WIFSIGNALED(status)
}
fn stop_sig(status: libc::c_int) -> libc::c_int {
    libc::WSTOPSIG(status)
}

/// siginfo 字段读取 (libc 联合体字段在 Rust 侧为方法)。
fn si_code(si: &libc::siginfo_t) -> i32 {
    si.si_code
}
fn si_addr(si: &libc::siginfo_t) -> u64 {
    // SAFETY: 只读联合体字段; SIGTRAP 路径下该成员有效
    unsafe { si.si_addr() as u64 }
}

/// 统一 ptrace 调用: 返回值 < 0 折叠为 io::Error。
fn ptrace_call(req: libc::c_int, pid: libc::pid_t, addr: usize, data: usize) -> io::Result<()> {
    // SAFETY: 参数由调用点保证; addr 携带 NT 编号或 0, data 携带指针或信号
    let rc = unsafe {
        libc::ptrace(
            req,
            pid,
            addr as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// 读取主线程的硬件断点寄存器组; 返回 (寄存器组, 实际槽数)。
fn read_dbg_regs(pid: libc::pid_t) -> io::Result<(HwBpRegs, usize)> {
    let mut regs = HwBpRegs::default();
    let mut iov = libc::iovec {
        // SAFETY: iov 指向本栈上合法结构, 容量 8+16*16 覆盖内核最大返回
        iov_base: &mut regs as *mut HwBpRegs as *mut libc::c_void,
        iov_len: std::mem::size_of::<HwBpRegs>(),
    };
    // SAFETY: GETREGSET 只写 iov 指向的缓冲, 长度以 iov_len 为准
    let rc = unsafe {
        libc::ptrace(
            PT_GETREGSET,
            pid,
            NT_HW_BREAKPOINT as *mut libc::c_void,
            &mut iov as *mut libc::iovec as *mut libc::c_void,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    // 内核把 iov_len 改写为实际大小: 资源信息 u64 + 每槽 16 字节
    let slot_count = (iov.iov_len.saturating_sub(8) / 16).min(16);
    Ok((regs, slot_count))
}

/// 向指定线程写回寄存器组: 仅改写 `slot` 槽, 其余原样保留。
///
/// `slot_count` 必须来自 GETREGSET 探得的内核实长 —— SETREGSET
/// 以同一长度回传, 不越权触碰内核不认识的槽位。
fn write_dbg_regs(
    tid: libc::pid_t,
    regs: &HwBpRegs,
    slot_count: usize,
    slot: usize,
    addr: u64,
    ctrl: u32,
) -> io::Result<()> {
    if slot >= slot_count {
        return Err(Error::other(format!(
            "线程 {tid} 断点槽位不足 ({slot_count})"
        )));
    }
    let mut local = *regs;
    local.slots[slot] = HwBpSlot { addr, ctrl, pad: 0 };
    let mut iov = libc::iovec {
        // SAFETY: local 为本栈上合法结构, 长度精确对齐内核实长
        iov_base: &mut local as *mut HwBpRegs as *mut libc::c_void,
        iov_len: 8 + slot_count * 16,
    };
    // SAFETY: SETREGSET 读取 iov 指向的缓冲, 长度以 iov_len 为准
    let rc = unsafe {
        libc::ptrace(
            PT_SETREGSET,
            tid,
            NT_HW_BREAKPOINT as *mut libc::c_void,
            &mut iov as *mut libc::iovec as *mut libc::c_void,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// 枚举 /proc/<pid>/task 下全部线程 tid (含主线程)。
fn list_tids(pid: libc::pid_t) -> io::Result<Vec<libc::pid_t>> {
    let mut tids = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/task"))?.flatten() {
        if let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<libc::pid_t>().ok())
        {
            tids.push(tid);
        }
    }
    if tids.is_empty() {
        // task 目录读不到时至少保证主线程
        tids.push(pid);
    }
    Ok(tids)
}
