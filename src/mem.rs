//! 进程内存读写双通道。
//!
//! [`MemHandle`] 是目标进程的内存句柄:
//! - 主通道: `/proc/<pid>/mem` 的 fd (打开时缓存, `pread`/`pwrite` 访问);
//! - 回退通道: `process_vm_readv` / `process_vm_writev` (fd 打开失败
//!   或主通道读写出错时启用, 只需 pid, 不需要 fd)。
//!
//! 运行期权限: 目标是其它进程时需要 root (或同 uid + ptrace_scope 允许);
//! 自身进程 (pid == 本进程) 始终可用 —— 宿主单测即依赖这一点。
//!
//! 所有错误折叠为 [`std::io::Result`], 任何路径都不 panic。

use std::ffi::CString;
use std::io;
use std::io::{Error, ErrorKind};
use std::path::Path;

use log::debug;

/// 进程内存句柄: 缓存 `/proc/<pid>/mem` 的 fd 与目标 pid。
///
/// 生命周期约定: JNI 侧由 `openProcess` 创建 (装箱指针)、
/// `closeProcess` 析构; Rust 侧可直接 [`MemHandle::open`] 后使用。
pub struct MemHandle {
    pid: libc::pid_t,
    fd: libc::c_int,
}

impl MemHandle {
    /// 打开目标进程的内存通道。
    ///
    /// 打开策略 (逐级退化, 永不因权限不足而直接失败 —— 只要进程存在):
    /// 1. `O_RDWR` 读写全开;
    /// 2. `O_RDONLY` 至少可读;
    /// 3. fd = -1, 仅靠 `process_vm_*` 系统调用通道。
    pub fn open(pid: i32) -> io::Result<Self> {
        let mem_path = format!("/proc/{pid}/mem");
        let cpath = CString::new(mem_path.as_str())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "路径含非法字节"))?;
        let fd = open_fd(&cpath, libc::O_RDWR | libc::O_CLOEXEC)
            .or_else(|| open_fd(&cpath, libc::O_RDONLY | libc::O_CLOEXEC))
            .unwrap_or(-1);
        if fd < 0 {
            // fd 打不开不代表进程不存在; 只有 /proc/<pid> 消失才判定 NotFound
            if !Path::new(&format!("/proc/{pid}")).exists() {
                return Err(Error::new(ErrorKind::NotFound, format!("进程 {pid} 不存在")));
            }
            debug!("mem: /proc/{pid}/mem 打开失败, 回退 process_vm_* 通道");
        }
        Ok(Self { pid, fd })
    }

    /// 目标进程 pid。
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// 读取 `addr` 起 `len` 字节; **全部成功才返回 `Ok`** (部分可读视为错误)。
    pub fn read(&self, addr: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let n = self.read_into(addr, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// 读取填充 `buf`; 成功时返回值恒等于 `buf.len()`。
    pub fn read_into(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
        check_range(addr, buf.len())?;
        if buf.is_empty() {
            return Ok(0);
        }
        if self.fd >= 0 {
            match pread_full(self.fd, buf, addr) {
                Ok(n) => return Ok(n),
                // 主通道失败 (如特殊映射 vvar) 时尝试回退通道
                Err(e) => debug!("mem: pread 于 {addr:#x} 失败({e}), 回退 process_vm_readv"),
            }
        }
        vm_readv_full(self.pid, addr, buf)
    }

    /// 写入 `data`; 返回成功写入的字节数。
    pub fn write(&self, addr: u64, data: &[u8]) -> io::Result<usize> {
        check_range(addr, data.len())?;
        if data.is_empty() {
            return Ok(0);
        }
        if self.fd >= 0 {
            match pwrite_full(self.fd, data, addr) {
                Ok(n) => return Ok(n),
                Err(e) => debug!("mem: pwrite 于 {addr:#x} 失败({e}), 回退 process_vm_writev"),
            }
        }
        vm_writev_full(self.pid, addr, data)
    }

    /// 写入 `data` 全部内容; 部分成功视为错误。
    pub fn write_all_bytes(&self, addr: u64, data: &[u8]) -> io::Result<()> {
        let n = self.write(addr, data)?;
        if n != data.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "写入不完整"));
        }
        Ok(())
    }

    /// 读取 C 风格字符串: 遇 NUL 或读满 `max_len` 字节为止。
    ///
    /// 宽松截断语义 (贴近 GameGuardian 行为): 已成功读出部分内容后
    /// 再遇读取错误, 按截断返回已读部分; 起始即不可读则报 `Err`。
    /// 输出按 UTF-8 有损转换 (非法字节替换为 U+FFFD)。
    pub fn read_cstring(&self, addr: u64, max_len: usize) -> io::Result<String> {
        if max_len == 0 {
            return Ok(String::new());
        }
        let end = addr.checked_add(max_len as u64).ok_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "地址区间溢出 u64")
        })?;
        let mut out: Vec<u8> = Vec::new();
        let mut cur = addr;
        while cur < end {
            let want = ((end - cur) as usize).min(64);
            let mut chunk = [0u8; 64];
            let buf = &mut chunk[..want];
            match self.read_into(cur, buf) {
                Ok(n) => {
                    // read_into 成功必然填满, n == want; 此处仍按实际 n 处理
                    if let Some(nul) = buf[..n].iter().position(|&b| b == 0) {
                        out.extend_from_slice(&buf[..nul]);
                        return Ok(lossy(&out));
                    }
                    out.extend_from_slice(&buf[..n]);
                    cur += n as u64;
                }
                Err(e) => {
                    if out.is_empty() {
                        return Err(e);
                    }
                    return Ok(lossy(&out));
                }
            }
        }
        Ok(lossy(&out))
    }
}

impl Drop for MemHandle {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: close 仅作用于本句柄缓存的合法 fd, 不会双重关闭
            // (fd 由 open 独占产生, Drop 只运行一次)
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

/// 地址区间合法性: 无 u64 溢出, 且落在 off_t (i64) 可表达范围内。
fn check_range(addr: u64, len: usize) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    if addr.checked_add(len as u64).is_none() {
        return Err(Error::new(ErrorKind::InvalidInput, "地址区间溢出 u64"));
    }
    if addr > libc::off_t::MAX as u64 {
        return Err(Error::new(ErrorKind::InvalidInput, "地址超出 off_t 范围"));
    }
    Ok(())
}

fn open_fd(path: &CString, flags: libc::c_int) -> Option<libc::c_int> {
    // SAFETY: path 为合法 NUL 结尾字符串; open 只返回 fd, 无内存写入
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd >= 0 {
        Some(fd)
    } else {
        None
    }
}

/// 主通道读: /proc/<pid>/mem 上循环 pread 直到填满。
fn pread_full(fd: libc::c_int, buf: &mut [u8], addr: u64) -> io::Result<usize> {
    let mut done = 0usize;
    while done < buf.len() {
        // check_range 已保证 addr + done 不会溢出 u64 / 超出 off_t
        let off = addr + done as u64;
        // SAFETY: pread 目标指针指向 buf[done..] (长度剩余量), 不会越界写
        let n = unsafe {
            libc::pread(
                fd,
                buf.as_mut_ptr().add(done).cast::<libc::c_void>(),
                buf.len() - done,
                off as libc::off_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "pread 提前结束"));
        }
        done += n as usize;
    }
    Ok(done)
}

/// 主通道写: /proc/<pid>/mem 上循环 pwrite 直到写完。
fn pwrite_full(fd: libc::c_int, data: &[u8], addr: u64) -> io::Result<usize> {
    let mut done = 0usize;
    while done < data.len() {
        let off = addr + done as u64;
        // SAFETY: pwrite 源指针指向 data[done..], 只读不写
        let n = unsafe {
            libc::pwrite(
                fd,
                data.as_ptr().add(done).cast::<libc::c_void>(),
                data.len() - done,
                off as libc::off_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "pwrite 提前结束"));
        }
        done += n as usize;
    }
    Ok(done)
}

/// 回退通道读: process_vm_readv, 跨越不可读页会部分成功 —— 循环推进。
fn vm_readv_full(pid: libc::pid_t, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
    let mut done = 0usize;
    while done < buf.len() {
        let local = libc::iovec {
            // SAFETY: 指向本进程栈/堆上合法切片的剩余部分
            iov_base: buf.as_mut_ptr().add(done).cast::<libc::c_void>(),
            iov_len: buf.len() - done,
        };
        let remote = libc::iovec {
            // check_range 已保证 addr + done 不溢出
            iov_base: (addr + done as u64) as *mut libc::c_void,
            iov_len: buf.len() - done,
        };
        // SAFETY: local/remote 均指向有效 iovec; 内核只写 local 指向的缓冲
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "process_vm_readv 提前结束",
            ));
        }
        done += n as usize;
    }
    Ok(done)
}

/// 回退通道写: process_vm_writev。
fn vm_writev_full(pid: libc::pid_t, addr: u64, data: &[u8]) -> io::Result<usize> {
    let mut done = 0usize;
    while done < data.len() {
        let local = libc::iovec {
            // SAFETY: 指向本进程合法切片的剩余部分, 只读
            iov_base: data.as_ptr().add(done).cast::<libc::c_void>(),
            iov_len: data.len() - done,
        };
        let remote = libc::iovec {
            iov_base: (addr + done as u64) as *mut libc::c_void,
            iov_len: data.len() - done,
        };
        // SAFETY: 内核只读 local 指向的缓冲, 写入远端 remote 区间
        let n = unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "process_vm_writev 提前结束",
            ));
        }
        done += n as usize;
    }
    Ok(done)
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 已知静态数据: 非零初值确保落在 .data 段 (rw-)
    static READ_TARGET: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

    /// 写回环测试缓冲: 零初值落在 .bss (rw-)
    static mut WRITE_BUF: [u8; 8] = [0u8; 8];

    /// C 串测试样本 (.rodata, 直接地址读取不经过区域过滤)
    static CSTR_SAMPLE: &[u8] = b"JIGUAN_NATIVE_CSTRING_TEST_0123456789\0";

    fn self_pid() -> i32 {
        std::process::id() as i32
    }

    /// 打开自身进程并读取静态数据 —— 验证双通道读取的正确性。
    #[test]
    fn mem_read_static_bytes_of_own_process() {
        let h = MemHandle::open(self_pid()).expect("打开自身进程必然成功");
        // SAFETY(测试): addr_of! 不创建引用, 仅取静态地址
        let addr = std::ptr::addr_of!(READ_TARGET) as usize as u64;
        let got = h.read(addr, 4).expect("读取静态数据");
        assert_eq!(got, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    /// 读取不可达地址必须报错, 而不是 panic 或返回脏数据。
    #[test]
    fn mem_read_invalid_address_errors() {
        let h = MemHandle::open(self_pid()).expect("打开自身进程");
        // 低地址页在用户态必然未映射
        assert!(h.read(0x1000, 16).is_err());
    }

    /// 写入 + 经内核通道读回 —— 排除编译器缓存干扰。
    #[test]
    fn mem_write_read_roundtrip_on_own_process() {
        let h = MemHandle::open(self_pid()).expect("打开自身进程");
        // SAFETY(测试): addr_of_mut! 不创建引用, 仅取静态可变地址
        let addr = std::ptr::addr_of_mut!(WRITE_BUF) as usize as u64;
        h.write_all_bytes(addr, &[1, 2, 3, 4, 5, 6, 7, 8])
            .expect("写入自身 .bss");
        let back = h.read(addr, 8).expect("读回");
        assert_eq!(back, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    /// 读取已知 C 字符串。
    #[test]
    fn mem_read_cstring_known_sample() {
        let h = MemHandle::open(self_pid()).expect("打开自身进程");
        let addr = CSTR_SAMPLE.as_ptr() as usize as u64;
        let s = h.read_cstring(addr, 256).expect("读取 C 串");
        assert_eq!(s, "JIGUAN_NATIVE_CSTRING_TEST_0123456789");
    }

    /// max_len 截断: 读满上限即返回 (不带 NUL)。
    #[test]
    fn mem_read_cstring_truncates_at_max_len() {
        let h = MemHandle::open(self_pid()).expect("打开自身进程");
        let addr = CSTR_SAMPLE.as_ptr() as usize as u64;
        let s = h.read_cstring(addr, 10).expect("截断读取");
        assert_eq!(s, "JIGUAN_NAT");
    }

    /// 自身 ELF 头校验: 经 maps 找到本测试二进制的文件映射,
    /// 从映射起点读出 0x7F 'E' 'L' 'F' 魔数 —— 端到端验证
    /// proc 解析 + mem 读取两模块的协同。
    #[test]
    fn mem_read_elf_magic_from_own_mapping() {
        use crate::proc;
        let pid = self_pid();
        let regions = proc::parse_maps(&proc::read_maps(pid).expect("读取自身 maps"));
        let r = regions
            .iter()
            .find(|r| r.offset == 0 && r.path.starts_with('/') && r.path.contains("jiguan"))
            .or_else(|| {
                regions
                    .iter()
                    .find(|r| r.offset == 0 && r.path.starts_with('/'))
            })
            .expect("找到自身 ELF 文件映射");
        let h = MemHandle::open(pid).expect("打开自身进程");
        let magic = h.read(r.start, 4).expect("读取 ELF 魔数");
        assert_eq!(magic, vec![0x7F, b'E', b'L', b'F'], "映射: {}", r.path);
    }
}
