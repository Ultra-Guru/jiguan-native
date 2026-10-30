# SAFETY —— 机关原生核心的安全纪律

本文档是 `jiguan-native` 全部 `unsafe` 决策的登记簿与理由书。
任何新增 `unsafe` 必须同步更新本文档。

---

## 1. panic 绝不穿越 FFI

**规则**: `src/jni.rs` 的全部 10 个 JNI 入口都包
`std::panic::catch_unwind(AssertUnwindSafe(...))`, 出错时记录日志、
清理挂起的 Java 异常 (`exception_clear`), 返回安全默认值
(`-1` / `null` / `false` / 空串)。

**为什么**:

- Rust 的 `extern "system"`(= JNI 的调用约定)**不是 unwind ABI**。
  自 Rust 1.81 起, panic 到达该边界会执行 abort —— 整个 Android
  宿主进程 (Android-Guru-Agent) 直接被杀。这是机关绝不允许的:
  宿主终端必须永远活着, 宁可原生调用返回失败、走 shell 降级。
- `AssertUnwindSafe` 是必须的: `JNIEnv` 内部含裸指针, 编译器无法
  证明 unwind 后仍一致。我们在 catch 之后**不再解引用** env 中的
  任何缓存对象, 只调用 `exception_clear`, 风险受控。

**验证**: `jni::log_panic` 对 panic 载荷做 `downcast` 提取消息,
永远不 `unwrap`。

## 2. 句柄 (jlong ↔ Box<MemHandle>) 的所有权契约

- `openProcess` 中 `Box::into_raw` 把堆上 `MemHandle` 的所有权移交
  jlong 句柄; `closeProcess` 中 `Box::from_raw` 唯一收回并析构
  (Drop 关闭 `/proc/pid/mem` fd)。
- **不变量**:
  1. 句柄只能来自 `openProcess`, 0 / 负数一律拒绝;
  2. open/close 严格配对, double-close 是未定义行为 (宿主侧用
     幂等封装防护);
  3. **同一句柄的并发调用必须由上层串行化** —— `&mut` 语义经裸指针
     传递, Rust 无法替你证明。Kotlin 侧建议对单一 handle 加互斥,
     多 handle 天然并行安全 (fd 各自独立)。
- Drop 兜底: 若宿主忘记 close, `MemHandle` 的 fd 会在进程退出时由
  内核回收, 不会泄漏到其它进程。

## 3. /proc/<pid>/mem 双通道读写的 unsafe 面

所有 `unsafe` 集中在四个 FFI 调用: `pread` / `pwrite` /
`process_vm_readv` / `process_vm_writev` (+ `open`/`close`)。
每个调用点的 SAFETY 注释声明:

- **指针有效性**: 目标缓冲指向本进程栈/堆上的合法切片, 长度取剩余量,
  不可能越界;
- **区间校验先行**: `check_range` 保证 `addr + len` 无 u64 溢出且
  落在 `off_t` (i64) 可表达范围 —— 传给内核前地址永远合法;
- **循环推进**: 短读/短写循环推进 `done`, 部分失败折叠为
  `UnexpectedEof` 错误而不是静默截断;
- **内核不越权**: `process_vm_*` 的 remote iovec 只指向目标进程
  已存在的映射, 写权限由内核强制 (ptrace_may_access)。

**永不 panic**: 所有分配经 `vec![0u8; len]` (len 由 jint clamp 到
非负), 理论上 OOM 仍会 abort —— 这属于 Rust 运行时的全局策略,
与 FFI 边界无关。

## 4. hook (内联钩子) 的写代码纪律

- **页保护**: `mprotect_rwx` 只对目标地址所在页 (跨页时两页) 生效,
  计算基于 `sysconf(_SC_PAGESIZE)`; 卸载时**尽力**恢复, 但保护位
  保持 RWX —— 完整恢复原始保护位需要解析 maps, 留给上层补齐
  (登记簿记录了 original 字节, 指令语义可完整还原)。
- **icache 同步**: arm64 上改代码后必须 `__clear_cache`, 否则其它
  核可能取到旧指令 —— 这是内核文档明确的架构要求, 不是可选项。
  x86 宿主上 icache 硬件一致, no-op 是安全的。
- **原子性警告**: install 的「读原始字节 → 写跳板」窗口内若目标函数
  正在其它核上执行, 属于竞态 —— 内联钩子装配天然如此 (Frida 同理),
  调用方应选择冷路径 (未被执行的函数) 安装。登记簿不做跨核停机。

## 5. ptrace (hwbp) 礼仪

**目标进程的尊严高于调试便利**:

1. **Drop 兜底 DETACH**: `HwBreakpointSession::drop` 必然执行
   清槽 + `PTRACE_DETACH` —— 任何退出路径 (含 panic unwind) 都不把
   目标进程留在 stop/attached 状态。忘了 detach 的 ptracer 会让
   目标永久挂起, 这是经典事故。
2. **不吞信号**: `wait_hit` 循环里, 非 trap 信号在 `PTRACE_CONT`
   时原样重新注入 (`data = sig`); 目标进程的 SIGSEGV/SIGINT 语义
   保持完整。其它来源的 SIGTRAP (软件断点/单步) 继续但不注入。
3. **槽位写回不越权**: `SETREGSET` 的 iov_len 严格使用
   `GETREGSET` 探得的内核实长 (8 + 槽数×16), 只改写登记的槽位,
   其余槽位原样回传 —— 不触碰内核不认识的寄存器。
4. **per-thread 资源**: 硬件断点是 per-thread 的; install/remove
   遍历 `/proc/<pid>/task` 全部线程写槽, 漏写线程会漏掉命中。
5. **attach 期间目标全停**: PTRACE_ATTACH 后目标全线程停机,
   会话应短 —— 布断点 → CONT → 等命中 → 尽快 DETACH。

## 6. 错误处理总则

- 非测试代码路径**零 `unwrap`/`expect`** (CI `clippy -D warnings`
  强制); 所有错误走 `io::Result` 或专用 `ScanError`;
- maps 解析对畸形行静默跳过 (内核是唯一写者, 防御性容错);
- `scan_memory` 对单区域最多容忍 3 次读错误即跳过 (vvar 类特殊映射
  不拖垮全局扫描);
- 日志 (`log` crate) 记录失败原因, 但**永不打印内存内容** —— 数据
  可能属于目标进程的隐私。

## 7. 权限与伦理边界

- 读写其它进程需要 root / ptrace 权限 —— 机关**不做任何提权**,
  不绕过 Yama/SELinux; 权限不足时报错返回, 由宿主决定降级路径;
- 本仓库只提供机制, 授权策略 (允许操作哪些 pid) 完全由宿主
  Android-Guru-Agent 的权限系统决定。
