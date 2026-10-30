# 机关 · jiguan-native

[![CI](https://github.com/Ultra-Guru/jiguan-native/actions/workflows/ci.yml/badge.svg)](https://github.com/Ultra-Guru/jiguan-native/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)

**机关 (Jiguan) V3.0 的 Rust 原生加速核心** —— 通用系统级 Android 智能体终端
(*Universal system-level Android agent terminal*) 的动力室。

> **Jiguan (机关) native acceleration core** — the Rust powertrain of the
> Jiguan V3.0 universal system-level Android agent terminal. The Kotlin host
> ([Ultra-Guru/Android-Guru-Agent](https://github.com/Ultra-Guru/Android-Guru-Agent))
> owns graceful shell-based fallbacks; this crate delivers the **fast native
> path** over JNI: process memory R/W, AOB scanning, arm64 trampoline
> generation, inline-hook bookkeeping and ptrace-driven hardware breakpoints.

机关取「机关术」之意 —— 精密、联动、层层递进: 原生层快而不鲁莽,
Kotlin 层稳而不迟缓; 原生通道不可用时, 机关自动降级为 shell 路径,
能力不断档。

---

## 架构 / Architecture

```text
┌───────────────────────────────────────────────────────────────────┐
│                    Android-Guru-Agent (Kotlin)                    │
│                  机关终端 V3.0 · Android 智能体宿主                  │
│                                                                   │
│   JiguanNative (external fun) ── System.loadLibrary("jiguan")     │
│        │                                                          │
│        │  降级哲学: JNI 不可用 / so 缺失 / 非 arm64 →               │
│        │  回退 shell 路径 (/proc + dd + grep), 能力保持             │
└────────┼──────────────────────────────────────────────────────────┘
         │  JNI · com.apex.agent.platform.jiguan.native.JiguanNative
┌────────▼──────────────────────────────────────────────────────────┐
│                jiguan-native (Rust · libjiguan.so)                │
│                                                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │ jni.rs   │  │ mem.rs   │  │ proc.rs  │  │ scan.rs          │   │
│  │ 边界守卫  │  │ 双通道读写 │  │ maps 解析 │  │ AOB 扫描 + 通配符 │   │
│  │ catch_   │  │ pread +  │  │ 进程枚举  │  │ 1MB 分块 + 重叠   │   │
│  │ unwind   │  │ vm_readv │  │ 区域过滤  │  │ 首锚点跳优        │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘   │
│  ┌──────────────────┐  ┌──────────────────────────────────────┐   │
│  │ hook.rs          │  │ hwbp.rs (Android + aarch64)          │   │
│  │ arm64 trampoline │  │ ptrace + NT_ARM_HW_BREAK 硬件断点      │   │
│  │ LDR X16 / BR X16 │  │ 槽位管理 · SIGTRAP 捕获 · 信号转发      │   │
│  │ 钩子登记簿        │  │ (其它平台为 Unsupported 桩)           │   │
│  └──────────────────┘  └──────────────────────────────────────┘   │
└────────┬───────────────────────────────┬──────────────────────────┘
         │ /proc/<pid>/mem               │ ptrace (ATTACH/GETREGSET/
         │ process_vm_readv/writev       │           SETREGSET/CONT)
┌────────▼───────────────────────────────▼──────────────────────────┐
│                    Linux Kernel (Android)                          │
└───────────────────────────────────────────────────────────────────┘
```

## JNI 契约 / JNI contract

Kotlin 侧类: `com.apex.agent.platform.jiguan.native.JiguanNative`
(标准 JNI 名字改编; `native` 在 Kotlin 中是合法包名段)。

| Kotlin 方法 | 语义 | 成功返回 | 失败返回 |
|---|---|---|---|
| `openProcess(pid: Int): Long` | 打开 `/proc/pid/mem` 双通道句柄 | 句柄 (堆指针) | `-1` |
| `closeProcess(handle: Long)` | 关闭句柄 (幂等) | — | 静默忽略非法句柄 |
| `readMemory(handle, address, size): ByteArray` | 读取内存 | 字节数组 | `null` |
| `writeMemory(handle, address, data): Boolean` | 全量写入 | `true` | `false` |
| `scanRegions(pid: Int): Array<String>` | rw-/r-x 区域的标准 maps 行 | 行数组 (可空集) | `null` |
| `scanMemory(handle, pattern, maxResults): LongArray` | AOB 扫描, 模式如 `"DE AD ?? ?? EF"` | 命中地址数组 | 非法模式/句柄 → `null` |
| `scanValueMemory(handle, valueBytes, fuzzyRange, maxResults): LongArray` | 精确字节扫描 (`fuzzyRange≠0` 时模糊匹配由 Kotlin 侧完成) | 命中地址数组 | `null` |
| `readCString(handle, address, maxLen): String` | 读 C 串 (遇 NUL/maxLen 停) | 字符串 | 空串 |
| `arm64Trampoline(target: Long): ByteArray` | 16 字节 `LDR X16,#8; BR X16; <target LE>` | 16 字节 | 理论上不失败 |
| `nativeVersion(): String` | 库标识 | `"jiguan-native/0.1.0"` | 空串 |

maps 行格式 (与内核 `%016lx-%016lx` 对齐):

```text
7ffd1c5a1000-7ffd1c5c2000 rw-p 00000000 00:00 0 [heap]
```

**边界纪律**: 每个 JNI 入口都包 `catch_unwind` —— Rust panic 绝不穿越
FFI (会直接 abort 整个进程); 所有错误折叠为安全默认值。详见
[docs/SAFETY.md](docs/SAFETY.md)。

## 模块 / Modules

| 模块 | 职责 |
|---|---|
| `mem` | `MemHandle`: `/proc/<pid>/mem` fd 主通道 + `process_vm_readv/writev` 回退通道; 读 / 写 / C 串 |
| `proc` | 零依赖 /proc 解析: `list_processes` / `parse_maps` / `scan_regions` |
| `scan` | `parse_pattern` (`??` 通配, 大小写/紧凑写法) · `scan_buffer` (首锚点跳优) · `scan_memory` (1MB 分块 + 跨块重叠 + 区域容错) |
| `hook` | `arm64_trampoline` / `decode_trampoline` · `mprotect_rwx` · `flush_icache` · `HookRegistry` (Android) |
| `hwbp` | aarch64 硬件断点: ptrace ATTACH → NT_ARM_HW_BREAK (0x402) 槽位 → SIGTRAP(si_code=TRAP_HWBKPT) 捕获 → DETACH; 其它平台为 `Unsupported` 桩 |
| `jni` | 10 个导出符号, 全部 catch_unwind, 见上表 |

## 构建 / Build

### 宿主 (Linux, 跑单测)

```bash
cargo test                 # 24 个单测: 模式解析 / 扫描 / maps / trampoline / 自身进程读写
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

单测在 x86_64 Linux 宿主即可运行 —— 内存读写用例以**自身进程**为靶
(打开 `/proc/self/mem`, 读写本进程静态数据), 不需要 root。

### Android NDK 交叉构建 (aarch64)

```bash
rustup target add aarch64-linux-android

export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.0.12077973"
export TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/aarch64-linux-android24-clang"

cargo build --target aarch64-linux-android --release
# → target/aarch64-linux-android/release/libjiguan.so
```

CI 的 `android-build` job 自动完成以上步骤并上传 `.so` artifact;
打 `v*` tag 时 `release` job 附带 `.so` 发布 GitHub Release。

## Kotlin 集成 / Kotlin integration

```kotlin
package com.apex.agent.platform.jiguan.native

/**
 * 机关原生核心 —— 快通道。
 * 加载失败 (so 缺失 / 架构不符) 时宿主必须走 shell 降级路径, 不得崩溃。
 */
object JiguanNative {
    init { System.loadLibrary("jiguan") }

    external fun openProcess(pid: Int): Long
    external fun closeProcess(handle: Long)
    external fun readMemory(handle: Long, address: Long, size: Int): ByteArray?
    external fun writeMemory(handle: Long, address: Long, data: ByteArray): Boolean
    external fun scanRegions(pid: Int): Array<String>?
    external fun scanMemory(handle: Long, pattern: String, maxResults: Int): LongArray?
    external fun scanValueMemory(
        handle: Long, valueBytes: ByteArray, fuzzyRange: Double, maxResults: Int,
    ): LongArray?
    external fun readCString(handle: Long, address: Long, maxLen: Int): String
    external fun arm64Trampoline(target: Long): ByteArray
    external fun nativeVersion(): String
}
```

**降级哲学 (机关之道)**:

```kotlin
val version = runCatching { JiguanNative.nativeVersion() }  // "jiguan-native/0.1.0"
    .getOrElse { null }                                    // ← so 缺失 / 非 arm64
if (version != null) {
    // 快通道: JNI 原生读写/扫描
} else {
    // 慢通道: shell 降级 (cat /proc/<pid>/maps + dd + grep),
    // 能力等价, 速度让步 —— 机关从不因组件缺失而卡死
}
```

约定:

- 句柄生命周期 `openProcess` ↔ `closeProcess` 严格配对, 用后即关;
- 同一句柄的并发调用需上层串行化 (见 docs/SAFETY.md);
- `scanValueMemory` 的 `fuzzyRange ≠ 0` 时, 数值型模糊匹配在 Kotlin
  侧完成, 原生侧始终是精确字节扫描。

## 安全纪律 / Security discipline

- **只碰你有权碰的进程**: 自身进程始终可读写; 其它进程需要 root
  (或同 uid + ptrace_scope 允许)。不做任何提权, 不绕过 SELinux。
- **ptrace 礼仪**: `hwbp` 会话 Drop 时必然清槽 + `PTRACE_DETACH`,
  绝不让目标进程停留在 stop 状态; 非 trap 信号原样重新注入。
- **panic 隔离**: JNI 边界 catch_unwind 全覆盖, 原生层异常绝不波及
  宿主进程。
- 详见 [docs/SAFETY.md](docs/SAFETY.md)。

## License

Apache-2.0 —— 与 Android-Guru-Agent 宿主同源。
