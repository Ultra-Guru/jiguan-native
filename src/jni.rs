//! JNI 边界 —— 符号与 Kotlin 契约一一对应。
//!
//! 宿主类: `com.apex.agent.platform.jiguan.native.JiguanNative`
//! (标准 JNI 名字改编, 如 `Java_com_apex_agent_platform_jiguan_native_JiguanNative_openProcess`)。
//!
//! ## 边界纪律
//!
//! - 每个入口都包 `catch_unwind`: Rust 的 `extern "system"` 边界
//!   panic 会直接 abort 整个进程 (非 C-unwind ABI), 必须拦下;
//! - 出错返回安全默认值: `-1` / `null` / `false` / 空字符串;
//! - 句柄 = `Box<MemHandle>` 的裸指针 (openProcess 产生,
//!   closeProcess 收回); 0 / -1 一律视为非法;
//! - 线程约定: 同一句柄的并发调用需上层串行化 (见 docs/SAFETY.md)。

use std::panic::{catch_unwind, AssertUnwindSafe};

use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{
    jboolean, jbyteArray, jdouble, jint, jlong, jlongArray, jobjectArray, jstring, JNI_FALSE,
    JNI_TRUE,
};
use jni::JNIEnv;

use crate::hook;
use crate::mem::MemHandle;
use crate::scan;
use crate::{native_version, proc};

// ---------------------------------------------------------------------------
// 句柄工具
// ---------------------------------------------------------------------------

/// jlong 句柄 → `&mut MemHandle`。
///
/// SAFETY: 句柄只能来自 `openProcess` 的 `Box::into_raw` 产物,
/// 且在 `closeProcess` 之前保持有效; 调用期间不得并发 close。
fn mem_handle(handle: jlong) -> Option<&'static mut MemHandle> {
    if handle <= 0 {
        return None;
    }
    // SAFETY: 指针由 Box::into_raw 产生 (堆上合法对象),
    // 生命周期由 JNI 侧 open/close 配对管理, 见模块文档线程约定
    unsafe { (handle as *mut MemHandle).as_mut() }
}

/// panic 载荷 → 可读日志 + 清理挂起的 Java 异常, 保证默认值干净返回。
fn log_panic(env: &mut JNIEnv, name: &str, payload: Box<dyn std::any::Any + Send>) {
    let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "未知 panic 载荷".to_string()
    };
    log::error!("JNI {name} panic (已拦截): {msg}");
    // 清掉可能挂起的 Java 异常, 让默认值能顺利返回宿主
    let _ = env.exception_clear();
}

// ---------------------------------------------------------------------------
// 导出符号 (与 JiguanNative.kt 契约一一对应)
// ---------------------------------------------------------------------------

/// `openProcess(pid: Int): Long` —— 打开目标进程内存句柄; 失败 -1。
#[no_mangle]
pub extern "system" fn Java_com_apex_agent_platform_jiguan_native_JiguanNative_openProcess(
    mut env: JNIEnv,
    _class: JClass,
    pid: jint,
) -> jlong {
    match catch_unwind(AssertUnwindSafe(|| {
        match MemHandle::open(pid) {
            // SAFETY: 裸指针所有权移交 jlong, 由 closeProcess 收回
            Ok(h) => Box::into_raw(Box::new(h)) as jlong,
            Err(e) => {
                log::error!("openProcess({pid}) 失败: {e}");
                -1
            }
        }
    })) {
        Ok(h) => h,
        Err(p) => {
            log_panic(&mut env, "openProcess", p);
            -1
        }
    }
}

/// `closeProcess(handle: Long)` —— 关闭句柄 (幂等, 非法句柄静默忽略)。
#[no_mangle]
pub extern "system" fn Java_com_apex_agent_platform_jiguan_native_JiguanNative_closeProcess(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if handle > 0 {
            // SAFETY: 句柄来自 openProcess 的 Box::into_raw;
            // 此处收回唯一所有权并析构 (Drop 关闭 fd)
            drop(unsafe { Box::from_raw(handle as *mut MemHandle) });
        }
    }));
    if res.is_err() {
        log_panic(&mut env, "closeProcess", Box::new("close panic"));
    }
}

/// `readMemory(handle, address, size): ByteArray` —— 失败返回 null。
#[no_mangle]
pub extern "system" fn Java_com_apex_agent_platform_jiguan_native_JiguanNative_readMemory(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
    size: jint,
) -> jbyteArray {
    match catch_unwind(AssertUnwindSafe(|| {
        read_memory(&mut env, handle, address, size)
    })) {
        Ok(arr) => arr,
        Err(p) => {
            log_panic(&mut env, "readMemory", p);
            std::ptr::null_mut()
        }
    }
}

fn read_memory(env: &mut JNIEnv, handle: jlong, address: jlong, size: jint) -> jbyteArray {
    let Some(mem) = mem_handle(handle) else {
        return std::ptr::null_mut();
    };
    let len = usize::try_from(size.max(0)).unwrap_or(0);
    let buf = match mem.read(address as u64, len) {
        Ok(b) => b,
        Err(e) => {
            log::debug!("readMemory({address:#x}, {size}) 失败: {e}");
            return std::ptr::null_mut();
        }
    };
    match env.byte_array_from_slice(&buf) {
        Ok(arr) => arr.into_raw(),
        Err(e) => {
            log::error!("readMemory 构造 byte[] 失败: {e}");
            std::ptr::null_mut()
        }
    }
}

/// `writeMemory(handle, address, data): Boolean` —— 全量写成功才 true。
#[no_mangle]
pub extern "system" fn Java_com_apex_agent_platform_jiguan_native_JiguanNative_writeMemory(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
    data: jbyteArray,
) -> jboolean {
    match catch_unwind(AssertUnwindSafe(|| {
        write_memory(&mut env, handle, address, data)
    })) {
        Ok(ok) => ok,
        Err(p) => {
            log_panic(&mut env, "writeMemory", p);
            JNI_FALSE
        }
    }
}

fn write_memory(env: &mut JNIEnv, handle: jlong, address: jlong, data: jbyteArray) -> jboolean {
    let Some(mem) = mem_handle(handle) else {
        return JNI_FALSE;
    };
    if data.is_null() {
        return JNI_FALSE;
    }
    // SAFETY: data 为 JVM 侧传入的有效非空 jbyteArray;
    // JByteArray 包装者析构不会释放 JVM 引用 (局部引用随帧回收)
    let jarr = unsafe { JByteArray::from_raw(data) };
    let bytes = match env.convert_byte_array(&jarr) {
        Ok(b) => b,
        Err(e) => {
            log::error!("writeMemory 读取 byte[] 失败: {e}");
            return JNI_FALSE;
        }
    };
    match mem.write_all_bytes(address as u64, &bytes) {
        Ok(()) => JNI_TRUE,
        Err(e) => {
            log::debug!("writeMemory({address:#x}, {} 字节) 失败: {e}", bytes.len());
            JNI_FALSE
        }
    }
}

/// `scanRegions(pid: Int): Array<String>` —— 可扫区域 (rw-/r-x) 的标准
/// maps 行; 失败返回 null (宿主据此走 shell 降级)。
#[no_mangle]
pub extern "system" fn Java_com_apex_agent_platform_jiguan_native_JiguanNative_scanRegions(
    mut env: JNIEnv,
    _class: JClass,
    pid: jint,
) -> jobjectArray {
    match catch_unwind(AssertUnwindSafe(|| scan_regions(&mut env, pid))) {
        Ok(arr) => arr,
        Err(p) => {
            log_panic(&mut env, "scanRegions", p);
            std::ptr::null_mut()
        }
    }
}

fn scan_regions(env: &mut JNIEnv, pid: jint) -> jobjectArray {
    let regions = match proc::scan_regions(pid) {
        Ok(r) => r,
        Err(e) => {
            log::error!("scanRegions({pid}) 失败: {e}");
            return std::ptr::null_mut();
        }
    };
    let lines: Vec<String> = regions.iter().map(|r| r.to_map_line()).collect();
    to_string_array(env, &lines)
}

/// `scanMemory(handle, pattern, maxResults): LongArray` —— AOB 扫描;
/// 无命中返回空数组, 句柄/模式非法返回 null。
#[no_mangle]
pub extern "system" fn Java_com_apex_agent_platform_jiguan_native_JiguanNative_scanMemory(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    pattern: jstring,
    max_results: jint,
) -> jlongArray {
    match catch_unwind(AssertUnwindSafe(|| {
        scan_memory_common(&mut env, handle, pattern, max_results)
    })) {
        Ok(arr) => arr,
        Err(p) => {
            log_panic(&mut env, "scanMemory", p);
            std::ptr::null_mut()
        }
    }
}

/// `scanValueMemory(handle, valueBytes, fuzzyRange, maxResults): LongArray`。
///
/// 精确字节扫描; `fuzzyRange != 0` 时仅记日志 —— 数值型模糊匹配
/// 由 Kotlin 侧完成 (此处保持纯字节语义, 契约见 README)。
#[no_mangle]
pub extern "system" fn Java_com_apex_agent_platform_jiguan_native_JiguanNative_scanValueMemory(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    value_bytes: jbyteArray,
    fuzzy_range: jdouble,
    max_results: jint,
) -> jlongArray {
    match catch_unwind(AssertUnwindSafe(|| {
        scan_value_memory(&mut env, handle, value_bytes, fuzzy_range, max_results)
    })) {
        Ok(arr) => arr,
        Err(p) => {
            log_panic(&mut env, "scanValueMemory", p);
            std::ptr::null_mut()
        }
    }
}

fn scan_value_memory(
    env: &mut JNIEnv,
    handle: jlong,
    value_bytes: jbyteArray,
    fuzzy_range: jdouble,
    max_results: jint,
) -> jlongArray {
    if fuzzy_range != 0.0 {
        log::debug!("scanValueMemory: fuzzyRange={fuzzy_range} 非零, 模糊匹配由 Kotlin 侧负责, 此处按精确字节扫描");
    }
    let Some(mem) = mem_handle(handle) else {
        return std::ptr::null_mut();
    };
    if value_bytes.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: JVM 侧传入的有效非空 jbyteArray
    let jarr = unsafe { JByteArray::from_raw(value_bytes) };
    let bytes = match env.convert_byte_array(&jarr) {
        Ok(b) => b,
        Err(e) => {
            log::error!("scanValueMemory 读取 byte[] 失败: {e}");
            return std::ptr::null_mut();
        }
    };
    if bytes.is_empty() {
        return std::ptr::null_mut();
    }
    let pattern: Vec<Option<u8>> = bytes.into_iter().map(Some).collect();
    let max = max_results.max(0) as usize;
    match scan::scan_memory(mem, &pattern, max) {
        Ok(addrs) => to_long_array(env, &addrs),
        Err(e) => {
            log::error!("scanValueMemory 扫描失败: {e}");
            std::ptr::null_mut()
        }
    }
}

/// scanMemory 实现: 模式串解析 + 全区域扫描。
fn scan_memory_common(
    env: &mut JNIEnv,
    handle: jlong,
    pattern: jstring,
    max_results: jint,
) -> jlongArray {
    let Some(mem) = mem_handle(handle) else {
        return std::ptr::null_mut();
    };
    if pattern.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: JVM 侧传入的有效非空 jstring
    let jstr = unsafe { JString::from_raw(pattern) };
    let pattern_str = match env.get_string(&jstr) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(e) => {
            log::error!("scanMemory 读取 pattern 失败: {e}");
            return std::ptr::null_mut();
        }
    };
    let parsed = match scan::parse_pattern(&pattern_str) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("scanMemory 模式非法 {pattern_str:?}: {e}");
            return std::ptr::null_mut();
        }
    };
    let max = max_results.max(0) as usize;
    match scan::scan_memory(mem, &parsed, max) {
        Ok(addrs) => to_long_array(env, &addrs),
        Err(e) => {
            log::error!("scanMemory 扫描失败: {e}");
            std::ptr::null_mut()
        }
    }
}

/// `readCString(handle, address, maxLen): String` —— 失败返回空串。
#[no_mangle]
pub extern "system" fn Java_com_apex_agent_platform_jiguan_native_JiguanNative_readCString(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
    max_len: jint,
) -> jstring {
    match catch_unwind(AssertUnwindSafe(|| {
        read_cstring(&mut env, handle, address, max_len)
    })) {
        Ok(s) => s,
        Err(p) => {
            log_panic(&mut env, "readCString", p);
            new_string_or_null(&mut env, "")
        }
    }
}

fn read_cstring(env: &mut JNIEnv, handle: jlong, address: jlong, max_len: jint) -> jstring {
    let s = match mem_handle(handle) {
        Some(mem) => match mem.read_cstring(address as u64, max_len.max(0) as usize) {
            Ok(s) => s,
            Err(e) => {
                log::debug!("readCString({address:#x}) 失败: {e}");
                String::new()
            }
        },
        None => String::new(),
    };
    new_string_or_null(env, &s)
}

/// `arm64Trampoline(target: Long): ByteArray` —— 16 字节绝对跳转桩
/// (纯计算, 永不失败; env 异常时仍可能返回 null)。
#[no_mangle]
pub extern "system" fn Java_com_apex_agent_platform_jiguan_native_JiguanNative_arm64Trampoline(
    mut env: JNIEnv,
    _class: JClass,
    target: jlong,
) -> jbyteArray {
    match catch_unwind(AssertUnwindSafe(|| {
        let bytes = hook::arm64_trampoline(target as u64);
        match env.byte_array_from_slice(&bytes) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                log::error!("arm64Trampoline 构造 byte[] 失败: {e}");
                std::ptr::null_mut()
            }
        }
    })) {
        Ok(arr) => arr,
        Err(p) => {
            log_panic(&mut env, "arm64Trampoline", p);
            std::ptr::null_mut()
        }
    }
}

/// `nativeVersion(): String` —— 形如 "jiguan-native/0.1.0"。
#[no_mangle]
pub extern "system" fn Java_com_apex_agent_platform_jiguan_native_JiguanNative_nativeVersion(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    match catch_unwind(AssertUnwindSafe(|| {
        new_string_or_null(&mut env, native_version())
    })) {
        Ok(s) => s,
        Err(p) => {
            log_panic(&mut env, "nativeVersion", p);
            new_string_or_null(&mut env, "")
        }
    }
}

// ---------------------------------------------------------------------------
// JVM 数组构造辅助
// ---------------------------------------------------------------------------

/// 构造 Java String[]; 失败返回 null。
fn to_string_array(env: &mut JNIEnv, lines: &[String]) -> jobjectArray {
    let class = match env.find_class("java/lang/String") {
        Ok(c) => c,
        Err(e) => {
            log::error!("to_string_array 找不到 String 类: {e}");
            return std::ptr::null_mut();
        }
    };
    let arr = match env.new_object_array(lines.len() as i32, class, JObject::null()) {
        Ok(a) => a,
        Err(e) => {
            log::error!("to_string_array 构造数组失败: {e}");
            return std::ptr::null_mut();
        }
    };
    for (i, line) in lines.iter().enumerate() {
        let jline = match env.new_string(line) {
            Ok(s) => s,
            Err(e) => {
                log::error!("to_string_array 构造 String 失败: {e}");
                return std::ptr::null_mut();
            }
        };
        if let Err(e) = env.set_object_array_element(&arr, i as i32, jline.into()) {
            log::error!("to_string_array 写入元素失败: {e}");
            return std::ptr::null_mut();
        }
    }
    arr.into_raw()
}

/// 构造 Java long[]; 失败返回 null。
fn to_long_array(env: &mut JNIEnv, values: &[jlong]) -> jlongArray {
    let arr = match env.new_long_array(values.len() as i32) {
        Ok(a) => a,
        Err(e) => {
            log::error!("to_long_array 构造数组失败: {e}");
            return std::ptr::null_mut();
        }
    };
    if !values.is_empty() {
        if let Err(e) = env.set_long_array_region(&arr, 0, values) {
            log::error!("to_long_array 写入元素失败: {e}");
            return std::ptr::null_mut();
        }
    }
    arr.into_raw()
}

/// 构造 Java String; env 异常兜底返回 null。
fn new_string_or_null(env: &mut JNIEnv, s: &str) -> jstring {
    match env.new_string(s) {
        Ok(js) => js.into_raw(),
        Err(e) => {
            log::error!("new_string({s:?}) 失败: {e}");
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 非正数句柄必须被挡在门口 (0 / -1 都视为非法)。
    #[test]
    fn jni_handle_guard_rejects_nonpositive() {
        assert!(mem_handle(0).is_none());
        assert!(mem_handle(-1).is_none());
    }
}
