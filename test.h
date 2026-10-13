
/**
 * @file test.h
 * @brief EPT Hook 测试接口声明
 */

#pragma once

#include <ntddk.h>

/**
 * @brief 安装所有测试 Hooks
 * @details 安装以下 Hooks：
 *          1. ObpReferenceObjectByHandleWithTag - 保护指定进程不被打开
 *          2. NtQuerySystemInformation - 隐藏指定进程
 *          3. MiReadWriteVirtualMemory - 拦截跨进程内存读写（特征码扫描定位）
 *
 * @return NTSTATUS
 *         - STATUS_SUCCESS: 所有 Hook 安装成功
 *         - STATUS_UNSUCCESSFUL: Hook 安装失败
 *
 * @note 调用此函数前，Hypervisor 必须已经启动
 * @note 必须在 VMX non-root mode 下调用（从安装测试 Hook 的 IOCTL 调用）
 */
NTSTATUS InstallTestHooks(VOID);

/** Clear cached test-hook state after EptHookUnHookAll has removed the hooks. */
VOID ResetTestHooksState(VOID);

/**
 * @brief 设置 MiReadWriteVirtualMemory Hook 的保护范围
 * @details 只保护「PID == ProcessId 的进程」中、地址落在
 *          [BaseAddress, BaseAddress + Size) 的内存读取：命中的那一段会被
 *          清零，范围之外完全不动。
 *
 *          Size == 0 表示清除配置 / 关闭保护，此时 Hook 纯透传。
 *
 * @param ProcessId   目标进程 PID
 * @param BaseAddress 受保护模块基址
 * @param Size        受保护范围大小（字节），0 表示关闭保护
 *
 * @note 该配置随时可改，无需重新安装 Hook；Hook 内部会实时读取这些值。
 */
VOID SetMiRWMProtectRange(ULONG ProcessId, ULONG_PTR BaseAddress, ULONG_PTR Size);
