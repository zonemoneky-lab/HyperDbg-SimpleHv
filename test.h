
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
