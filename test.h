
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
 *          3. MiCopyVirtualMemory - 拦截跨进程内存读写（从 MmCopyVirtualMemory 反汇编定位）
 *          4. MmCopyMemory - 拦截直接内存拷贝（导出函数，隐藏区域命中即阻断）
 *          5. MmQueryVirtualMemory - 查询受保护模块区域时把 Protect 伪装成
 *             PAGE_NOACCESS（未导出，特征码扫描定位；复用第 3 项的保护范围配置）
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
 * @brief 设置受保护模块区域（Hook 3 MiCopyVirtualMemory 与 Hook 5 MmQueryVirtualMemory 共用）
 * @details 保护「PID == ProcessId 的进程」中、地址落在
 *          [BaseAddress, BaseAddress + Size) 的模块区域：
 *            - Hook 3：读取命中的那一段会被清零；写入命中直接拦截；
 *            - Hook 5：查询该区域时，返回的 MEMORY_BASIC_INFORMATION.Protect
 *              会被伪装成 PAGE_NOACCESS。
 *          范围之外完全不动。
 *
 *          Size == 0 表示清除配置 / 关闭保护，此时两个 Hook 都纯透传。
 *
 * @param ProcessId   目标进程 PID
 * @param BaseAddress 受保护模块基址
 * @param Size        受保护范围大小（字节），0 表示关闭保护
 *
 * @note 该配置随时可改，无需重新安装 Hook；Hook 内部会实时读取这些值。
 */
VOID SetMiRWMProtectRange(ULONG ProcessId, ULONG_PTR BaseAddress, ULONG_PTR Size);

/**
 * @brief 设置 MmCopyMemory Hook 的隐藏区域
 * @details 当某次 MmCopyMemory 的「源地址范围」与
 *          [Start, Start + Size) 发生重叠时，直接拦截
 *          （返回 0xC0000018，传输字节数置 0）。
 *
 *          - VIRTUAL 源：直接比较 VirtualAddress 区间；
 *          - PHYSICAL 源：先 MmGetVirtualForPhysical 映射再比较。
 *          - ProcessId != 0 时只拦截「当前进程上下文 == 该 PID」的请求；
 *            ProcessId == 0 表示不限进程。
 *          - Size == 0 表示清除配置 / 关闭拦截（Hook 变回纯透传）。
 *
 * @param ProcessId 可选，限定进程；0 = 任意进程
 * @param Start     隐藏区域起始地址
 * @param Size      隐藏区域大小（字节），0 = 关闭
 */
VOID SetMmCopyHideRegion(ULONG ProcessId, ULONG_PTR Start, ULONG_PTR Size);
