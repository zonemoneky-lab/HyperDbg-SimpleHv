/**
 * @file DeviceIoctl.h
 * @brief SimpleHv IOCTL Definitions
 * @details Defines IOCTL codes and structures for user-kernel communication
 */

#pragma once

#include <ntddk.h>

//////////////////////////////////////////////////
//            IOCTL Code Definitions            //
//////////////////////////////////////////////////

// Device type (custom device)
#define FILE_DEVICE_SIMPLEHV    0x8000

// IOCTL Codes
#define IOCTL_SIMPLEHV_PING \
    CTL_CODE(FILE_DEVICE_SIMPLEHV, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SIMPLEHV_INSTALL_TEST_HOOKS \
    CTL_CODE(FILE_DEVICE_SIMPLEHV, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SIMPLEHV_UNHOOK_ALL \
    CTL_CODE(FILE_DEVICE_SIMPLEHV, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 设置 MiReadWriteVirtualMemory Hook 的保护范围（PID + 模块地址区间）
#define IOCTL_SIMPLEHV_SET_MIRWM_RANGE \
    CTL_CODE(FILE_DEVICE_SIMPLEHV, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 设置 MmCopyMemory Hook 的隐藏区域（可选 PID + 地址区间）
#define IOCTL_SIMPLEHV_SET_MMCOPY_REGION \
    CTL_CODE(FILE_DEVICE_SIMPLEHV, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

//////////////////////////////////////////////////
//            Data Structures                   //
//////////////////////////////////////////////////

/**
 * @brief Ping response structure
 */
typedef struct _SIMPLEHV_PING_RESPONSE {
    UINT64 Signature;       // Should be HYPERCALL_SIGN
    UINT32 NumProcessors;   // Number of logical processors
    BOOLEAN IsRunning;      // Is hypervisor running
} SIMPLEHV_PING_RESPONSE, *PSIMPLEHV_PING_RESPONSE;

/**
 * @brief Install test hooks response
 */
typedef struct _SIMPLEHV_INSTALL_HOOKS_RESPONSE {
    NTSTATUS Status;        // Installation status
    UINT32 HooksInstalled;  // Number of hooks installed
} SIMPLEHV_INSTALL_HOOKS_RESPONSE, *PSIMPLEHV_INSTALL_HOOKS_RESPONSE;

/**
 * @brief 设置 MiRWM 保护范围的请求
 * @details 只保护 ProcessId 进程中 [BaseAddress, BaseAddress + Size) 的读取。
 *          Size == 0 表示清除配置 / 关闭保护。
 *
 *          字段统一使用 UINT64 / UINT32，保证与 usermode 端结构体布局一致。
 */
typedef struct _SIMPLEHV_SET_MIRWM_RANGE_REQUEST {
    UINT32 ProcessId;       // 目标进程 PID
    UINT32 Reserved;        // 对齐填充
    UINT64 BaseAddress;     // 受保护模块基址
    UINT64 Size;            // 受保护范围大小（0 = 关闭保护）
} SIMPLEHV_SET_MIRWM_RANGE_REQUEST, *PSIMPLEHV_SET_MIRWM_RANGE_REQUEST;

/**
 * @brief 设置 MiRWM 保护范围的响应（回显实际生效的配置）
 */
typedef struct _SIMPLEHV_SET_MIRWM_RANGE_RESPONSE {
    UINT32 Status;          // NTSTATUS
    UINT32 ProcessId;       // 实际生效的 PID
    UINT64 BaseAddress;     // 实际生效的基址
    UINT64 Size;            // 实际生效的大小
} SIMPLEHV_SET_MIRWM_RANGE_RESPONSE, *PSIMPLEHV_SET_MIRWM_RANGE_RESPONSE;

/**
 * @brief 设置 MmCopyMemory 隐藏区域的请求
 * @details 源地址范围与 [Start, Start + Size) 重叠的拷贝会被拦截。
 *          ProcessId == 0 表示不限进程（任意地址空间上下文都拦）。
 *          Size == 0 表示清除配置 / 关闭拦截。
 */
typedef struct _SIMPLEHV_SET_MMCOPY_REGION_REQUEST {
    UINT32 ProcessId;       // 可选，限定进程；0 = 任意进程
    UINT32 Reserved;        // 对齐填充
    UINT64 Start;           // 隐藏区域起始地址
    UINT64 Size;            // 隐藏区域大小（0 = 关闭拦截）
} SIMPLEHV_SET_MMCOPY_REGION_REQUEST, *PSIMPLEHV_SET_MMCOPY_REGION_REQUEST;

/**
 * @brief 设置 MmCopyMemory 隐藏区域的响应（回显实际生效的配置）
 */
typedef struct _SIMPLEHV_SET_MMCOPY_REGION_RESPONSE {
    UINT32 Status;          // NTSTATUS
    UINT32 ProcessId;       // 实际生效的 PID
    UINT64 Start;           // 实际生效的起始地址
    UINT64 Size;            // 实际生效的大小
} SIMPLEHV_SET_MMCOPY_REGION_RESPONSE, *PSIMPLEHV_SET_MMCOPY_REGION_RESPONSE;

//////////////////////////////////////////////////
//            Function Declarations             //
//////////////////////////////////////////////////

/**
 * @brief Handle IRP_MJ_CREATE
 */
NTSTATUS DeviceIoctlCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/**
 * @brief Handle IRP_MJ_CLOSE
 */
NTSTATUS DeviceIoctlClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/**
 * @brief Handle IRP_MJ_DEVICE_CONTROL
 */
NTSTATUS DeviceIoctlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
