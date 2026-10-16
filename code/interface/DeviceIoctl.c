/**
 * @file DeviceIoctl.c
 * @brief SimpleHv IOCTL Implementation
 * @details Implements device I/O control handlers for user-kernel communication
 */

#include "pch.h"

/**
 * @brief Handle IRP_MJ_CREATE
 */
NTSTATUS
DeviceIoctlCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    SimpleHvLog("[DeviceIoctl] CREATE request");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle IRP_MJ_CLOSE
 */
NTSTATUS
DeviceIoctlClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    SimpleHvLog("[DeviceIoctl] CLOSE request");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle IOCTL_SIMPLEHV_PING
 */
NTSTATUS
HandleIoctlPing(PIRP Irp)
{
    PIO_STACK_LOCATION irpStack;
    SIMPLEHV_PING_RESPONSE* response;
    ULONG outputBufferLength;

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    // Check output buffer size
    if (outputBufferLength < sizeof(SIMPLEHV_PING_RESPONSE)) {
        SimpleHvLogError("[DeviceIoctl] PING: Output buffer too small");
        return STATUS_BUFFER_TOO_SMALL;
    }

    response = (SIMPLEHV_PING_RESPONSE*)Irp->AssociatedIrp.SystemBuffer;

    // Fill response
    response->Signature = HYPERCALL_SIGN;
    response->NumProcessors = KeQueryActiveProcessorCount(0);
    response->IsRunning = VmxGetCurrentLaunchState();

    SimpleHvLog("[DeviceIoctl] PING: Signature=0x%llx, NumCPUs=%d, Running=%d",
                response->Signature, response->NumProcessors, response->IsRunning);

    Irp->IoStatus.Information = sizeof(SIMPLEHV_PING_RESPONSE);
    return STATUS_SUCCESS;
}

/**
 * @brief Handle IOCTL_SIMPLEHV_INSTALL_TEST_HOOKS
 */
NTSTATUS
HandleIoctlInstallTestHooks(PIRP Irp)
{
    PIO_STACK_LOCATION irpStack;
    SIMPLEHV_INSTALL_HOOKS_RESPONSE* response;
    ULONG outputBufferLength;
    NTSTATUS status;

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    // Check output buffer size
    if (outputBufferLength < sizeof(SIMPLEHV_INSTALL_HOOKS_RESPONSE)) {
        SimpleHvLogError("[DeviceIoctl] INSTALL_HOOKS: Output buffer too small");
        return STATUS_BUFFER_TOO_SMALL;
    }

    SimpleHvLog("[DeviceIoctl] Installing test hooks...");

    // Call InstallTestHooks in normal kernel context
    status = InstallTestHooks();

    response = (SIMPLEHV_INSTALL_HOOKS_RESPONSE*)Irp->AssociatedIrp.SystemBuffer;
    response->Status = status;
    response->HooksInstalled = NT_SUCCESS(status) ? 5 : 0;

    if (NT_SUCCESS(status)) {
        SimpleHvLog("[DeviceIoctl] Test hooks installed successfully");
    } else {
        SimpleHvLogError("[DeviceIoctl] Failed to install test hooks: 0x%x", status);
    }

    Irp->IoStatus.Information = sizeof(SIMPLEHV_INSTALL_HOOKS_RESPONSE);
    return STATUS_SUCCESS;
}

/**
 * @brief Handle IOCTL_SIMPLEHV_SET_MIRWM_RANGE
 * @details 设置 MiReadWriteVirtualMemory Hook 的保护范围（PID + 模块地址区间）。
 *          只保护指定进程中落在 [BaseAddress, BaseAddress + Size) 的内存读取，
 *          Size == 0 表示清除配置 / 关闭保护（Hook 变回纯透传）。
 */
NTSTATUS
HandleIoctlSetMiRwmRange(PIRP Irp)
{
    PIO_STACK_LOCATION irpStack;
    SIMPLEHV_SET_MIRWM_RANGE_REQUEST*  request;
    SIMPLEHV_SET_MIRWM_RANGE_RESPONSE* response;
    ULONG inputBufferLength;
    ULONG outputBufferLength;
    ULONG     processId;
    ULONG_PTR baseAddress;
    ULONG_PTR size;

    irpStack           = IoGetCurrentIrpStackLocation(Irp);
    inputBufferLength  = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inputBufferLength < sizeof(SIMPLEHV_SET_MIRWM_RANGE_REQUEST)) {
        SimpleHvLogError("[DeviceIoctl] SET_MIRWM_RANGE: Input buffer too small (%u < %u)",
                         inputBufferLength, (ULONG)sizeof(SIMPLEHV_SET_MIRWM_RANGE_REQUEST));
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (outputBufferLength < sizeof(SIMPLEHV_SET_MIRWM_RANGE_RESPONSE)) {
        SimpleHvLogError("[DeviceIoctl] SET_MIRWM_RANGE: Output buffer too small (%u < %u)",
                         outputBufferLength, (ULONG)sizeof(SIMPLEHV_SET_MIRWM_RANGE_RESPONSE));
        return STATUS_BUFFER_TOO_SMALL;
    }

    // METHOD_BUFFERED: 输入 / 输出共用 SystemBuffer，先读出来再写回
    request     = (SIMPLEHV_SET_MIRWM_RANGE_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
    processId   = (ULONG)request->ProcessId;
    baseAddress = (ULONG_PTR)request->BaseAddress;
    size        = (ULONG_PTR)request->Size;

    SimpleHvLog("[DeviceIoctl] SET_MIRWM_RANGE: pid=%u base=0x%llx size=0x%llx",
                processId, (UINT64)baseAddress, (UINT64)size);

    // 应用到 Hook（内部会打自己的日志）
    SetMiRWMProtectRange(processId, baseAddress, size);

    response = (SIMPLEHV_SET_MIRWM_RANGE_RESPONSE*)Irp->AssociatedIrp.SystemBuffer;
    response->Status      = (UINT32)STATUS_SUCCESS;
    response->ProcessId   = processId;
    response->BaseAddress = (UINT64)baseAddress;
    response->Size        = (UINT64)size;

    Irp->IoStatus.Information = sizeof(SIMPLEHV_SET_MIRWM_RANGE_RESPONSE);
    return STATUS_SUCCESS;
}

/**
 * @brief Handle IOCTL_SIMPLEHV_SET_MMCOPY_REGION
 * @details 设置 MmCopyMemory Hook 的隐藏区域（可选 PID + 地址区间）。
 *          源地址范围与 [Start, Start + Size) 重叠的拷贝会被拦截。
 *          Size == 0 表示清除配置 / 关闭拦截。
 */
NTSTATUS
HandleIoctlSetMmCopyRegion(PIRP Irp)
{
    PIO_STACK_LOCATION irpStack;
    SIMPLEHV_SET_MMCOPY_REGION_REQUEST*  request;
    SIMPLEHV_SET_MMCOPY_REGION_RESPONSE* response;
    ULONG inputBufferLength;
    ULONG outputBufferLength;
    ULONG     processId;
    ULONG_PTR start;
    ULONG_PTR size;

    irpStack           = IoGetCurrentIrpStackLocation(Irp);
    inputBufferLength  = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inputBufferLength < sizeof(SIMPLEHV_SET_MMCOPY_REGION_REQUEST)) {
        SimpleHvLogError("[DeviceIoctl] SET_MMCOPY_REGION: Input buffer too small (%u < %u)",
                         inputBufferLength, (ULONG)sizeof(SIMPLEHV_SET_MMCOPY_REGION_REQUEST));
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (outputBufferLength < sizeof(SIMPLEHV_SET_MMCOPY_REGION_RESPONSE)) {
        SimpleHvLogError("[DeviceIoctl] SET_MMCOPY_REGION: Output buffer too small (%u < %u)",
                         outputBufferLength, (ULONG)sizeof(SIMPLEHV_SET_MMCOPY_REGION_RESPONSE));
        return STATUS_BUFFER_TOO_SMALL;
    }

    // METHOD_BUFFERED: 输入 / 输出共用 SystemBuffer，先读出来再写回
    request   = (SIMPLEHV_SET_MMCOPY_REGION_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
    processId = (ULONG)request->ProcessId;
    start     = (ULONG_PTR)request->Start;
    size      = (ULONG_PTR)request->Size;

    SimpleHvLog("[DeviceIoctl] SET_MMCOPY_REGION: pid=%u start=0x%llx size=0x%llx",
                processId, (UINT64)start, (UINT64)size);

    // 应用到 Hook（内部会打自己的日志）
    SetMmCopyHideRegion(processId, start, size);

    response = (SIMPLEHV_SET_MMCOPY_REGION_RESPONSE*)Irp->AssociatedIrp.SystemBuffer;
    response->Status    = (UINT32)STATUS_SUCCESS;
    response->ProcessId = processId;
    response->Start     = (UINT64)start;
    response->Size      = (UINT64)size;

    Irp->IoStatus.Information = sizeof(SIMPLEHV_SET_MMCOPY_REGION_RESPONSE);
    return STATUS_SUCCESS;
}

/**
 * @brief Handle IOCTL_SIMPLEHV_UNHOOK_ALL
 */
NTSTATUS
HandleIoctlUnhookAll(PIRP Irp)
{
    UNREFERENCED_PARAMETER(Irp);

    SimpleHvLog("[DeviceIoctl] Unhooking all hooks...");

    // Call unhook function
    EptHookUnHookAll();
	ResetTestHooksState();

    SimpleHvLog("[DeviceIoctl] All hooks removed");

    Irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

/**
 * @brief Handle IRP_MJ_DEVICE_CONTROL
 */
NTSTATUS
DeviceIoctlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpStack;
    ULONG controlCode;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

    SimpleHvLog("[DeviceIoctl] IOCTL request: 0x%x", controlCode);

    // Dispatch to specific handler
    switch (controlCode) {
        case IOCTL_SIMPLEHV_PING:
            status = HandleIoctlPing(Irp);
            break;

        case IOCTL_SIMPLEHV_INSTALL_TEST_HOOKS:
            status = HandleIoctlInstallTestHooks(Irp);
            break;

        case IOCTL_SIMPLEHV_UNHOOK_ALL:
            status = HandleIoctlUnhookAll(Irp);
            break;

        case IOCTL_SIMPLEHV_SET_MIRWM_RANGE:
            status = HandleIoctlSetMiRwmRange(Irp);
            break;

        case IOCTL_SIMPLEHV_SET_MMCOPY_REGION:
            status = HandleIoctlSetMmCopyRegion(Irp);
            break;

        default:
            SimpleHvLogWarning("[DeviceIoctl] Unknown IOCTL code: 0x%x", controlCode);
            status = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Information = 0;
            break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
