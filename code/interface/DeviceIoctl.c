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
    response->HooksInstalled = NT_SUCCESS(status) ? 2 : 0;

    if (NT_SUCCESS(status)) {
        SimpleHvLog("[DeviceIoctl] Test hooks installed successfully");
    } else {
        SimpleHvLogError("[DeviceIoctl] Failed to install test hooks: 0x%x", status);
    }

    Irp->IoStatus.Information = sizeof(SIMPLEHV_INSTALL_HOOKS_RESPONSE);
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
