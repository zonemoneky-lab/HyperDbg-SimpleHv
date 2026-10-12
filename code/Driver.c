/**
 * @file Driver.c
 * @author Your Name
 * @brief SimpleHv Driver Entry and Main Logic
 * @details
 * SimpleHv - A simple hypervisor for learning Intel VT-x
 * Based on HyperDbg architecture
 *
 * @version 0.1
 * @date 2025-10-20
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

//////////////////////////////////////////////////
//               Global Variables               //
//////////////////////////////////////////////////

PDEVICE_OBJECT g_DeviceObject = NULL;

//////////////////////////////////////////////////
//            Function Declarations             //
//////////////////////////////////////////////////

VOID DriverUnLoad(PDRIVER_OBJECT DriverObject);

//
// ========================================
// Driver Entry Point
// ========================================
//

/**
 * @brief Driver Entry Point
 *
 * @param DriverObject Pointer to driver object
 * @param RegistryPath Registry path
 * @return NTSTATUS Status code
 */
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    NTSTATUS Ntstatus = STATUS_SUCCESS;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;

    UNREFERENCED_PARAMETER(RegistryPath);

    SimpleHvLog("========================================");
    SimpleHvLog("[Driver] SimpleHv driver loading...");
    SimpleHvLog("========================================");

    // Initialize non-executable pool memory
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    // Register unload routine
    DriverObject->DriverUnload = DriverUnLoad;

    // Register IRP handlers
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceIoctlCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceIoctlClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoctlDispatch;

    // Create device
    RtlInitUnicodeString(&deviceName, L"\\Device\\SimpleHv");
    Ntstatus = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(Ntstatus)) {
        SimpleHvLogError("[Driver] Failed to create device: 0x%x", Ntstatus);
        return Ntstatus;
    }

    SimpleHvLog("[Driver] Device created successfully");

    // Create symbolic link
    RtlInitUnicodeString(&symbolicLink, L"\\DosDevices\\SimpleHv");
    Ntstatus = IoCreateSymbolicLink(&symbolicLink, &deviceName);

    if (!NT_SUCCESS(Ntstatus)) {
        SimpleHvLogError("[Driver] Failed to create symbolic link: 0x%x", Ntstatus);
        IoDeleteDevice(g_DeviceObject);
        return Ntstatus;
    }

    SimpleHvLog("[Driver] Symbolic link created: \\\\.\\SimpleHv");

    // Initialize VMM
    if (!LoaderInitVmm()) {
        SimpleHvLogError("[Driver] LoaderInitVmm failed!");
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(g_DeviceObject);
        return STATUS_UNSUCCESSFUL;
    }
    SimpleHvLog("[Driver] LoaderInitVmm success");

    // Initialize Driver (EPT related)
    if (!LoaderInitDriver()) {
        SimpleHvLogError("[Driver] LoaderInitDriver failed!");
        SimpleHvLogWarning("[Driver] HyperEvade will be disabled due to pool allocation failure");
	}
	else {
		SimpleHvLog("[Driver] LoaderInitDriver success");

        // Configure HyperEvade transparent mode
        DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE Request = { 0 };

        Request.IsHide = TRUE;
        Request.TrueIfProcessIdAndFalseIfProcessName = TRUE;
        Request.ProcId = 0;

        // System call numbers (TODO: Get dynamically from ntdll)
        Request.SystemCallNumbersInformation.SysNtQuerySystemInformation = 0x36;
        Request.SystemCallNumbersInformation.SysNtQuerySystemInformationEx = 0xF1;
        Request.SystemCallNumbersInformation.SysNtSystemDebugControl = 0x1D9;
        Request.SystemCallNumbersInformation.SysNtQueryAttributesFile = 0x40;
        Request.SystemCallNumbersInformation.SysNtOpenDirectoryObject = 0x58;
        Request.SystemCallNumbersInformation.SysNtQueryDirectoryObject = 0x5B;
        Request.SystemCallNumbersInformation.SysNtQueryInformationProcess = 0x19;
        Request.SystemCallNumbersInformation.SysNtSetInformationProcess = 0x1C;
        Request.SystemCallNumbersInformation.SysNtQueryInformationThread = 0x25;
        Request.SystemCallNumbersInformation.SysNtSetInformationThread = 0x0D;
        Request.SystemCallNumbersInformation.SysNtOpenFile = 0x33;
        Request.SystemCallNumbersInformation.SysNtOpenKey = 0x12;
        Request.SystemCallNumbersInformation.SysNtOpenKeyEx = 0xCF;
        Request.SystemCallNumbersInformation.SysNtQueryValueKey = 0x17;
        Request.SystemCallNumbersInformation.SysNtEnumerateKey = 0x32;

        // Activate transparent mode
        if (TransparentHideDebuggerWrapper(&Request))
        {
            SimpleHvLog("[Driver] HyperEvade transparent mode activated successfully!");
        }
        else
        {
            SimpleHvLogWarning("[Driver] HyperEvade failed to activate, status: 0x%x",
                Request.KernelStatus);
        }
	}

    SimpleHvLog("========================================");
    SimpleHvLog("[Driver] SimpleHv driver loaded successfully");
    SimpleHvLog("[Driver] Device ready: \\\\.\\SimpleHv");
    SimpleHvLog("========================================");

    return STATUS_SUCCESS;
}


VOID DriverUnLoad(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symbolicLink;

    UNREFERENCED_PARAMETER(DriverObject);

    SimpleHvLog("========================================");
    SimpleHvLog("[Driver] Driver unloading...");
    SimpleHvLog("========================================");

    // Uninitialize VMM
    VmFuncUninitVmm();
    SimpleHvLog("[Driver] VMM uninitialized");

    // Delete symbolic link
    RtlInitUnicodeString(&symbolicLink, L"\\DosDevices\\SimpleHv");
    IoDeleteSymbolicLink(&symbolicLink);
    SimpleHvLog("[Driver] Symbolic link deleted");

    // Delete device
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        SimpleHvLog("[Driver] Device deleted");
    }

    SimpleHvLog("========================================");
    SimpleHvLog("[Driver] Driver unloaded successfully");
    SimpleHvLog("========================================");
}
