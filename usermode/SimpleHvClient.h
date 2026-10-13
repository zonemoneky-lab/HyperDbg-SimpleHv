/**
 * @file SimpleHvClient.h
 * @brief SimpleHv User Mode Client - IOCTL Interface
 * @details Provides C++ wrapper for communicating with SimpleHv driver via IOCTL
 */

#pragma once

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

//////////////////////////////////////////////////
//            IOCTL Code Definitions            //
//////////////////////////////////////////////////

#define FILE_DEVICE_SIMPLEHV    0x8000

#define IOCTL_SIMPLEHV_PING \
    CTL_CODE(FILE_DEVICE_SIMPLEHV, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SIMPLEHV_INSTALL_TEST_HOOKS \
    CTL_CODE(FILE_DEVICE_SIMPLEHV, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SIMPLEHV_UNHOOK_ALL \
    CTL_CODE(FILE_DEVICE_SIMPLEHV, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SIMPLEHV_SET_MIRWM_RANGE \
    CTL_CODE(FILE_DEVICE_SIMPLEHV, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

//////////////////////////////////////////////////
//            Data Structures                   //
//////////////////////////////////////////////////

typedef struct _SIMPLEHV_PING_RESPONSE {
    UINT64 Signature;
    UINT32 NumProcessors;
    BOOLEAN IsRunning;
} SIMPLEHV_PING_RESPONSE, *PSIMPLEHV_PING_RESPONSE;

typedef struct _SIMPLEHV_INSTALL_HOOKS_RESPONSE {
    UINT32 Status;          // NTSTATUS
    UINT32 HooksInstalled;
} SIMPLEHV_INSTALL_HOOKS_RESPONSE, *PSIMPLEHV_INSTALL_HOOKS_RESPONSE;

// 设置 MiRWM 保护范围（必须与驱动端 DeviceIoctl.h 布局一致）
typedef struct _SIMPLEHV_SET_MIRWM_RANGE_REQUEST {
    UINT32 ProcessId;       // 目标进程 PID
    UINT32 Reserved;        // 对齐填充
    UINT64 BaseAddress;     // 受保护模块基址
    UINT64 Size;            // 受保护范围大小（0 = 关闭保护）
} SIMPLEHV_SET_MIRWM_RANGE_REQUEST, *PSIMPLEHV_SET_MIRWM_RANGE_REQUEST;

typedef struct _SIMPLEHV_SET_MIRWM_RANGE_RESPONSE {
    UINT32 Status;          // NTSTATUS
    UINT32 ProcessId;       // 实际生效的 PID
    UINT64 BaseAddress;     // 实际生效的基址
    UINT64 Size;            // 实际生效的大小
} SIMPLEHV_SET_MIRWM_RANGE_RESPONSE, *PSIMPLEHV_SET_MIRWM_RANGE_RESPONSE;

//////////////////////////////////////////////////
//            SimpleHv Client Class             //
//////////////////////////////////////////////////

namespace SimpleHv {

class Client {
private:
    HANDLE hDevice;

public:
    Client() : hDevice(INVALID_HANDLE_VALUE) {}

    ~Client() {
        Close();
    }

    /**
     * @brief Open connection to SimpleHv driver
     */
    bool Open() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            return true; // Already opened
        }

        hDevice = CreateFileW(
            L"\\\\.\\SimpleHv",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        return (hDevice != INVALID_HANDLE_VALUE);
    }

    /**
     * @brief Close connection
     */
    void Close() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            hDevice = INVALID_HANDLE_VALUE;
        }
    }

    /**
     * @brief Check if connected
     */
    bool IsConnected() const {
        return (hDevice != INVALID_HANDLE_VALUE);
    }

    /**
     * @brief Ping hypervisor
     */
    bool Ping(SIMPLEHV_PING_RESPONSE* response) {
        if (!IsConnected()) return false;

        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            IOCTL_SIMPLEHV_PING,
            NULL,
            0,
            response,
            sizeof(SIMPLEHV_PING_RESPONSE),
            &bytesReturned,
            NULL
        ) != FALSE;
    }

    /**
     * @brief Install test hooks
     */
    bool InstallTestHooks(SIMPLEHV_INSTALL_HOOKS_RESPONSE* response) {
        if (!IsConnected()) return false;

        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            IOCTL_SIMPLEHV_INSTALL_TEST_HOOKS,
            NULL,
            0,
            response,
            sizeof(SIMPLEHV_INSTALL_HOOKS_RESPONSE),
            &bytesReturned,
            NULL
        ) != FALSE;
    }

    /**
     * @brief Set MiRWM protect range (PID + module address range)
     * @details 只保护 ProcessId 进程中 [BaseAddress, BaseAddress + Size) 的读取。
     *          Size == 0 表示清除配置 / 关闭保护。
     */
    bool SetMiRwmRange(UINT32 processId, UINT64 baseAddress, UINT64 size,
                       SIMPLEHV_SET_MIRWM_RANGE_RESPONSE* response) {
        if (!IsConnected()) return false;

        SIMPLEHV_SET_MIRWM_RANGE_REQUEST request = { 0 };
        request.ProcessId   = processId;
        request.Reserved    = 0;
        request.BaseAddress = baseAddress;
        request.Size        = size;

        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            IOCTL_SIMPLEHV_SET_MIRWM_RANGE,
            &request,
            sizeof(SIMPLEHV_SET_MIRWM_RANGE_REQUEST),
            response,
            sizeof(SIMPLEHV_SET_MIRWM_RANGE_RESPONSE),
            &bytesReturned,
            NULL
        ) != FALSE;
    }

    /**
     * @brief Unhook all
     */
    bool UnhookAll() {
        if (!IsConnected()) return false;

        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            IOCTL_SIMPLEHV_UNHOOK_ALL,
            NULL,
            0,
            NULL,
            0,
            &bytesReturned,
            NULL
        ) != FALSE;
    }
};

} // namespace SimpleHv
