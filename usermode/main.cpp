#include <iostream>
#include <iomanip>
#include <windows.h>
#include <string>
#include "SimpleHvClient.h"

void PrintMenu() {
    std::cout << "========================================" << std::endl;
    std::cout << "          Test Menu                     " << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  1. Ping Hypervisor" << std::endl;
    std::cout << "  2. Install Test Hooks" << std::endl;
    std::cout << "  3. Unhook All" << std::endl;
    std::cout << "  4. Set MiRWM Protect Range (PID + Module)" << std::endl;
    std::cout << "  5. Set MmCopyMemory Hide Region" << std::endl;
    std::cout << "  0. Exit" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Select option: ";
}

void RunPingTest(SimpleHv::Client& client) {
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "         Ping Test                      " << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    std::cout << "[*] Sending PING IOCTL..." << std::endl;

    SIMPLEHV_PING_RESPONSE response = { 0 };
    if (!client.Ping(&response)) {
        std::cout << "[-] PING failed! Error: " << GetLastError() << std::endl;
        std::cout << "    Make sure SimpleHv driver is loaded" << std::endl;
        return;
    }

    std::cout << "[+] PING successful!" << std::endl;
    std::cout << "    Signature    : 0x" << std::hex << std::uppercase
              << response.Signature << std::dec << std::endl;
    std::cout << "    NumProcessors: " << response.NumProcessors << std::endl;
    std::cout << "    IsRunning    : " << (response.IsRunning ? "Yes" : "No") << std::endl;
    std::cout << std::endl;

    if (response.Signature == 0xE79086E5A198) {
        std::cout << "[+] Hypervisor signature matches!" << std::endl;
    } else {
        std::cout << "[-] Unexpected signature!" << std::endl;
    }
    std::cout << std::endl;
}

// 读取一行输入并解析为 64 位无符号数（base=0 自动识别 0x 十六进制 / 十进制）
static bool ReadUInt64(const char* prompt, UINT64& out) {
    std::cout << prompt;
    std::string line;
    if (!std::getline(std::cin, line)) {
        return false;
    }
    if (line.empty()) {
        return false;
    }
    try {
        size_t pos = 0;
        out = std::stoull(line, &pos, 0);
        return true;
    } catch (...) {
        return false;
    }
}

void RunSetMiRwmRangeTest(SimpleHv::Client& client) {
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "   Set MiRWM Protect Range              " << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Region [Base, Base+Size) of target PID" << std::endl;
    std::cout << "  is protected by BOTH:" << std::endl;
    std::cout << "   - Hook 3 MiCopyVirtualMemory: reads " << std::endl;
    std::cout << "     zeroed / writes denied" << std::endl;
    std::cout << "   - Hook 5 MmQueryVirtualMemory: query " << std::endl;
    std::cout << "     returns Protect = PAGE_NOACCESS" << std::endl;
    std::cout << "  Size = 0 disables protection." << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    UINT64 pid  = 0;
    UINT64 base = 0;
    UINT64 size = 0;

    if (!ReadUInt64("[*] Target PID (decimal, e.g. 1234): ", pid)) {
        std::cout << "[-] Invalid PID input" << std::endl;
        std::cout << std::endl;
        return;
    }

    if (pid == 0) {
        std::cout << "[*] PID = 0 -> clearing config / disabling protection (Size forced to 0)" << std::endl;
    } else {
        if (!ReadUInt64("[*] Module BaseAddress (hex, e.g. 0x7FF6A0000000): ", base)) {
            std::cout << "[-] Invalid base address input" << std::endl;
            std::cout << std::endl;
            return;
        }
        if (!ReadUInt64("[*] Protect Size (hex, e.g. 0x1000, 0 = disable): ", size)) {
            std::cout << "[-] Invalid size input" << std::endl;
            std::cout << std::endl;
            return;
        }
    }

    std::cout << std::endl;
    std::cout << "[*] Sending IOCTL_SIMPLEHV_SET_MIRWM_RANGE..." << std::endl;
    std::cout << "    PID  : " << pid << std::endl;
    std::cout << "    Base : 0x" << std::hex << std::uppercase << base << std::dec << std::endl;
    std::cout << "    Size : 0x" << std::hex << std::uppercase << size << std::dec << std::endl;

    SIMPLEHV_SET_MIRWM_RANGE_RESPONSE response = { 0 };
    if (client.SetMiRwmRange((UINT32)pid, base, size, &response)) {
        std::cout << "[*] IOCTL completed" << std::endl;
        std::cout << "    Status      : 0x" << std::hex << std::uppercase
                  << response.Status << std::dec << std::endl;
        std::cout << "    Applied PID : " << response.ProcessId << std::endl;
        std::cout << "    Applied Base: 0x" << std::hex << std::uppercase
                  << response.BaseAddress << std::dec << std::endl;
        std::cout << "    Applied Size: 0x" << std::hex << std::uppercase
                  << response.Size << std::dec << std::endl;

        if (response.Status == 0) {
            if (response.Size == 0) {
                std::cout << "[+] Protection CLEARED (Hook is passthrough now)" << std::endl;
            } else {
                std::cout << "[+] Protect range applied!" << std::endl;
            }
        } else {
            std::cout << "[-] Failed to set protect range" << std::endl;
        }
    } else {
        std::cout << "[-] IOCTL failed! Error: " << GetLastError() << std::endl;
    }

    std::cout << std::endl;
}

void RunSetMmCopyRegionTest(SimpleHv::Client& client) {
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "   Set MmCopyMemory Hide Region         " << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Any MmCopyMemory whose SOURCE range   " << std::endl;
    std::cout << "  overlaps [Start, Start+Size) is       " << std::endl;
    std::cout << "  blocked (returns 0xC0000018).         " << std::endl;
    std::cout << "  PID = 0  -> apply to ANY process.     " << std::endl;
    std::cout << "  Size = 0 -> disable interception.     " << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    UINT64 pid   = 0;
    UINT64 start = 0;
    UINT64 size  = 0;

    if (!ReadUInt64("[*] Target PID (decimal, 0 = any process): ", pid)) {
        std::cout << "[-] Invalid PID input" << std::endl;
        std::cout << std::endl;
        return;
    }

    if (pid == 0) {
        std::cout << "[*] PID = 0 -> only clearing config / disabling interception" << std::endl;
    } else {
        if (!ReadUInt64("[*] Hide Region Start (hex, e.g. 0xFFFF800000000000): ", start)) {
            std::cout << "[-] Invalid start address input" << std::endl;
            std::cout << std::endl;
            return;
        }
        if (!ReadUInt64("[*] Hide Region Size (hex, e.g. 0x1000, 0 = disable): ", size)) {
            std::cout << "[-] Invalid size input" << std::endl;
            std::cout << std::endl;
            return;
        }
    }

    std::cout << std::endl;
    std::cout << "[*] Sending IOCTL_SIMPLEHV_SET_MMCOPY_REGION..." << std::endl;
    std::cout << "    PID   : " << pid << std::endl;
    std::cout << "    Start : 0x" << std::hex << std::uppercase << start << std::dec << std::endl;
    std::cout << "    Size  : 0x" << std::hex << std::uppercase << size << std::dec << std::endl;

    SIMPLEHV_SET_MMCOPY_REGION_RESPONSE response = { 0 };
    if (client.SetMmCopyRegion((UINT32)pid, start, size, &response)) {
        std::cout << "[*] IOCTL completed" << std::endl;
        std::cout << "    Status      : 0x" << std::hex << std::uppercase
                  << response.Status << std::dec << std::endl;
        std::cout << "    Applied PID : " << response.ProcessId << std::endl;
        std::cout << "    Applied Start: 0x" << std::hex << std::uppercase
                  << response.Start << std::dec << std::endl;
        std::cout << "    Applied Size : 0x" << std::hex << std::uppercase
                  << response.Size << std::dec << std::endl;

        if (response.Status == 0) {
            if (response.Size == 0) {
                std::cout << "[+] Hide region CLEARED (Hook is passthrough now)" << std::endl;
            } else {
                std::cout << "[+] Hide region applied!" << std::endl;
            }
        } else {
            std::cout << "[-] Failed to set hide region" << std::endl;
        }
    } else {
        std::cout << "[-] IOCTL failed! Error: " << GetLastError() << std::endl;
    }

    std::cout << std::endl;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "   SimpleHv Usermode Test Client       " << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // Create client
    SimpleHv::Client client;

    std::cout << "[*] Connecting to SimpleHv driver..." << std::endl;
    std::cout << "    Device: \\\\.\\SimpleHv" << std::endl;
    std::cout << std::endl;

    if (!client.Open()) {
        std::cout << "[-] Failed to open SimpleHv device!" << std::endl;
        std::cout << "    Error code: " << GetLastError() << std::endl;
        std::cout << std::endl;
        std::cout << "[*] Make sure to:" << std::endl;
        std::cout << "    1. Load the SimpleHv driver (sc start SimpleHv)" << std::endl;
        std::cout << "    2. Run this program as Administrator" << std::endl;
        std::cout << "    3. Enable virtualization in BIOS" << std::endl;
        std::cout << std::endl;
        system("pause");
        return -1;
    }

    std::cout << "[+] Connected to SimpleHv driver!" << std::endl;
    std::cout << std::endl;

    // 主菜单循环
    while (true) {
        PrintMenu();

        std::string input;
        std::getline(std::cin, input);
         
        if (input.empty()) {
            continue;
        }

        int choice = std::stoi(input);

        switch (choice) {
            case 1:
                RunPingTest(client);
                std::cout << "Press any key to continue..." << std::endl;
                system("pause");
                break;

            case 2:
                std::cout << std::endl;
                std::cout << "========================================" << std::endl;
                std::cout << "  Install Test Hooks                   " << std::endl;
                std::cout << "========================================" << std::endl;
                std::cout << std::endl;
                std::cout << "[*] Sending IOCTL_SIMPLEHV_INSTALL_TEST_HOOKS..." << std::endl;

                {
                    SIMPLEHV_INSTALL_HOOKS_RESPONSE response = { 0 };
                    if (client.InstallTestHooks(&response)) {
                        std::cout << "[*] IOCTL completed" << std::endl;
                        std::cout << "    Status         : 0x" << std::hex << std::uppercase
                                  << response.Status << std::dec << std::endl;
                        std::cout << "    Hooks Installed: " << response.HooksInstalled << std::endl;

                        if (response.Status == 0) {
                            std::cout << "[+] Test hooks installed successfully!" << std::endl;
                        } else {
                            std::cout << "[-] Failed to install hooks" << std::endl;
                        }
                    } else {
                        std::cout << "[-] IOCTL failed! Error: " << GetLastError() << std::endl;
                    }
                }

                std::cout << std::endl;
                std::cout << "Press any key to continue..." << std::endl;
                system("pause");
                break;

            case 3:
                std::cout << std::endl;
                std::cout << "========================================" << std::endl;
                std::cout << "  Unhook All                           " << std::endl;
                std::cout << "========================================" << std::endl;
                std::cout << std::endl;
                std::cout << "[*] Sending IOCTL_SIMPLEHV_UNHOOK_ALL..." << std::endl;

                if (client.UnhookAll()) {
                    std::cout << "[+] All hooks removed successfully!" << std::endl;
                } else {
                    std::cout << "[-] IOCTL failed! Error: " << GetLastError() << std::endl;
                }

                std::cout << std::endl;
                std::cout << "Press any key to continue..." << std::endl;
                system("pause");
                break;

            case 4:
                RunSetMiRwmRangeTest(client);
                std::cout << "Press any key to continue..." << std::endl;
                system("pause");
                break;

            case 5:
                RunSetMmCopyRegionTest(client);
                std::cout << "Press any key to continue..." << std::endl;
                system("pause");
                break;

            case 0:
                std::cout << std::endl;
                std::cout << "[*] Exiting..." << std::endl;
                client.Close();
                return 0;

            default:
                std::cout << "[-] Invalid option!" << std::endl;
                std::cout << std::endl;
                break;
        }

        std::cout << std::endl;
    }

    return 0;
}
