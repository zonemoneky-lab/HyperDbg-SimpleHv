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
