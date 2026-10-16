/**
 * @file Vmexit.h
 * @author Your Name
 * @brief VM-Exit Handler Definitions
 * @version 0.1
 * @date 2025-10-20
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#pragma once

//
// ========================================
// Function Prototypes
// ========================================
//

// Main VM-Exit handler (called from assembly)
//
// TscAtVmexit is captured by AsmVmexitHandler right at VM-exit entry (after all
// guest general-purpose registers have been saved) and is used to hide the VMX
// root-mode duration from the guest's time-stamp counter.
//
BOOLEAN VmxVmexitHandler(PGUEST_REGS GuestRegs, UINT64 TscAtVmexit);

// Specific exit handlers
VOID VmxHandleCpuid(PVIRTUAL_MACHINE_STATE VmState);
BOOLEAN VmxHandleVmcall(PVIRTUAL_MACHINE_STATE VmState);

// TODO: Add more handlers as needed

