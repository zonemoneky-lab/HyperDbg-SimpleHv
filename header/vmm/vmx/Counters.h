/**
 * @file Counters.h
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief The headers for functions for emulating counters
 * @details
 * @version 0.1
 * @date 2020-06-14
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#pragma once

//////////////////////////////////////////////////
//			         Functions  				//
//////////////////////////////////////////////////

VOID
CounterEmulateRdtsc(VIRTUAL_MACHINE_STATE * VCpu);

VOID
CounterEmulateRdtscp(VIRTUAL_MACHINE_STATE * VCpu);

VOID
CounterEmulateRdpmc(VIRTUAL_MACHINE_STATE * VCpu);

/**
 * @brief Hide the time spent in VMX root mode from the guest's TSC
 *
 * @details Guest RDTSC/RDTSCP returns (host TSC + VMCS TSC_OFFSET). By
 * subtracting the VMX root-mode duration from TSC_OFFSET after every VM-exit,
 * the guest can no longer observe the VM-exit/VM-entry round trip in its own
 * time-stamp counter.
 *
 * @param VCpu The virtual processor's state
 * @param TscAtVmexit TSC value captured by AsmVmexitHandler on VM-exit entry
 * @return VOID
 */
VOID
CounterApplyTscOffsetCompensation(VIRTUAL_MACHINE_STATE * VCpu, UINT64 TscAtVmexit);

/**
 * @brief Reset the guest's TSC offset back to zero
 * @details MUST be called from VMX root mode (VMCS access)
 *
 * @param VCpu The virtual processor's state
 * @return VOID
 */
VOID
CounterResetTscOffset(VIRTUAL_MACHINE_STATE * VCpu);

/**
 * @brief Read the current guest TSC offset
 * @details MUST be called from VMX root mode (VMCS access)
 *
 * @return UINT64 The current TSC offset (signed, as an unsigned 64-bit value)
 */
UINT64
CounterGetTscOffset(VOID);

VOID
CounterSetPreemptionTimer(UINT32 TimerValue);

VOID
CounterClearPreemptionTimer();
