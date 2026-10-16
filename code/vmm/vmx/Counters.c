/**
 * @file Counters.c
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief The functions for emulating counters
 * @details
 * @version 0.1
 * @date 2020-06-14
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

/**
 * @brief Emulate RDTSC
 *
 * @param VCpu The virtual processor's state
 * @return VOID
 */
VOID
CounterEmulateRdtsc(VIRTUAL_MACHINE_STATE * VCpu)
{
    //
    // I realized that if you log anything here (SimpleHvLog) then
    // the system-halts, currently don't have any idea of how
    // to solve it, in the future we solve it using tsc offsetting
    // or tsc scalling (The reason is because of that fucking patchguard :( )
    //
    // NOTE: the current TSC offset MUST be added here, otherwise the
    // emulated RDTSC would return the raw host TSC and therefore jump
    // forward by the whole accumulated offset (see
    // CounterApplyTscOffsetCompensation).
    //
    UINT64      Tsc       = __rdtsc() + CounterGetTscOffset();
    PGUEST_REGS GuestRegs = VCpu->Regs;

    GuestRegs->rax = 0x00000000ffffffff & Tsc;
    GuestRegs->rdx = 0x00000000ffffffff & (Tsc >> 32);
}

/**
 * @brief Emulate RDTSCP
 *
 * @param VCpu The virtual processor's state
 * @return VOID
 */
VOID
CounterEmulateRdtscp(VIRTUAL_MACHINE_STATE * VCpu)
{
    UINT32      Aux       = 0;
    UINT64      Tsc       = __rdtscp(&Aux) + CounterGetTscOffset();
    PGUEST_REGS GuestRegs = VCpu->Regs;

    GuestRegs->rax = 0x00000000ffffffff & Tsc;
    GuestRegs->rdx = 0x00000000ffffffff & (Tsc >> 32);

    GuestRegs->rcx = 0x00000000ffffffff & Aux;
}

/**
 * @brief Emulate RDPMC
 *
 * @param VCpu The virtual processor's state
 * @return VOID
 */
VOID
CounterEmulateRdpmc(VIRTUAL_MACHINE_STATE * VCpu)
{
    UINT32      EcxReg    = 0;
    PGUEST_REGS GuestRegs = VCpu->Regs;

    EcxReg         = GuestRegs->rcx & 0xffffffff;
    UINT64 Pmc     = __readpmc(EcxReg);
    GuestRegs->rax = 0x00000000ffffffff & Pmc;
    GuestRegs->rdx = 0x00000000ffffffff & (Pmc >> 32);
}

/**
 * @brief Upper bound for a single TSC offset compensation step.
 *
 * @details A single VM-exit should never keep us in VMX root mode for this
 * many TSC cycles. A larger value means the TSC we got from the assembly
 * handler is stale/bogus (e.g. the guest TSC moved backwards, or a nested
 * event re-entered the handler), so we skip the step instead of corrupting
 * the guest's time-line.
 *
 */
#define TSC_OFFSET_MAX_STEP 5000000ULL

/**
 * @brief Hide the time spent in VMX root mode from the guest's TSC
 *
 * @details The guest reads the TSC as (host TSC + VMCS TSC_OFFSET). We
 * therefore subtract the VMX root-mode duration from TSC_OFFSET, which makes
 * the guest's TSC advance exactly as if no VM-exit had happened.
 *
 *          This is what defeats "RDTSC -> CPUID -> RDTSC": CPUID always
 * causes a VM-exit, and without this compensation the guest observes the
 * whole VM-exit/VM-entry round trip inside the TSC delta.
 *
 *          NOTE: the ASM prologue/epilogue of AsmVmexitHandler is NOT
 * covered here (only the C handler part is measured). See the
 * AsmVmexitHandler.asm comments for the entry-TSC capture.
 *
 * @param VCpu The virtual processor's state
 * @param TscAtVmexit TSC value captured by AsmVmexitHandler on VM-exit entry
 * @return VOID
 */
VOID
CounterApplyTscOffsetCompensation(VIRTUAL_MACHINE_STATE * VCpu, UINT64 TscAtVmexit)
{
    UINT64 ExitTsc;
    UINT64 Delta;
    UINT64 CurrentOffset;

    UNREFERENCED_PARAMETER(VCpu);

    ExitTsc = __rdtsc();

    //
    // The guest TSC must never move backwards; if it looks like it would,
    // something is off with the captured value, so do nothing.
    //
    if (ExitTsc <= TscAtVmexit)
    {
        return;
    }

    Delta = ExitTsc - TscAtVmexit;

    if (Delta > TSC_OFFSET_MAX_STEP)
    {
        return;
    }

    VmxVmread64P(VMCS_CTRL_TSC_OFFSET, &CurrentOffset);
    CurrentOffset -= Delta;
    VmxVmwrite64(VMCS_CTRL_TSC_OFFSET, CurrentOffset);

    g_TscOffsetTotalCompensated += Delta;
    g_TscOffsetCompensationCount++;
}

/**
 * @brief Reset the guest's TSC offset back to zero
 * @details MUST be called from VMX root mode (VMCS access)
 *
 * @param VCpu The virtual processor's state
 * @return VOID
 */
VOID
CounterResetTscOffset(VIRTUAL_MACHINE_STATE * VCpu)
{
    UNREFERENCED_PARAMETER(VCpu);

    VmxVmwrite64(VMCS_CTRL_TSC_OFFSET, 0);
}

/**
 * @brief Read the current guest TSC offset
 * @details MUST be called from VMX root mode (VMCS access)
 *
 * @return UINT64 The current TSC offset (signed, as an unsigned 64-bit value)
 */
UINT64
CounterGetTscOffset(VOID)
{
    UINT64 Offset = 0;

    VmxVmread64P(VMCS_CTRL_TSC_OFFSET, &Offset);

    return Offset;
}

/**
 * @brief Set the timer value for preemption timer
 *
 * @param TimerValue Value of the timer
 * @return VOID
 */
VOID
CounterSetPreemptionTimer(UINT32 TimerValue)
{
    //
    // Set the time value
    //
    VmxVmwrite64(VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE, TimerValue);
}

/**
 * @brief Clears the preemption timer
 *
 * @return VOID
 */
VOID
CounterClearPreemptionTimer()
{
    //
    // Set the time value to NULL
    //
    VmxVmwrite64(VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE, NULL64_ZERO);
}
