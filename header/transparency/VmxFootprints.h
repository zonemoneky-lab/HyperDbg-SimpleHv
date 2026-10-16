/**
 * @file VmxFootprint.h
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Hide the debugger from VMX-footrpints of anti-debugging and anti-hypervisor methods (headers)
 * @details
 * @version 0.14
 * @date 2024-08-06
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#pragma once

//
// Some of the functions are exported in the module
//

//////////////////////////////////////////////////
//        TSC offset compensation modes         //
//////////////////////////////////////////////////

/**
 * @brief TSC offset compensation is disabled (default)
 */
#define TSC_OFFSET_COMPENSATION_OFF 0

/**
 * @brief Only compensate the VM-exits that a timing-based anti-hypervisor
 * check actually relies on (CPUID / RDTSC / RDTSCP).
 *
 * @details This is the SAFE default. CPUID is rare in normal workloads, so the
 * accumulated TSC offset - and therefore the TSC drift and the cross-core TSC
 * skew - stays negligible. It is still enough to defeat the classic
 * "RDTSC -> CPUID -> RDTSC" detection, because CPUID unconditionally causes a
 * VM-exit.
 */
#define TSC_OFFSET_COMPENSATION_CPUID_ONLY 1

/**
 * @brief Compensate every single VM-exit (aggressive)
 *
 * @details Hides the exit overhead of every VM-exit cause, including EPT
 * violations coming from our own hooks. This is the strongest setting, but the
 * guest's TSC then drifts behind real time by the fraction of time spent in
 * VMX root mode, and the offset accumulates independently per core, so cores
 * can drift apart from each other (Windows does check cross-core TSC
 * synchronization, and QPC follows the TSC).
 *
 *          Use it only for short-lived anti-analysis scenarios.
 */
#define TSC_OFFSET_COMPENSATION_ALL_EXITS 2
