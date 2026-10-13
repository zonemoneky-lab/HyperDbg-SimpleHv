/**
 * @file test.c
 * @brief EPT Hook 测试示例 - 使用 EptHookInstallHiddenInlineHookAuto
 * @details
 *     演示如何使用 EptHookInstallHiddenInlineHookAuto 实现内核函数 Hook
 *     Hook 三个关键函数实现进程保护：
 *     1. ObpReferenceObjectByHandleWithTag - 防止进程被打开
 *     2. NtQuerySystemInformation - 隐藏进程
 *     3. MiReadWriteVirtualMemory - 拦截跨进程内存读写（通过特征码扫描定位）
 */

#include "pch.h"


// ========================================
// 函数类型定义
// ========================================

typedef NTSTATUS(__stdcall* fnObReferenceObjectByHandleWithTag)(
	HANDLE Handle,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	ULONG Tag,
	PVOID* Object,
	POBJECT_HANDLE_INFORMATION HandleInformation,
	__int64 a0
);

typedef NTSTATUS(__stdcall* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

/*
 * MiReadWriteVirtualMemory function type.
 *
 * This is the internal (non-exported) kernel function that both
 * NtReadVirtualMemory and NtWriteVirtualMemory call to perform the
 * actual cross-process memory copy.
 *
 * IDA signature at 14093B450:
 *   48 89 5C 24 ? 48 89 74 24 ? 4C 89 44 24 ? 48 89 54 24 ?
 *   57 41 54 41 55 41 56 41 57 48 83 EC
 *
 * MiReadWriteVirtualMemory 的原型在不同 Windows 版本上不完全一致：
 *   旧版 (Win10 早期)：6 参数，第 6 个是 ACCESS_MASK DesiredAccess，
 *                      PreviousMode 从当前线程读取（ExGetPreviousMode）。
 *   新版 (Win11/近版)：多一个栈上传参（第 7 个）。
 *
 * 因此这里统一声明为 7 参数「超集」，全部按位置原样透传：
 *   - 若真实函数只有 6 个参数，多传的第 7 个会被忽略，无副作用；
 *   - 若真实函数有 7 个参数，则第 7 个被正确转发（避免它读到栈垃圾，
 *     之前的 6 参数声明就是因为没透传第 7 个而返回 STATUS_INVALID_PARAMETER）。
 * 参数名用 Arg6/Arg7，避免语义误解 —— 需要 PreviousMode 时一律用
 * ExGetPreviousMode()，不要依赖 Arg6。
 */
typedef NTSTATUS(NTAPI* pMiReadWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead,
	ULONG_PTR Arg6,
	ULONG_PTR Arg7
);

// ========================================
// 全局变量 - 保存原始函数地址
// ========================================

fnObReferenceObjectByHandleWithTag old_ObpReferenceObjectByHandleWithTag = NULL;
fnNtQuerySystemInformation old_NtQuerySystemInformation = NULL;
pMiReadWriteVirtualMemory old_MiReadWriteVirtualMemory = NULL;
static BOOLEAN g_ObpTestHookInstalled = FALSE;
static BOOLEAN g_NtQueryTestHookInstalled = FALSE;
static BOOLEAN g_MiRWM_TestHookInstalled = FALSE;

/*
 * MiRWM 运行期日志限流：
 * MiReadWriteVirtualMemory 每次跨进程读写都会进入 Hook，若目标进程被频繁
 * 读取会疯狂刷屏。这里只打印前 MIRWM_HOOK_LOG_LIMIT 次命中，之后静默
 * （缓冲区依然会被正常清零，只是不再打日志）。
 */
#define MIRWM_HOOK_LOG_LIMIT 8
static volatile LONG g_MiRWM_HookHitCount = 0;

/*
 * ============================================================
 * MiRWM 保护范围配置（由 usermode 通过 IOCTL 设置）
 * ============================================================
 * 只保护「PID == g_MiRWM_TargetPid 的进程」中、地址落在
 *   [g_MiRWM_ProtectBase, g_MiRWM_ProtectBase + g_MiRWM_ProtectSize)
 * 范围内的内存读取：命中的那一段会被清零，范围之外完全不动。
 *
 * g_MiRWM_ProtectSize == 0 表示未配置 / 关闭保护 —— 此时 Hook 纯透传，
 * 对系统行为零影响（避免误伤）。
 */
static volatile ULONG_PTR g_MiRWM_TargetPid   = 0;
static volatile ULONG_PTR g_MiRWM_ProtectBase = 0;
static volatile ULONG_PTR g_MiRWM_ProtectSize = 0;

VOID ResetTestHooksState(VOID)
{
	g_ObpTestHookInstalled = FALSE;
	g_NtQueryTestHookInstalled = FALSE;
	g_MiRWM_TestHookInstalled = FALSE;
	g_MiRWM_HookHitCount = 0;
	old_ObpReferenceObjectByHandleWithTag = NULL;
	old_NtQuerySystemInformation = NULL;
	old_MiReadWriteVirtualMemory = NULL;
	SimpleHvLog("[Test] Test-hook state reset after UNHOOK_ALL");
}

/**
 * @brief 设置 MiRWM 保护范围（由 usermode 的 IOCTL 调用）
 * @details 只保护 pid 进程中 [BaseAddress, BaseAddress + Size) 的读取。
 *          Size == 0 表示关闭保护（Hook 变回纯透传）。
 *
 * @param ProcessId   目标进程 PID
 * @param BaseAddress 受保护模块基址
 * @param Size        受保护范围大小（字节）
 */
VOID SetMiRWMProtectRange(ULONG ProcessId, ULONG_PTR BaseAddress, ULONG_PTR Size)
{
	/* 先清 size，避免读到「新 base + 旧 size」的中间态 */
	g_MiRWM_ProtectSize = 0;
	g_MiRWM_TargetPid   = ProcessId;
	g_MiRWM_ProtectBase = BaseAddress;
	g_MiRWM_ProtectSize = Size;

	if (Size == 0) {
		SimpleHvLog("[MiRWM] Protect range CLEARED (protection disabled)");
	} else {
		SimpleHvLog("[MiRWM] Protect range SET: pid=%u base=0x%llx size=0x%llx (end=0x%llx)",
		            ProcessId, (UINT64)BaseAddress, (UINT64)Size,
		            (UINT64)(BaseAddress + Size));
	}
}

// ========================================
// 外部声明
// ========================================

char* PsGetProcessImageFileName(PEPROCESS Process);

// ========================================
// 配置：受保护的进程列表
// ========================================

PCWCH protected_process_list[] = {
	L"cheatengine",
	L"HyperCE",
	L"x64dbg",
	L"x32dbg",
	L"ida"
};

// ANSI 版本的保护进程列表（用于 IsProtectedProcessA）
PCSZ protected_process_list_a[] = {
	"cheatengine",
	"HyperCE",
	"x64dbg",
	"x32dbg",
	"ida"
};

// ========================================
// 辅助函数
// ========================================

BOOLEAN StringArrayContainsW(PCWCH str, PCWCH* arr, SIZE_T len)
{
	if (str == NULL || arr == NULL || len == 0)
		return FALSE;

	for (SIZE_T i = 0; i < len; i++) {
		if (wcsstr(str, arr[i]) != NULL)
			return TRUE;
	}
	return FALSE;
}

/**
 * @brief 安全的字符串子串查找（避免越界读取）
 * @details PsGetProcessImageFileName 返回15字节固定长度数组，可能不是 null-terminated
 *          使用 RtlCompareMemory 进行安全的内存比较
 */
BOOLEAN StringArrayContainsA(PCSZ str, PCSZ* arr, SIZE_T len)
{
	if (str == NULL || arr == NULL || len == 0)
		return FALSE;

	// PsGetProcessImageFileName 返回的最大长度是15字节
	SIZE_T str_len = 0;
	for (SIZE_T i = 0; i < 15; i++) {
		if (str[i] == '\0')
			break;
		str_len++;
	}

	// 遍历保护进程列表
	for (SIZE_T i = 0; i < len; i++) {
		if (arr[i] == NULL)
			continue;

		SIZE_T pattern_len = 0;
		while (arr[i][pattern_len] != '\0') {
			pattern_len++;
		}

		if (pattern_len == 0 || pattern_len > str_len)
			continue;

		// 在 str 中查找 arr[i]
		for (SIZE_T j = 0; j <= str_len - pattern_len; j++) {
			// 使用 RtlCompareMemory 进行安全比较
			if (RtlCompareMemory(&str[j], arr[i], pattern_len) == pattern_len) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

BOOLEAN IsProtectedProcessW(PCWCH process)
{
	if (process == NULL)
		return FALSE;

	return StringArrayContainsW(
		process, protected_process_list, sizeof(protected_process_list) / sizeof(PCWCH));
}

/**
 * @brief 检查进程名是否在保护列表中（ANSI 版本）
 * @details 直接比较 ANSI 字符串，不进行内存分配，可在任意 IRQL 下安全调用
 * @param process 进程名（ANSI 字符串，通常来自 PsGetProcessImageFileName）
 * @return TRUE 如果在保护列表中，FALSE 否则
 */
BOOLEAN IsProtectedProcessA(PCSZ process)
{
	if (process == NULL)
		return FALSE;

	// 直接使用 ANSI 字符串比较，不需要转换为 Unicode
	// 这样可以避免内存分配，在任意 IRQL 下都是安全的
	return StringArrayContainsA(
		process, protected_process_list_a, sizeof(protected_process_list_a) / sizeof(PCSZ));
}

/**
 * @brief 在 ObReferenceObjectByHandleWithTag 中查找内部函数 ObpReferenceObjectByHandleWithTag
 * @details 通过查找第一个 CALL 指令来定位内部函数
 */
UINT8* FindObpReferenceObjectByHandleWithTag()
{
	UINT8* pObReferenceObjectByHandleWithTag = (UINT8*)ObReferenceObjectByHandleWithTag;
	SIZE_T offset;

	for (offset = 0; offset < 0x100; offset++) {
		UINT8* curr = pObReferenceObjectByHandleWithTag + offset;

		// 查找 CALL 指令 (0xE8)
		if (*curr == 0xE8) {
			// 计算 CALL 的目标地址
			// CALL rel32: E8 [4字节相对偏移]
			// 目标地址 = 当前地址 + 5 + rel32
			return curr + 5 + *(INT32*)(curr + 1);
		}
	}

	return NULL;
}

// ========================================
// Hook 处理函数
// ========================================

/**
 * @brief ObpReferenceObjectByHandleWithTag Hook 处理函数
 * @details 如果调用者是受保护进程，则降低其访问权限
 */
NTSTATUS ObpReferenceObjectByHandleWithTagHook(
	HANDLE Handle,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	ULONG Tag,
	PVOID* Object,
	POBJECT_HANDLE_INFORMATION HandleInformation,
	__int64 a0)
{
	// 如果 trampoline 还没准备好（Hook 正在安装中），返回错误避免崩溃
	if (old_ObpReferenceObjectByHandleWithTag == NULL) {
		// Hook 还未完全安装，直接返回错误
		// 注意：不能调用原函数（会再次触发 Hook 导致死循环）
		return STATUS_UNSUCCESSFUL;
	}

	char* curr_process_name = PsGetProcessImageFileName(PsGetCurrentProcess());

	// 如果当前进程是受保护进程，降低其权限
	if (IsProtectedProcessA(curr_process_name)) {
		static BOOLEAN first_log = TRUE;
		if (first_log) {
			first_log = FALSE;
			SimpleHvLog("[Hook] Protected process '%s' detected, blocking access", curr_process_name);
		}

		// 将访问权限设为 0，访问模式设为 KernelMode
		return old_ObpReferenceObjectByHandleWithTag(
			Handle, 0, ObjectType, KernelMode, Tag, Object, HandleInformation, a0);
	}

	// 非保护进程，正常调用
	return old_ObpReferenceObjectByHandleWithTag(
		Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation, a0);
}

/**
 * @brief NtQuerySystemInformation Hook 处理函数
 * @details 从进程列表中移除受保护的进程
 */
NTSTATUS NtQuerySystemInformationHook(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	NTSTATUS stat;
	PSYSTEM_PROCESS_INFORMATION prev;
	PSYSTEM_PROCESS_INFORMATION curr;

	// 如果 trampoline 还没准备好（Hook 正在安装中），返回错误
	if (old_NtQuerySystemInformation == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	// 调用原始函数
	stat = old_NtQuerySystemInformation(
		SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	// 如果查询成功且查询的是进程信息
	if (NT_SUCCESS(stat) && SystemInformationClass == SystemProcessInformation) {
		prev = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		curr = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)prev + prev->NextEntryOffset);

		// 遍历进程链表
		while (prev->NextEntryOffset != NULL) {
			PWCH buffer = curr->ImageName.Buffer;

			// 如果是受保护进程，从链表中移除
			if (buffer && IsProtectedProcessW(buffer)) {
				if (curr->NextEntryOffset == 0)
					prev->NextEntryOffset = 0;
				else
					prev->NextEntryOffset += curr->NextEntryOffset;
				curr = prev;
			}

			prev = curr;
			curr = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)curr + curr->NextEntryOffset);
		}
	}

	return stat;
}

// ========================================
// 导出接口
// ========================================

/* Forward declarations (defined later in this file) */
PVOID    ResolveMiReadWriteVirtualMemorySig(VOID);
NTSTATUS NTAPI FakeMiReadWriteVirtualMemory(
	HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
	SIZE_T BufferSize, PSIZE_T NumberOfBytesRead,
	ULONG_PTR Arg6, ULONG_PTR Arg7);

/**
 * @brief 安装所有测试 Hooks
 * @details 安装以下 EPT Hooks：
 *          1. ObpReferenceObjectByHandleWithTag - 保护指定进程不被打开
 *          2. NtQuerySystemInformation - 隐藏指定进程
 *          3. MiReadWriteVirtualMemory - 拦截跨进程内存读写（特征码扫描定位）
 * @return NTSTATUS 成功返回 STATUS_SUCCESS，失败返回相应错误码
 * @note 必须在 VMX non-root mode 下调用（从安装测试 Hook 的 IOCTL 调用）
 */
NTSTATUS InstallTestHooks(VOID)
{
	PVOID pObpReferenceObjectByHandleWithTag;
	PVOID pNtQuerySystemInformation;
	PVOID pMiRWM = NULL;
	BOOLEAN result;
	UINT32 coreId;
	UINT32 processId;
	UNICODE_STRING routineName;
	SIZE_T i;

	SimpleHvLog("========================================");
	SimpleHvLog("[Test] Installing test hooks...");
	SimpleHvLog("========================================");



	// ========================================
	// Hook 1: ObpReferenceObjectByHandleWithTag
	// ========================================
	pObpReferenceObjectByHandleWithTag = FindObpReferenceObjectByHandleWithTag();
	if (!pObpReferenceObjectByHandleWithTag) {
		SimpleHvLogError("[Test] Failed to find ObpReferenceObjectByHandleWithTag");
		return STATUS_UNSUCCESSFUL;
	}

	SimpleHvLog("[Test] ObpReferenceObjectByHandleWithTag: 0x%llx", pObpReferenceObjectByHandleWithTag);

	// 安装 EPT Hook 并获取 trampoline 地址
	//result = EptHookInstallHiddenInlineHookAuto(
	//	pObpReferenceObjectByHandleWithTag,                // 目标函数地址
	//	(PVOID)ObpReferenceObjectByHandleWithTagHook,      // Hook 处理函数
	//	0                                                   // ProcessId (0 = 内核 hook)
	//);

	coreId = KeGetCurrentProcessorNumberEx(NULL);
	processId = HANDLE_TO_UINT32(PsGetCurrentProcessId());
	SimpleHvLog("[Test] Hook 1 request: core=%u pid=%u IRQL=%u target=%p handler=%p pageOffset=0x%Ix",
	            coreId, processId, KeGetCurrentIrql(), pObpReferenceObjectByHandleWithTag,
	            ObpReferenceObjectByHandleWithTagHook,
	            (SIZE_T)pObpReferenceObjectByHandleWithTag & (PAGE_SIZE - 1));
	if (g_ObpTestHookInstalled) {
		SimpleHvLog("[Test] Hook 1 already installed; trampoline=%p", old_ObpReferenceObjectByHandleWithTag);
		goto install_hook_2;
	}
	result = ConfigureEptHook2(coreId,
	                           pObpReferenceObjectByHandleWithTag,
	                           (PVOID)ObpReferenceObjectByHandleWithTagHook,
	                           processId,
	                           (PVOID *)&old_ObpReferenceObjectByHandleWithTag);
	if (result) {
		SimpleHvLog("[Test] Hook 1 installed: ObpReferenceObjectByHandleWithTag");
		SimpleHvLog("[Test] Trampoline address: 0x%llx", old_ObpReferenceObjectByHandleWithTag);

		if (old_ObpReferenceObjectByHandleWithTag == NULL) {
			SimpleHvLogError("[Test] ERROR: Trampoline is NULL!");
			return STATUS_UNSUCCESSFUL;
		}

		if ((UINT64)old_ObpReferenceObjectByHandleWithTag < 0xFFFF000000000000) {
			SimpleHvLogError("[Test] ERROR: Trampoline address looks invalid: 0x%llx", old_ObpReferenceObjectByHandleWithTag);
			return STATUS_UNSUCCESSFUL;
		}
		g_ObpTestHookInstalled = TRUE;
	} else {
		SimpleHvLogError("[Test] Failed to install Hook 1: core=%u pid=%u target=%p handler=%p trampoline=%p",
		                 coreId, processId, pObpReferenceObjectByHandleWithTag,
		                 ObpReferenceObjectByHandleWithTagHook, old_ObpReferenceObjectByHandleWithTag);
		return STATUS_UNSUCCESSFUL;
	}



	install_hook_2:
	// ========================================
	// 3. Hook NtQuerySystemInformation
	// ========================================
	RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
	pNtQuerySystemInformation = MmGetSystemRoutineAddress(&routineName);

	if (!pNtQuerySystemInformation) {
		SimpleHvLogError("[Test] Failed to find NtQuerySystemInformation");
		return STATUS_UNSUCCESSFUL;
	}

	SimpleHvLog("[Test] NtQuerySystemInformation: 0x%llx", pNtQuerySystemInformation);
	coreId = KeGetCurrentProcessorNumberEx(NULL);
	processId = HANDLE_TO_UINT32(PsGetCurrentProcessId());
	SimpleHvLog("[Test] Hook 2 request: core=%u pid=%u IRQL=%u target=%p handler=%p pageOffset=0x%Ix",
	            coreId, processId, KeGetCurrentIrql(), pNtQuerySystemInformation,
	            NtQuerySystemInformationHook,
	            (SIZE_T)pNtQuerySystemInformation & (PAGE_SIZE - 1));

	// 安装 EPT Hook 并获取 trampoline 地址
	//result = EptHookInstallHiddenInlineHookAuto(
	//	pNtQuerySystemInformation,                         // 目标函数地址
	//	(PVOID)NtQuerySystemInformationHook,               // Hook 处理函数
	//	0                                                   // ProcessId (0 = 内核 hook)
	//);
	if (g_NtQueryTestHookInstalled) {
		SimpleHvLog("[Test] Hook 2 already installed; trampoline=%p", old_NtQuerySystemInformation);
		goto hooks_installed;
	}
	result = ConfigureEptHook2(coreId,
	                            pNtQuerySystemInformation,
	                            (PVOID)NtQuerySystemInformationHook,
	                            processId,
	                            (PVOID *)&old_NtQuerySystemInformation);
	if (result) {
		SimpleHvLog("[Test] Hook 2 installed: NtQuerySystemInformation");
		SimpleHvLog("[Test] Trampoline address: 0x%llx", old_NtQuerySystemInformation);

		if (old_NtQuerySystemInformation == NULL) {
			SimpleHvLogError("[Test] ERROR: Hook 2 Trampoline is NULL!");
			return STATUS_UNSUCCESSFUL;
		}
	
		if ((UINT64)old_NtQuerySystemInformation < 0xFFFF000000000000) {
			SimpleHvLogError("[Test] ERROR: Hook 2 Trampoline address looks invalid: 0x%llx", old_NtQuerySystemInformation);
			return STATUS_UNSUCCESSFUL;
		}
		g_NtQueryTestHookInstalled = TRUE;
	} else {
		SimpleHvLogError("[Test] Failed to install Hook 2: core=%u pid=%u target=%p handler=%p trampoline=%p",
		                 coreId, processId, pNtQuerySystemInformation,
		                 NtQuerySystemInformationHook, old_NtQuerySystemInformation);
		return STATUS_UNSUCCESSFUL;
	}



	// ========================================
	// 3b. Hook MiReadWriteVirtualMemory (via signature scan)
	// ========================================
	/*
	 * MiReadWriteVirtualMemory is the internal function that both
	 * NtReadVirtualMemory and NtWriteVirtualMemory call to perform
	 * the actual cross-process memory copy.  Hooking this single
	 * function intercepts ALL cross-process read/write operations,
	 * which is more efficient than hooking the two Nt wrappers.
	 *
	 * We locate it via signature scanning rather than MmGetSystemRoutineAddress
	 * (it is not exported) or the E8-call-from-NtReadVirtualMemory trick
	 * (brittle on different builds).
	 */
	if (g_MiRWM_TestHookInstalled) {
		SimpleHvLog("[Test] Hook 3 already installed; trampoline=%p",
			old_MiReadWriteVirtualMemory);
		goto hooks_installed;
	}

	pMiRWM = ResolveMiReadWriteVirtualMemorySig();
	if (!pMiRWM) {
		SimpleHvLogError("[Test] Failed to find MiReadWriteVirtualMemory via signature scan");
		/* Non-fatal: the other two hooks are still useful */
		goto hooks_installed;
	}

	coreId = KeGetCurrentProcessorNumberEx(NULL);
	processId = HANDLE_TO_UINT32(PsGetCurrentProcessId());
	SimpleHvLog("[Test] Hook 3 request: core=%u pid=%u IRQL=%u target=%p handler=%p pageOffset=0x%Ix",
	            coreId, processId, KeGetCurrentIrql(), pMiRWM,
	            FakeMiReadWriteVirtualMemory,
	            (SIZE_T)pMiRWM & (PAGE_SIZE - 1));

	result = ConfigureEptHook2(coreId,
	                           pMiRWM,
	                           (PVOID)FakeMiReadWriteVirtualMemory,
	                           processId,
	                           (PVOID *)&old_MiReadWriteVirtualMemory);
	if (result) {
		SimpleHvLog("[Test] Hook 3 installed: MiReadWriteVirtualMemory");
		SimpleHvLog("[Test]   target     = 0x%llx", (UINT64)pMiRWM);
		SimpleHvLog("[Test]   trampoline = 0x%llx", (UINT64)old_MiReadWriteVirtualMemory);

		if (old_MiReadWriteVirtualMemory == NULL) {
			SimpleHvLogError("[Test] ERROR: Hook 3 Trampoline is NULL!");
			return STATUS_UNSUCCESSFUL;
		}

		if ((UINT64)old_MiReadWriteVirtualMemory < 0xFFFF000000000000) {
			SimpleHvLogError("[Test] ERROR: Hook 3 Trampoline address looks invalid: 0x%llx",
				old_MiReadWriteVirtualMemory);
			return STATUS_UNSUCCESSFUL;
		}
		g_MiRWM_TestHookInstalled = TRUE;
	} else {
		SimpleHvLogError("[Test] Failed to install Hook 3: core=%u pid=%u target=%p handler=%p trampoline=%p",
		                 coreId, processId, pMiRWM,
		                 FakeMiReadWriteVirtualMemory, old_MiReadWriteVirtualMemory);
		SimpleHvLogWarning("[Test] Hook 3 (MiReadWriteVirtualMemory) NOT installed; "
		                   "hooks 1/2 remain active");
	}

	hooks_installed:
	// ========================================
	// 4. 完成
	// ========================================
	SimpleHvLog("========================================");
	SimpleHvLog("[Test] Hook status:");
	SimpleHvLog("[Test]   [%s] 1. ObpReferenceObjectByHandleWithTag",
	            g_ObpTestHookInstalled ? "OK" : "--");
	SimpleHvLog("[Test]   [%s] 2. NtQuerySystemInformation",
	            g_NtQueryTestHookInstalled ? "OK" : "--");
	SimpleHvLog("[Test]   [%s] 3. MiReadWriteVirtualMemory",
	            g_MiRWM_TestHookInstalled ? "OK" : "--");
	SimpleHvLog("[Test] Protected processes:");
	for (i = 0; i < sizeof(protected_process_list) / sizeof(PCWCH); i++) {
		SimpleHvLog("[Test]   - %ws", protected_process_list[i]);
	}
	SimpleHvLog("[Test] MiRWM runtime hit logs throttled to first %u hits",
	            MIRWM_HOOK_LOG_LIMIT);
	SimpleHvLog("========================================");

	return STATUS_SUCCESS;
}



// ========================================
// Signature Scanning for MiReadWriteVirtualMemory
// ========================================

/*
 * Signature (at 14093B450):
 *   48 89 5C 24 ?  48 89 74 24 ?  4C 89 44 24 ?  48 89 54 24 ?
 *   57 41 54 41 55 41 56 41 57 48 83 EC
 *
 * Disassembled prologue:
 *   mov [rsp+??], rbx    ; 48 89 5C 24 ??
 *   mov [rsp+??], rsi    ; 48 89 74 24 ??
 *   mov [rsp+??], r8     ; 4C 89 44 24 ??
 *   mov [rsp+??], rdx    ; 48 89 54 24 ??
 *   push rdi             ; 57
 *   push r12             ; 41 54
 *   push r13             ; 41 55
 *   push r14             ; 41 56
 *   push r15             ; 41 57
 *   sub rsp, ??          ; 48 83 EC ??
 *
 * 32 bytes total, 4 wildcards (at offsets 4, 9, 14, 19)
 */

static const UINT8 g_MiRWM_Signature[] = {
	0x48, 0x89, 0x5C, 0x24, 0x00, /* ? */  /* 0-4  */
	0x48, 0x89, 0x74, 0x24, 0x00, /* ? */  /* 5-9  */
	0x4C, 0x89, 0x44, 0x24, 0x00, /* ? */  /* 10-14 */
	0x48, 0x89, 0x54, 0x24, 0x00, /* ? */  /* 15-19 */
	0x57, 0x41, 0x54, 0x41, 0x55,           /* 20-24 */
	0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC  /* 25-31 */
};
static const SIZE_T g_MiRWM_SigLen = sizeof(g_MiRWM_Signature);

/* Mask: TRUE = must match, FALSE = wildcard */
static const BOOLEAN g_MiRWM_Mask[] = {
	TRUE, TRUE, TRUE, TRUE, FALSE,            /* xxxx? */
	TRUE, TRUE, TRUE, TRUE, FALSE,            /* xxxx? */
	TRUE, TRUE, TRUE, TRUE, FALSE,            /* xxxx? */
	TRUE, TRUE, TRUE, TRUE, FALSE,            /* xxxx? */
	TRUE, TRUE, TRUE, TRUE, TRUE,             /* xxxxx */
	TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE  /* xxxxxxx */
};

/**
 * @brief Pattern match with wildcard support
 * @param base     Start of memory region to scan
 * @param size     Size of region
 * @param pattern  Byte pattern to match
 * @param mask    Mask array (TRUE = match, FALSE = wildcard)
 * @param patLen  Length of pattern
 * @return Pointer to first match, or NULL
 */
static PVOID MiRWM_FindPattern(
	PUCHAR base, SIZE_T size,
	const UINT8* pattern, const BOOLEAN* mask, SIZE_T patLen)
{
	if (!base || !pattern || !mask || patLen == 0 || size < patLen)
		return NULL;

	SIZE_T endPos = size - patLen;
	for (SIZE_T i = 0; i <= endPos; i++) {
		BOOLEAN match = TRUE;
		for (SIZE_T j = 0; j < patLen; j++) {
			if (mask[j] && base[i + j] != pattern[j]) {
				match = FALSE;
				break;
			}
		}
		if (match)
			return (PVOID)(base + i);
	}
	return NULL;
}

/**
 * @brief Get the ntoskrnl base address via ZwQuerySystemInformation
 * @details The reported ImageSize may be only ~3.5MB on some builds,
 *          which is NOT sufficient as a scan range. Callers should
 *          parse PE section headers instead.
 */
static PVOID MiRWM_GetKernelBase(PULONG pReportedImageSize)
{
	typedef NTSTATUS(NTAPI* fnZwQuerySystemInformation)(
		ULONG, PVOID, ULONG, PULONG);

	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
	fnZwQuerySystemInformation pZwQSI =
		(fnZwQuerySystemInformation)MmGetSystemRoutineAddress(&routineName);
	if (!pZwQSI) {
		SimpleHvLogError("[MiRWM] ZwQuerySystemInformation not found");
		return NULL;
	}
	SimpleHvLog("[MiRWM] ZwQuerySystemInformation @ 0x%llx", (UINT64)pZwQSI);

	ULONG returnLength = 0;
	NTSTATUS status = pZwQSI(SystemModuleInformation, NULL, 0, &returnLength);
	if (status != STATUS_INFO_LENGTH_MISMATCH || returnLength == 0) {
		SimpleHvLogError("[MiRWM] Failed to get module info size: 0x%x", status);
		return NULL;
	}
	SimpleHvLog("[MiRWM] Module info buffer size: %u bytes", returnLength);

	PVOID buffer = PlatformMemAllocateZeroedNonPagedPool(returnLength);
	if (!buffer) {
		SimpleHvLogError("[MiRWM] Failed to allocate %u bytes for module info", returnLength);
		return NULL;
	}

	status = pZwQSI(SystemModuleInformation, buffer, returnLength, &returnLength);
	if (!NT_SUCCESS(status)) {
		SimpleHvLogError("[MiRWM] Failed to query module info: 0x%x", status);
		PlatformMemFreePool(buffer);
		return NULL;
	}

	PSYSTEM_MODULE_INFORMATION modInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
	PVOID kernelBase = NULL;
	ULONG imageSize = 0;

	if (modInfo->Count > 0) {
		kernelBase  = modInfo->Module[0].ImageBase;
		imageSize   = modInfo->Module[0].ImageSize;
		SimpleHvLog("[MiRWM] Module count: %u", modInfo->Count);
		SimpleHvLog("[MiRWM] Module[0] '%s' base=0x%llx reportedImageSize=0x%x (%u bytes)",
			modInfo->Module[0].FullPathName, (UINT64)kernelBase, imageSize, imageSize);
	} else {
		SimpleHvLogError("[MiRWM] Module info count is 0");
	}

	if (pReportedImageSize)
		*pReportedImageSize = imageSize;

	PlatformMemFreePool(buffer);
	return kernelBase;
}

/*
 * PE 结构体的原始偏移（避免引入 ntimage.h，PIMAGE_NT_HEADERS 在
 * 内核编译环境下会带来一堆头文件依赖问题，这里直接按偏移读取）。
 *
 * IMAGE_DOS_HEADER:
 *   0x3C  e_lfanew            -> 指向 IMAGE_NT_HEADERS
 *
 * IMAGE_NT_HEADERS:
 *   0x00  Signature           (== 0x00004550 "PE\0\0")
 *   0x06  FileHeader.NumberOfSections          (USHORT)
 *   0x14  FileHeader.SizeOfOptionalHeader      (USHORT)
 *   0x18  OptionalHeader                       (起始)
 *
 * IMAGE_OPTIONAL_HEADER:
 *   0x10  AddressOfEntryPoint (相对 OptionalHeader)
 *   0x38  SizeOfImage         (相对 OptionalHeader)
 *
 * IMAGE_SECTION_HEADER (每个 40 字节):
 *   0x08  Misc.VirtualSize
 *   0x0C  VirtualAddress
 */
#define PE_DOS_LFANEW_OFFSET        0x3C
#define PE_NT_SIGNATURE             0x00004550
#define PE_NT_NUMSECTIONS_OFFSET    0x06
#define PE_NT_SIZEOFOPT_OFFSET      0x14
#define PE_NT_OPT_OFFSET            0x18
#define PE_OPT_ENTRYPOINT_OFFSET    (PE_NT_OPT_OFFSET + 0x10)  /* 0x28 */
#define PE_OPT_SIZEOFIMAGE_OFFSET   (PE_NT_OPT_OFFSET + 0x38)  /* 0x50 */
#define PE_SECTION_SIZE             40
#define PE_SECTION_VIRTUALSIZE      0x08
#define PE_SECTION_VIRTUALADDR      0x0C

/**
 * @brief 打印一段内存的前 16 字节（HEX），用于人工核对特征码是否命中正确
 * @details 手工拼字符串，避免依赖 ntstrsafe.h 等额外头文件
 */
static VOID MiRWM_LogBytes(const char* tag, PUCHAR addr)
{
	static const char hex[] = "0123456789ABCDEF";
	char buf[3 * 16 + 1];
	int  i;

	for (i = 0; i < 16; i++) {
		UCHAR b = addr[i];
		buf[i * 3 + 0] = hex[(b >> 4) & 0xF];
		buf[i * 3 + 1] = hex[b & 0xF];
		buf[i * 3 + 2] = (i == 15) ? '\0' : ' ';
	}

	SimpleHvLog("[MiRWM] %s @0x%llx: %s", tag, (UINT64)addr, buf);
}

/**
 * @brief Resolve MiReadWriteVirtualMemory via signature scanning
 * @details 直接按原始偏移解析 ntoskrnl 的 PE 头（不使用 PIMAGE_NT_HEADERS /
 *          RtlImageNtHeader / IMAGE_FIRST_SECTION，避免 ntimage.h 依赖），
 *          先扫描 .text 段，若失败再从内核基址扫描较大范围。
 *          之所以要 fallback：某些版本上报的 ImageSize 只有 ~3.5MB，
 *          不足以覆盖整个 .text。
 * @return MiReadWriteVirtualMemory 地址，未找到返回 NULL
 */
PVOID ResolveMiReadWriteVirtualMemorySig(VOID)
{
	ULONG   reportedImageSize = 0;
	PVOID   kernelBase;
	PUCHAR  base;
	PVOID   found = NULL;
	BOOLEAN isText = FALSE;          /* 是否命中 .text 段 */
	BOOLEAN foundInText = FALSE;     /* 结果是否来自 .text 扫描 */

	SimpleHvLog("[MiRWM] ===== Resolving MiReadWriteVirtualMemory (signature scan) =====");

	kernelBase = MiRWM_GetKernelBase(&reportedImageSize);
	if (!kernelBase) {
		SimpleHvLogError("[MiRWM] FAILED: cannot get kernel base address");
		return NULL;
	}

	base = (PUCHAR)kernelBase;

	/* ---- Pass 1: 手动解析 PE，扫描 .text 段 ---- */
	__try
	{
		ULONG e_lfanew = *(PULONG)(base + PE_DOS_LFANEW_OFFSET);
		PUCHAR nt;
		ULONG  ntSig;
		USHORT numSections;
		USHORT sizeOfOptional;
		ULONG  sizeOfImage;
		ULONG  entryPoint;
		PUCHAR sectionBase;
		USHORT i;

		if (e_lfanew == 0 || e_lfanew > 0x1000) {
			SimpleHvLogError("[MiRWM] FAILED: bad e_lfanew = 0x%x", e_lfanew);
			return NULL;
		}

		nt = base + e_lfanew;
		ntSig = *(PULONG)nt;
		if (ntSig != PE_NT_SIGNATURE) {
			SimpleHvLogError("[MiRWM] FAILED: bad NT signature = 0x%08x (expect 0x%08x)",
			                 ntSig, PE_NT_SIGNATURE);
			return NULL;
		}

		numSections    = *(PUSHORT)(nt + PE_NT_NUMSECTIONS_OFFSET);
		sizeOfOptional = *(PUSHORT)(nt + PE_NT_SIZEOFOPT_OFFSET);
		sizeOfImage    = *(PULONG)(nt + PE_OPT_SIZEOFIMAGE_OFFSET);
		entryPoint     = *(PULONG)(nt + PE_OPT_ENTRYPOINT_OFFSET);

		SimpleHvLog("[MiRWM] PE OK: e_lfanew=0x%x sections=%u optHdr=0x%x "
		            "SizeOfImage=0x%x EntryPoint=0x%x (reportedSize=0x%x)",
		            e_lfanew, numSections, sizeOfOptional,
		            sizeOfImage, entryPoint, reportedImageSize);

		sectionBase = nt + PE_NT_OPT_OFFSET + sizeOfOptional;

		/* 遍历段表：打印每段信息，并记录 .text 段 */
		for (i = 0; i < numSections; i++) {
			PUCHAR s = sectionBase + (SIZE_T)i * PE_SECTION_SIZE;
			ULONG  va    = *(PULONG)(s + PE_SECTION_VIRTUALADDR);
			ULONG  vsize = *(PULONG)(s + PE_SECTION_VIRTUALSIZE);

			SimpleHvLog("[MiRWM]   section[%u] '%.8s' VA=0x%x VSize=0x%x",
			            i, s, va, vsize);

			if (!isText &&
			    s[0] == '.' && s[1] == 't' && s[2] == 'e' && s[3] == 'x' && s[4] == 't') {
				isText = TRUE;
				SimpleHvLog("[MiRWM] Scanning .text: start=0x%llx size=0x%x",
				            (UINT64)(base + va), vsize);
				found = MiRWM_FindPattern(base + va, (SIZE_T)vsize,
				                          g_MiRWM_Signature, g_MiRWM_Mask, g_MiRWM_SigLen);
			}
		}

		if (!isText) {
			SimpleHvLogWarning("[MiRWM] No .text section found in PE headers");
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		SimpleHvLogError("[MiRWM] Exception parsing PE headers: 0x%x", GetExceptionCode());
	}

	if (found) {
		foundInText = TRUE;
	} else if (isText) {
		SimpleHvLog("[MiRWM] Not found in .text section, trying extended scan...");
	}

	/* ---- Pass 2: fallback，从内核基址扫描较大范围 ---- */
	if (!found) {
		SIZE_T scanRange = (SIZE_T)reportedImageSize;
		if (scanRange < 0x1000000)
			scanRange = 0x1000000;  /* 至少 16MB，覆盖上报过小的情况 */

		SimpleHvLog("[MiRWM] Extended scan: base=0x%llx range=0x%llx",
		            (UINT64)base, (UINT64)scanRange);

		__try
		{
			found = MiRWM_FindPattern(base, scanRange,
			                          g_MiRWM_Signature, g_MiRWM_Mask, g_MiRWM_SigLen);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			SimpleHvLogError("[MiRWM] Exception during extended scan: 0x%x", GetExceptionCode());
		}
	}

	if (found) {
		SimpleHvLog("[MiRWM] ===== RESOLVED =====");
		SimpleHvLog("[MiRWM]   MiReadWriteVirtualMemory = 0x%llx", (UINT64)found);
		SimpleHvLog("[MiRWM]   offset from kernel base   = +0x%llx",
		            (UINT64)((PUCHAR)found - base));
		SimpleHvLog("[MiRWM]   located via               = %s",
		            foundInText ? ".text section" : "extended scan");
		MiRWM_LogBytes("matched bytes", (PUCHAR)found);
	} else {
		SimpleHvLogError("[MiRWM] ===== FAILED: signature not found in kernel image =====");
	}

	return found;
}

// ========================================
// Hook Handler: MiReadWriteVirtualMemory
// ========================================

/**
 * @brief Hook handler for MiReadWriteVirtualMemory
 * @details 只保护「指定 PID 进程中某模块地址范围」的读取：
 *          1. 先透传调用原函数（7 个参数全部原样传递）；
 *          2. 若配置了保护范围，且目标进程 PID 匹配；
 *          3. 计算本次读取范围与保护范围的交集，只把交集那一段清零。
 *
 *          未配置保护范围（Size==0）时纯透传，对系统零影响。
 *
 * @param ProcessHandle    目标进程句柄
 * @param BaseAddress      目标进程内的读取基址
 * @param Buffer           调用方的输出缓冲区
 * @param BufferSize       请求字节数
 * @param NumberOfBytesRead 可选，返回实际传输字节数
 * @param Arg6             第 6 个参数（各版本含义不同：DesiredAccess 或 PreviousMode），原样透传
 * @param Arg7             第 7 个参数（仅新版存在），必须原样透传
 */
NTSTATUS NTAPI FakeMiReadWriteVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead,
	ULONG_PTR Arg6,
	ULONG_PTR Arg7)
{
	NTSTATUS  result;
	PEPROCESS targetProcess = NULL;
	ULONG_PTR protBase;
	ULONG_PTR protSize;
	ULONG_PTR bytesTransferred;
	BOOLEAN   haveByteCount;
	ULONG     targetPid;
	KPROCESSOR_MODE prevMode;

	/* trampoline 未就绪：不能调原函数（会死循环），直接返回错误 */
	if (old_MiReadWriteVirtualMemory == NULL)
		return STATUS_INVALID_DEVICE_STATE;

	protSize = g_MiRWM_ProtectSize;

	/*
	 * 未配置保护范围 -> 纯透传。
	 * 注意：即使不拦截，也必须把 7 个参数（含第 7 个）原样传给原函数。
	 */
	if (protSize == 0) {
		return old_MiReadWriteVirtualMemory(
			ProcessHandle, BaseAddress, Buffer,
			BufferSize, NumberOfBytesRead, Arg6, Arg7);
	}

	protBase  = g_MiRWM_ProtectBase;
	targetPid = (ULONG)g_MiRWM_TargetPid;

	/*
	 * 取 PreviousMode 一律用 ExGetPreviousMode()（读当前线程），
	 * 不要用 Arg6 —— 它在不同版本上可能是 DesiredAccess。
	 */
	prevMode = ExGetPreviousMode();

	/* ---- 引用目标进程（仅在用户态 + PASSIVE_LEVEL 下安全） ---- */
	if (KeGetCurrentIrql() == PASSIVE_LEVEL && prevMode == UserMode) {
		/*
		 * DesiredAccess = 0：只要求「引用到进程对象」，不做访问权限检查。
		 * 我们只需要拿到 EPROCESS 去取 PID，不关心调用方是否拥有
		 * PROCESS_VM_READ —— 用 0 可以避免「句柄权限不足 -> 引用失败 ->
		 * 漏保护」的情况。
		 */
		NTSTATUS refStatus = ObReferenceObjectByHandle(
			ProcessHandle,
			0,                      /* 不检查访问权限，只引用对象 */
			*PsProcessType,
			UserMode,
			(PVOID*)&targetProcess,
			NULL);
		if (!NT_SUCCESS(refStatus))
			targetProcess = NULL;
	}

	/* ---- 先让原函数完成真正的读写（7 参数全透传！） ---- */
	result = old_MiReadWriteVirtualMemory(
		ProcessHandle, BaseAddress, Buffer,
		BufferSize, NumberOfBytesRead, Arg6, Arg7);

	/* 只处理成功、且目标 PID 匹配的情况 */
	if (!targetProcess ||
	    (result != STATUS_SUCCESS && result != STATUS_PARTIAL_COPY)) {
		if (targetProcess)
			ObDereferenceObject(targetProcess);
		return result;
	}

	/* 目标进程 PID 不匹配 -> 原样返回（ULONG_PTR 中转，避免 HANDLE->ULONG 截断告警） */
	{
		ULONG actualPid = (ULONG)(ULONG_PTR)PsGetProcessId(targetProcess);
		if (actualPid != targetPid) {
			ObDereferenceObject(targetProcess);
			return result;
		}
	}

	/* ---- 计算实际传输字节数 ---- */
	bytesTransferred = 0;
	haveByteCount = FALSE;

	if (NumberOfBytesRead) {
		__try {
			ProbeForRead(NumberOfBytesRead, sizeof(SIZE_T), __alignof(SIZE_T));
			bytesTransferred = *NumberOfBytesRead;
			haveByteCount = (bytesTransferred <= BufferSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			haveByteCount = FALSE;
		}
	} else if (result == STATUS_SUCCESS) {
		bytesTransferred = BufferSize;
		haveByteCount = TRUE;
	}

	/* ---- 只清零「读取范围 ∩ 保护范围」那一段 ---- */
	if (haveByteCount && bytesTransferred != 0 && Buffer) {
		ULONG_PTR readStart = (ULONG_PTR)BaseAddress;

		/* 溢出保护 */
		if (bytesTransferred <= MAXULONG_PTR - readStart &&
		    protSize        <= MAXULONG_PTR - protBase) {

			ULONG_PTR readEnd    = readStart + bytesTransferred;
			ULONG_PTR protEnd    = protBase + protSize;
			ULONG_PTR isectStart = (readStart > protBase) ? readStart : protBase;
			ULONG_PTR isectEnd   = (readEnd   < protEnd)   ? readEnd   : protEnd;

			if (isectStart < isectEnd) {
				ULONG_PTR offset = isectStart - readStart;  /* 在调用方 buffer 中的偏移 */
				ULONG_PTR size   = isectEnd - isectStart;   /* 需要清零的字节数 */

				if (size <= MAXULONG_PTR - (ULONG_PTR)Buffer) {
					PVOID dest = (PVOID)((ULONG_PTR)Buffer + offset);

					__try {
						if (prevMode == UserMode)
							ProbeForWrite(dest, (SIZE_T)size, 1);
						RtlZeroMemory(dest, (SIZE_T)size);
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
						SimpleHvLogError("[MiRWM Hook] clear buffer failed: 0x%x",
						                 GetExceptionCode());
					}

					/* 限流日志：只打印前 MIRWM_HOOK_LOG_LIMIT 次命中 */
					{
						ULONG hit = (ULONG)InterlockedIncrement(&g_MiRWM_HookHitCount);
						if (hit <= MIRWM_HOOK_LOG_LIMIT) {
							SimpleHvLog("[MiRWM Hook] #%u pid=%u read [0x%llx, +0x%llx) "
							            "hits protect range -> zeroed 0x%llx bytes (buf+0x%llx)",
							            hit, targetPid,
							            (UINT64)readStart, (UINT64)bytesTransferred,
							            (UINT64)size, (UINT64)offset);
							if (hit == MIRWM_HOOK_LOG_LIMIT)
								SimpleHvLog("[MiRWM Hook] log limit reached (%u); "
								            "further hits silent", MIRWM_HOOK_LOG_LIMIT);
						}
					}
				}
			}
		}
	}

	ObDereferenceObject(targetProcess);
	return result;
}