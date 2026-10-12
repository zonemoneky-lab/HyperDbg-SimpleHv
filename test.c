/**
 * @file test.c
 * @brief EPT Hook 测试示例 - 使用 EptHookInstallHiddenInlineHookAuto
 * @details
 *     演示如何使用 EptHookInstallHiddenInlineHookAuto 实现内核函数 Hook
 *     Hook 两个关键函数实现进程保护：
 *     1. ObpReferenceObjectByHandleWithTag - 防止进程被打开
 *     2. NtQuerySystemInformation - 隐藏进程
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

// ========================================
// 全局变量 - 保存原始函数地址
// ========================================

fnObReferenceObjectByHandleWithTag old_ObpReferenceObjectByHandleWithTag = NULL;
fnNtQuerySystemInformation old_NtQuerySystemInformation = NULL;
static BOOLEAN g_ObpTestHookInstalled = FALSE;
static BOOLEAN g_NtQueryTestHookInstalled = FALSE;

VOID ResetTestHooksState(VOID)
{
	g_ObpTestHookInstalled = FALSE;
	g_NtQueryTestHookInstalled = FALSE;
	old_ObpReferenceObjectByHandleWithTag = NULL;
	old_NtQuerySystemInformation = NULL;
	SimpleHvLog("[Test] Test-hook state reset after UNHOOK_ALL");
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

/**
 * @brief 安装所有测试 Hooks
 * @details 安装 ObpReferenceObjectByHandleWithTag 和 NtQuerySystemInformation 的 EPT Hooks
 * @return NTSTATUS 成功返回 STATUS_SUCCESS，失败返回相应错误码
 * @note 必须在 VMX non-root mode 下调用（从安装测试 Hook 的 IOCTL 调用）
 */
NTSTATUS InstallTestHooks(VOID)
{
	PVOID pObpReferenceObjectByHandleWithTag;
	PVOID pNtQuerySystemInformation;

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

	hooks_installed:
	// ========================================
	// 4. 完成
	// ========================================
	SimpleHvLog("========================================");
	SimpleHvLog("[Test] All test hooks installed successfully");
	SimpleHvLog("[Test] Protected processes:");
	for (i = 0; i < sizeof(protected_process_list) / sizeof(PCWCH); i++) {
		SimpleHvLog("[Test]   - %ws", protected_process_list[i]);
	}
	SimpleHvLog("========================================");

	return STATUS_SUCCESS;
}
