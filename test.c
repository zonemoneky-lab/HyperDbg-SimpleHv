/**
 * @file test.c
 * @brief EPT Hook 测试示例 - 使用 EptHookInstallHiddenInlineHookAuto
 * @details
 *     演示如何使用 EptHookInstallHiddenInlineHookAuto 实现内核函数 Hook
 *     Hook 四个关键函数实现进程保护：
 *     1. ObpReferenceObjectByHandleWithTag - 防止进程被打开
 *     2. NtQuerySystemInformation - 隐藏进程
 *     3. MiCopyVirtualMemory - 拦截跨进程内存读写（从 MmCopyVirtualMemory 反汇编定位）
 *     4. MmCopyMemory - 拦截直接内存拷贝（导出函数，隐藏区域命中即阻断）
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
 * MiCopyVirtualMemory function type.
 *
 * 这是「跨进程内存拷贝」的底层公共函数（未导出）：
 *
 *     NtReadVirtualMemory / NtWriteVirtualMemory
 *         -> MiReadWriteVirtualMemory
 *              -> MiCopyVirtualMemory        <-- 本 Hook 的目标
 *     MmCopyVirtualMemory (导出)
 *         -> MiCopyVirtualMemory
 *
 * 因此只需 Hook MiCopyVirtualMemory 一处，即可覆盖上面所有调用路径，
 * 比分别 Hook NtReadVirtualMemory / NtWriteVirtualMemory 更省、更稳。
 *
 * 原型与 MmCopyVirtualMemory 一致（后者只是它的包装）：
 *   NTSTATUS MiCopyVirtualMemory(
 *       PEPROCESS        SourceProcess,   // 从哪个进程读
 *       PVOID            SourceAddress,   // 源地址（SourceProcess 内）
 *       PEPROCESS        TargetProcess,   // 写到哪个进程
 *       PVOID            TargetAddress,   // 目标地址（调用方的输出缓冲区）
 *       SIZE_T           BufferSize,      // 字节数
 *       KPROCESSOR_MODE  PreviousMode,
 *       PSIZE_T          ReturnSize);     // 实际拷贝字节数
 *
 * 地址定位见 ResolveMiCopyVirtualMemory()：从导出函数 MmCopyVirtualMemory
 * 反汇编出其中的相对 call/jmp 即为 MiCopyVirtualMemory（不再使用 IDA 特征码扫描）。
 */
typedef NTSTATUS(NTAPI* pMiCopyVirtualMemory)(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

/*
 * MmCopyMemory function type.
 *
 * 这是 **导出** 的内核函数（ntoskrnl 导出，可用 MmGetSystemRoutineAddress 定位），
 * 用于在「任意虚拟地址 / 物理地址」与目标缓冲区之间拷贝内存。很多驱动/工具
 * 会用它来读取物理内存或内核内存，因此 hook 它可以拦截「绕过
 * NtReadVirtualMemory 直接读内存」的访问方式。
 *
 * 原型（WDK）：
 *   NTSTATUS MmCopyMemory(
 *       _Out_writes_bytes_(NumberOfBytes) PVOID  TargetAddress,
 *       _In_                             MM_COPY_ADDRESS SourceAddress,
 *       _In_                             SIZE_T   NumberOfBytes,
 *       _In_                             ULONG    Flags,
 *       _Out_                            PSIZE_T  NumberOfBytesTransferred);
 *
 * Flags: MM_COPY_MEMORY_VIRTUAL (0x2) / MM_COPY_MEMORY_PHYSICAL (0x1)
 */
typedef NTSTATUS(NTAPI* pMmCopyMemory)(
	PVOID TargetAddress,
	MM_COPY_ADDRESS SourceAddress,
	SIZE_T NumberOfBytes,
	ULONG Flags,
	PSIZE_T NumberOfBytesTransferred
);

// ========================================
// 全局变量 - 保存原始函数地址
// ========================================

fnObReferenceObjectByHandleWithTag old_ObpReferenceObjectByHandleWithTag = NULL;
fnNtQuerySystemInformation old_NtQuerySystemInformation = NULL;
pMiCopyVirtualMemory old_MiCopyVirtualMemory = NULL;
pMmCopyMemory old_MmCopyMemory = NULL;
static BOOLEAN g_ObpTestHookInstalled = FALSE;
static BOOLEAN g_NtQueryTestHookInstalled = FALSE;
static BOOLEAN g_MiRWM_TestHookInstalled = FALSE;
static BOOLEAN g_MmCopyTestHookInstalled = FALSE;

/*
 * MiCopy 运行期日志限流：
 * MiCopyVirtualMemory 每次跨进程读写都会进入 Hook，若目标进程被频繁
 * 读取/写入会疯狂刷屏。这里只打印前 MIRWM_HOOK_LOG_LIMIT 次命中，之后静默
 * （读取依然会被正常清零 / 写入依然会被拦截，只是不再打日志）。
 */
#define MIRWM_HOOK_LOG_LIMIT 8
static volatile LONG g_MiRWM_HookHitCount = 0;      /* 读取命中（清零）次数 */
static volatile LONG g_MiRWM_WriteBlockCount = 0;   /* 写入命中（拦截）次数 */

/*
 * ============================================================
 * MiCopy 保护范围配置（由 usermode 通过 IOCTL 设置）
 * ============================================================
 * Hook 目标已从 MiReadWriteVirtualMemory 改为其底层公共函数
 * MiCopyVirtualMemory（见 ResolveMiCopyVirtualMemory）。配置语义不变：
 * 只保护「PID == g_MiRWM_TargetPid 的进程」中、地址落在
 *   [g_MiRWM_ProtectBase, g_MiRWM_ProtectBase + g_MiRWM_ProtectSize)
 * 范围内的内存读取：命中的那一段会被清零，范围之外完全不动。
 *
 * g_MiRWM_ProtectSize == 0 表示未配置 / 关闭保护 —— 此时 Hook 纯透传，
 * 对系统行为零影响（避免误伤）。
 *
 * （变量名保留 MiRWM 前缀，是为了与既有的 IOCTL / usermode 接口命名保持一致。）
 */
static volatile ULONG_PTR g_MiRWM_TargetPid   = 0;
static volatile ULONG_PTR g_MiRWM_ProtectBase = 0;
static volatile ULONG_PTR g_MiRWM_ProtectSize = 0;

/*
 * ============================================================
 * MmCopyMemory 隐藏区域配置（由 usermode 通过 IOCTL 设置）
 * ============================================================
 * 当某次 MmCopyMemory 的「源地址范围」与
 *   [g_HideMemRegionStart, g_HideMemRegionStart + g_HideMemRegionSize)
 * 发生重叠时，直接拦截（返回 STATUS_INVALID_ADDRESS，传输字节数置 0）。
 *
 * 注意（用户强调的三点）：
 *   1. 不只是比较起始地址，必须判断「本次读取范围是否跨入目标区域」，
 *      因此用 RangesOverlap() 做区间重叠判断。
 *   2. SourceAddress.VirtualAddress 本身不含 PID —— 想限定「只拦某个进程」，
 *      必须结合请求发生时的地址空间上下文（当前进程）。这里用
 *      g_HideMemTargetPid 做可选限定：== 0 表示「任意进程都拦」。
 *   3. PHYSICAL 与 VIRTUAL 是两种不同语义的源地址，必须分开处理
 *      （物理地址不能直接当虚拟地址比较，需要先 MmGetVirtualForPhysical 映射）。
 *
 * g_HideMemRegionSize == 0 表示未配置 / 关闭 —— Hook 纯透传。
 */
static volatile ULONG_PTR g_HideMemRegionStart = 0;
static volatile ULONG_PTR g_HideMemRegionSize  = 0;
static volatile ULONG_PTR g_HideMemTargetPid   = 0;

#define MMCOPY_HOOK_LOG_LIMIT 8
static volatile LONG g_MmCopy_HookHitCount = 0;    /* 命中拦截次数 */
static volatile LONG g_MmCopy_PhysMissCount = 0;   /* 物理地址无法映射成 VA 的次数 */

/**
 * @brief 判断「读取区间 [addr, addr+len)」是否与「目标区间 [region, region+size)」重叠
 * @details 处理了整数溢出：若加法溢出则视为「可能重叠」，返回 TRUE（保守拦截）。
 *          这是用户强调的第 1 点 —— 必须考虑跨入目标区域，而不只是起始地址。
 */
static BOOLEAN RangesOverlap(
	ULONG_PTR addr, SIZE_T len,
	ULONG_PTR regionStart, ULONG_PTR regionSize)
{
	ULONG_PTR addrEnd;
	ULONG_PTR regionEnd;

	if (regionSize == 0 || len == 0)
		return FALSE;

	/* 溢出保护：任一加法溢出，保守认为重叠 */
	if (addr > MAXULONG_PTR - (ULONG_PTR)len)
		return TRUE;
	if (regionStart > MAXULONG_PTR - regionSize)
		return TRUE;

	addrEnd   = addr + (ULONG_PTR)len;
	regionEnd = regionStart + regionSize;

	/* 半开区间重叠判定：[addr, addrEnd) ∩ [regionStart, regionEnd) != ∅ */
	return (addr < regionEnd) && (regionStart < addrEnd);
}

/**
 * @brief 设置 MmCopyMemory 隐藏区域（由 usermode 的 IOCTL 调用）
 * @param ProcessId 可选：只拦截该 PID（当前进程上下文）的请求；0 = 任意进程
 * @param Start     隐藏区域起始地址
 * @param Size      隐藏区域大小（字节），0 = 关闭
 */
VOID SetMmCopyHideRegion(ULONG ProcessId, ULONG_PTR Start, ULONG_PTR Size)
{
	/* 先清 size，避免读到「新 start + 旧 size」的中间态 */
	g_HideMemRegionSize = 0;
	g_HideMemTargetPid  = ProcessId;
	g_HideMemRegionStart = Start;
	g_HideMemRegionSize  = Size;

	if (Size == 0) {
		SimpleHvLog("[MmCopy] Hide region CLEARED (interception disabled)");
	} else {
		SimpleHvLog("[MmCopy] Hide region SET: pid=%u start=0x%llx size=0x%llx (end=0x%llx)",
		            ProcessId, (UINT64)Start, (UINT64)Size, (UINT64)(Start + Size));
	}
}

VOID ResetTestHooksState(VOID)
{
	g_ObpTestHookInstalled = FALSE;
	g_NtQueryTestHookInstalled = FALSE;
	g_MiRWM_TestHookInstalled = FALSE;
	g_MmCopyTestHookInstalled = FALSE;
	g_MiRWM_HookHitCount = 0;
	g_MiRWM_WriteBlockCount = 0;
	g_MmCopy_HookHitCount = 0;
	g_MmCopy_PhysMissCount = 0;
	old_ObpReferenceObjectByHandleWithTag = NULL;
	old_NtQuerySystemInformation = NULL;
	old_MiCopyVirtualMemory = NULL;
	old_MmCopyMemory = NULL;
	SimpleHvLog("[Test] Test-hook state reset after UNHOOK_ALL");
}

/**
 * @brief 设置保护范围（由 usermode 的 IOCTL 调用）
 * @details 只保护 pid 进程中 [BaseAddress, BaseAddress + Size) 的读取。
 *          命中范围会被清零；Hook 目标是 MiCopyVirtualMemory
 *          （NtRead/NtWriteVirtualMemory 与 MmCopyVirtualMemory 的公共底层）。
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

/*
 * 拦截 MmCopyMemory 时返回的状态码。
 * 用户参考实现里用的是 0xC0000018（STATUS_CONFLICTING_ADDRESSES）；
 * 这里用宏包一层，方便后续想改成 STATUS_INVALID_ADDRESS (0xC0000141)。
 */
#define MMCOPY_BLOCK_STATUS ((NTSTATUS)0xC0000018L)

/**
 * @brief MmCopyMemory Hook 处理函数
 * @details 拦截「源地址范围与隐藏区域重叠」的内存拷贝：
 *          - VIRTUAL (0x2) ：直接取 SourceAddress.VirtualAddress，
 *                            用 RangesOverlap 判断本次读取范围
 *                            是否跨入隐藏区域；
 *          - PHYSICAL (0x1)：物理地址不能直接当虚拟地址比较，
 *                            先用 MmGetVirtualForPhysical 映射成虚拟地址，
 *                            再判断；映射失败则放行，避免误伤。
 *          命中时返回 MMCOPY_BLOCK_STATUS 并把 *NumberOfBytesTransferred 置 0。
 *
 *          进程身份：SourceAddress.VirtualAddress 不含 PID。若 g_HideMemTargetPid
 *          非 0，则只在「当前地址空间上下文（当前进程）== 目标 PID」时拦截。
 */
NTSTATUS NTAPI MmCopyMemoryHook(
	PVOID TargetAddress,
	MM_COPY_ADDRESS SourceAddress,
	SIZE_T NumberOfBytes,
	ULONG Flags,
	PSIZE_T NumberOfBytesTransferred)
{
	ULONG_PTR   regionStart;
	ULONG_PTR   regionSize;
	ULONG_PTR   address   = 0;
	ULONG_PTR   curPid;
	BOOLEAN     blocked   = FALSE;
	const char* kind      = "?";

	/* trampoline 未就绪（Hook 安装中）：不能调原函数（会死循环） */
	if (old_MmCopyMemory == NULL)
		return STATUS_UNSUCCESSFUL;

	regionSize = g_HideMemRegionSize;

	/* 未配置隐藏区域 / 参数无效 -> 纯透传 */
	if (regionSize == 0 || TargetAddress == NULL || NumberOfBytes == 0) {
		return old_MmCopyMemory(
			TargetAddress, SourceAddress, NumberOfBytes, Flags, NumberOfBytesTransferred);
	}

	regionStart = g_HideMemRegionStart;
	curPid      = (ULONG_PTR)PsGetCurrentProcessId();

	if (Flags == MM_COPY_MEMORY_VIRTUAL) {
		kind    = "VIRTUAL";
		address = (ULONG_PTR)SourceAddress.VirtualAddress;

		/* 进程身份限定：0 表示不限进程；非 0 则要求当前进程匹配 */
		if (g_HideMemTargetPid == 0 || curPid == g_HideMemTargetPid) {
			blocked = RangesOverlap(
				address, NumberOfBytes, regionStart, regionSize);
		}
	} else if (Flags == MM_COPY_MEMORY_PHYSICAL) {
		PVOID va;

		kind = "PHYSICAL";
		/* 物理地址 -> 虚拟地址映射；映射不到就放行，但记录一下（便于发现绕过尝试） */
		va = MmGetVirtualForPhysical(SourceAddress.PhysicalAddress);
		if (va != NULL) {
			address = (ULONG_PTR)va;
			if (g_HideMemTargetPid == 0 || curPid == g_HideMemTargetPid) {
				blocked = RangesOverlap(
					address, NumberOfBytes, regionStart, regionSize);
			}
		} else {
			ULONG miss = (ULONG)InterlockedIncrement(&g_MmCopy_PhysMissCount);
			if (miss <= MMCOPY_HOOK_LOG_LIMIT) {
				SimpleHvLog("[MmCopy Hook] PHYSICAL src=0x%llx maps to no VA "
				            "(MmGetVirtualForPhysical=NULL) -> passthrough",
				            (UINT64)SourceAddress.PhysicalAddress.QuadPart);
			}
		}
	}

	if (blocked) {
		if (NumberOfBytesTransferred) {
			__try {
				/* 可能是内核指针，不能 Probe；直接写在 __try 里兜底异常 */
				*NumberOfBytesTransferred = 0;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				/* 忽略：即使写不进去也不影响拦截结果 */
			}
		}

		/* 限流日志：只打印前 MMCOPY_HOOK_LOG_LIMIT 次命中 */
		{
			ULONG hit = (ULONG)InterlockedIncrement(&g_MmCopy_HookHitCount);
			if (hit <= MMCOPY_HOOK_LOG_LIMIT) {
				SimpleHvLog("[MmCopy Hook] #%u BLOCKED %s src=0x%llx len=0x%llx "
				            "pid=%llu hits [0x%llx, +0x%llx)",
				            hit, kind, (UINT64)address, (UINT64)NumberOfBytes,
				            (UINT64)curPid,
				            (UINT64)regionStart, (UINT64)regionSize);
				if (hit == MMCOPY_HOOK_LOG_LIMIT)
					SimpleHvLog("[MmCopy Hook] log limit reached (%u); further hits silent",
					            MMCOPY_HOOK_LOG_LIMIT);
			}
		}

		return MMCOPY_BLOCK_STATUS;
	}

	return old_MmCopyMemory(
		TargetAddress, SourceAddress, NumberOfBytes, Flags, NumberOfBytesTransferred);
}

// ========================================
// 导出接口
// ========================================

/* Forward declarations (defined later in this file) */
PVOID    ResolveMiCopyVirtualMemory(VOID);
NTSTATUS NTAPI FakeMiCopyVirtualMemory(
	PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess,
	PVOID TargetAddress, SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

/**
 * @brief 安装所有测试 Hooks
 * @details 安装以下 EPT Hooks：
 *          1. ObpReferenceObjectByHandleWithTag - 保护指定进程不被打开
 *          2. NtQuerySystemInformation - 隐藏指定进程
 *          3. MiCopyVirtualMemory - 拦截跨进程内存读写（从 MmCopyVirtualMemory 反汇编定位）
 *          4. MmCopyMemory - 拦截直接内存拷贝（导出函数，隐藏区域命中即阻断）
 * @return NTSTATUS 成功返回 STATUS_SUCCESS，失败返回相应错误码
 * @note 必须在 VMX non-root mode 下调用（从安装测试 Hook 的 IOCTL 调用）
 */
NTSTATUS InstallTestHooks(VOID)
{
	PVOID pObpReferenceObjectByHandleWithTag;
	PVOID pNtQuerySystemInformation;
	PVOID pMiCopy = NULL;
	PVOID pMmCopyMemory = NULL;
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
		goto install_hook_3;
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
	// 3b. Hook MiCopyVirtualMemory
	// ========================================
	install_hook_3:
	/*
	 * MiCopyVirtualMemory 是跨进程内存拷贝的底层公共函数：
	 *   NtRead/NtWriteVirtualMemory -> MiReadWriteVirtualMemory -> MiCopyVirtualMemory
	 *   MmCopyVirtualMemory (导出)                              -> MiCopyVirtualMemory
	 * Hook 它一处即可覆盖以上全部路径。
	 *
	 * 定位方式：MmCopyVirtualMemory 是导出的包装函数，反汇编其入口处的
	 * 相对 call/jmp 即可得到 MiCopyVirtualMemory —— 不再依赖 IDA 特征码扫描。
	 */
	if (g_MiRWM_TestHookInstalled) {
		SimpleHvLog("[Test] Hook 3 already installed; trampoline=%p",
			old_MiCopyVirtualMemory);
		goto install_hook_4;
	}

	pMiCopy = ResolveMiCopyVirtualMemory();
	if (!pMiCopy) {
		SimpleHvLogError("[Test] Failed to resolve MiCopyVirtualMemory from MmCopyVirtualMemory");
		/* Non-fatal: the other hooks are still useful */
		goto install_hook_4;
	}

	coreId = KeGetCurrentProcessorNumberEx(NULL);
	processId = HANDLE_TO_UINT32(PsGetCurrentProcessId());
	SimpleHvLog("[Test] Hook 3 request: core=%u pid=%u IRQL=%u target=%p handler=%p pageOffset=0x%Ix",
	            coreId, processId, KeGetCurrentIrql(), pMiCopy,
	            FakeMiCopyVirtualMemory,
	            (SIZE_T)pMiCopy & (PAGE_SIZE - 1));

	result = ConfigureEptHook2(coreId,
	                           pMiCopy,
	                           (PVOID)FakeMiCopyVirtualMemory,
	                           processId,
	                           (PVOID *)&old_MiCopyVirtualMemory);
	if (result) {
		SimpleHvLog("[Test] Hook 3 installed: MiCopyVirtualMemory");
		SimpleHvLog("[Test]   target     = 0x%llx", (UINT64)pMiCopy);
		SimpleHvLog("[Test]   trampoline = 0x%llx", (UINT64)old_MiCopyVirtualMemory);

		if (old_MiCopyVirtualMemory == NULL) {
			SimpleHvLogError("[Test] ERROR: Hook 3 Trampoline is NULL!");
			return STATUS_UNSUCCESSFUL;
		}

		if ((UINT64)old_MiCopyVirtualMemory < 0xFFFF000000000000) {
			SimpleHvLogError("[Test] ERROR: Hook 3 Trampoline address looks invalid: 0x%llx",
				old_MiCopyVirtualMemory);
			return STATUS_UNSUCCESSFUL;
		}
		g_MiRWM_TestHookInstalled = TRUE;
	} else {
		SimpleHvLogError("[Test] Failed to install Hook 3: core=%u pid=%u target=%p handler=%p trampoline=%p",
		                 coreId, processId, pMiCopy,
		                 FakeMiCopyVirtualMemory, old_MiCopyVirtualMemory);
		SimpleHvLogWarning("[Test] Hook 3 (MiCopyVirtualMemory) NOT installed; "
		                   "other hooks remain active");
	}

	install_hook_4:
	// ========================================
	// 3c. Hook MmCopyMemory (exported kernel routine)
	// ========================================
	/*
	 * MmCopyMemory 是 ntoskrnl 导出的内存拷贝例程，可直接用
	 * MmGetSystemRoutineAddress 定位。很多驱动/工具用它读物理内存或
	 * 内核内存来绕过 NtReadVirtualMemory，hook 它可以补齐这一类访问。
	 */
	if (g_MmCopyTestHookInstalled) {
		SimpleHvLog("[Test] Hook 4 already installed; trampoline=%p", old_MmCopyMemory);
		goto hooks_installed;
	}

	RtlInitUnicodeString(&routineName, L"MmCopyMemory");
	pMmCopyMemory = MmGetSystemRoutineAddress(&routineName);
	if (!pMmCopyMemory) {
		SimpleHvLogError("[Test] Failed to find MmCopyMemory (exported)");
		goto hooks_installed;
	}

	SimpleHvLog("[Test] MmCopyMemory: 0x%llx", pMmCopyMemory);
	coreId = KeGetCurrentProcessorNumberEx(NULL);
	processId = HANDLE_TO_UINT32(PsGetCurrentProcessId());
	SimpleHvLog("[Test] Hook 4 request: core=%u pid=%u IRQL=%u target=%p handler=%p pageOffset=0x%Ix",
	            coreId, processId, KeGetCurrentIrql(), pMmCopyMemory,
	            MmCopyMemoryHook,
	            (SIZE_T)pMmCopyMemory & (PAGE_SIZE - 1));

	result = ConfigureEptHook2(coreId,
	                           pMmCopyMemory,
	                           (PVOID)MmCopyMemoryHook,
	                           processId,
	                           (PVOID *)&old_MmCopyMemory);
	if (result) {
		SimpleHvLog("[Test] Hook 4 installed: MmCopyMemory");
		SimpleHvLog("[Test]   target     = 0x%llx", (UINT64)pMmCopyMemory);
		SimpleHvLog("[Test]   trampoline = 0x%llx", (UINT64)old_MmCopyMemory);

		if (old_MmCopyMemory == NULL) {
			SimpleHvLogError("[Test] ERROR: Hook 4 Trampoline is NULL!");
			return STATUS_UNSUCCESSFUL;
		}

		if ((UINT64)old_MmCopyMemory < 0xFFFF000000000000) {
			SimpleHvLogError("[Test] ERROR: Hook 4 Trampoline address looks invalid: 0x%llx",
				old_MmCopyMemory);
			return STATUS_UNSUCCESSFUL;
		}
		g_MmCopyTestHookInstalled = TRUE;
	} else {
		SimpleHvLogError("[Test] Failed to install Hook 4: core=%u pid=%u target=%p handler=%p trampoline=%p",
		                 coreId, processId, pMmCopyMemory,
		                 MmCopyMemoryHook, old_MmCopyMemory);
		SimpleHvLogWarning("[Test] Hook 4 (MmCopyMemory) NOT installed; other hooks remain active");
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
	SimpleHvLog("[Test]   [%s] 3. MiCopyVirtualMemory",
	            g_MiRWM_TestHookInstalled ? "OK" : "--");
	SimpleHvLog("[Test]   [%s] 4. MmCopyMemory",
	            g_MmCopyTestHookInstalled ? "OK" : "--");
	SimpleHvLog("[Test] Protected processes:");
	for (i = 0; i < sizeof(protected_process_list) / sizeof(PCWCH); i++) {
		SimpleHvLog("[Test]   - %ws", protected_process_list[i]);
	}
	SimpleHvLog("[Test] MiRWM runtime hit logs throttled to first %u hits",
	            MIRWM_HOOK_LOG_LIMIT);
	SimpleHvLog("[Test] MmCopy runtime hit logs throttled to first %u hits",
	            MMCOPY_HOOK_LOG_LIMIT);
	SimpleHvLog("========================================");

	return STATUS_SUCCESS;
}



// ========================================
// Resolving MiCopyVirtualMemory (via exported MmCopyVirtualMemory)
// ========================================

/*
 * MiCopyVirtualMemory 未导出，但 MmCopyVirtualMemory 是它的导出包装：
 *     MmCopyVirtualMemory 内部必然有一条相对 call/jmp 跳进 MiCopyVirtualMemory。
 * 因此用 Zydis 反汇编 MmCopyVirtualMemory 入口处的若干条指令，取其中第一条
 * 「目标落在内核空间的相对 call/jmp」即为 MiCopyVirtualMemory。
 *
 * 相比 IDA 特征码扫描：不依赖具体版本的字节序列，跨版本更稳，也不用手工维护通配符。
 */

#define MICOPY_DISASM_SCAN_LEN 0x60   /* 反汇编 MmCopyVirtualMemory 入口前 0x60 字节 */

/**
 * @brief 反汇编 functionAddr 起始的 scanLen 字节，返回第一条指向内核空间的相对 call/jmp 目标
 * @param functionAddr 函数入口
 * @param scanLen      扫描字节数
 * @return 目标地址；未找到返回 NULL
 */
static PVOID MiCopy_FindRelativeCallTarget(PVOID functionAddr, SIZE_T scanLen)
{
	ZydisDecoder            decoder;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
	SIZE_T                  offset = 0;

	if (functionAddr == NULL || scanLen == 0)
		return NULL;

	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder,
	                                   ZYDIS_MACHINE_MODE_LONG_64,
	                                   ZYDIS_STACK_WIDTH_64))) {
		SimpleHvLogError("[MiCopy] ZydisDecoderInit failed");
		return NULL;
	}

	while (offset < scanLen) {
		ZyanStatus status = ZydisDecoderDecodeFull(
			&decoder,
			(PVOID)((PUCHAR)functionAddr + offset),
			scanLen - offset,
			&instruction,
			operands);

		if (!ZYAN_SUCCESS(status)) {
			/* 解码失败：按字节滑动，跳过可疑字节后继续 */
			offset++;
			continue;
		}

		/* 只看相对寻址的 call / jmp（x64 下即 E8 / E9） */
		if ((instruction.mnemonic == ZYDIS_MNEMONIC_CALL ||
		     instruction.mnemonic == ZYDIS_MNEMONIC_JMP) &&
		    instruction.operand_count >= 1 &&
		    operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
		    operands[0].imm.is_relative) {

			ULONG_PTR instrAddr = (ULONG_PTR)functionAddr + offset;
			ULONG_PTR target    = instrAddr + instruction.length +
			                      (ULONG_PTR)(INT64)operands[0].imm.value.s;

			SimpleHvLog("[MiCopy]   +0x%Ix %s -> 0x%llx",
			            offset,
			            (instruction.mnemonic == ZYDIS_MNEMONIC_CALL) ? "call" : "jmp",
			            (UINT64)target);

			/* 目标必须在内核空间，且不能是自身 */
			if (target >= 0xFFFF000000000000ULL &&
			    target != (ULONG_PTR)functionAddr) {
				return (PVOID)target;
			}
		}

		offset += instruction.length;
	}

	return NULL;
}

/**
 * @brief 解析 MiCopyVirtualMemory 地址（从导出函数 MmCopyVirtualMemory 反汇编 call 得到）
 * @details 不再使用 IDA 特征码扫描。
 * @return MiCopyVirtualMemory 地址；失败返回 NULL
 */
PVOID ResolveMiCopyVirtualMemory(VOID)
{
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"MmCopyVirtualMemory");
	PVOID          pMmCopyVirtualMemory;
	PVOID          pMiCopyVirtualMemory;

	SimpleHvLog("[MiCopy] ===== Resolving MiCopyVirtualMemory (from MmCopyVirtualMemory) =====");

	pMmCopyVirtualMemory = MmGetSystemRoutineAddress(&routineName);
	if (!pMmCopyVirtualMemory) {
		SimpleHvLogError("[MiCopy] FAILED: MmCopyVirtualMemory is not exported");
		return NULL;
	}
	SimpleHvLog("[MiCopy] MmCopyVirtualMemory (exported) = 0x%llx",
	            (UINT64)pMmCopyVirtualMemory);

	/* 反汇编入口前若干字节，打印每条相对 call/jmp，取第一条落在内核空间的 */
	pMiCopyVirtualMemory = MiCopy_FindRelativeCallTarget(
		pMmCopyVirtualMemory, MICOPY_DISASM_SCAN_LEN);

	if (!pMiCopyVirtualMemory) {
		SimpleHvLogError("[MiCopy] FAILED: no relative call/jmp to kernel space found "
		                 "in the first 0x%x bytes of MmCopyVirtualMemory",
		                 MICOPY_DISASM_SCAN_LEN);
		return NULL;
	}

	SimpleHvLog("[MiCopy] ===== RESOLVED =====");
	SimpleHvLog("[MiCopy]   MiCopyVirtualMemory              = 0x%llx",
	            (UINT64)pMiCopyVirtualMemory);
	SimpleHvLog("[MiCopy]   offset from MmCopyVirtualMemory  = +0x%llx",
	            (UINT64)((PUCHAR)pMiCopyVirtualMemory - (PUCHAR)pMmCopyVirtualMemory));
	return pMiCopyVirtualMemory;
}

// ========================================
// Hook Handler: MiCopyVirtualMemory
// ========================================

/*
 * 写入命中保护范围时返回的状态码（直接拦截、不执行拷贝）。
 * 用宏包一层，方便改成 STATUS_INVALID_ADDRESS (0xC0000141) 等其它码。
 */
#define MICOPY_WRITE_BLOCK_STATUS ((NTSTATUS)0xC0000022L)   /* STATUS_ACCESS_DENIED */

/**
 * @brief Hook handler for MiCopyVirtualMemory
 * @details 保护「指定 PID 进程中某模块地址范围」的内存，读写两个方向分别处理：
 *
 *          - 写入方向（写入方是别人，且 TargetProcess == 被保护进程、
 *            TargetAddress 命中范围）：
 *            **在调用原函数之前直接拦截**，返回 MICOPY_WRITE_BLOCK_STATUS，
 *            并把 *ReturnSize 置 0 —— 写入一旦放行就无法收回，必须提前拒绝。
 *
 *          - 读取方向（读取方是别人，且 SourceProcess == 被保护进程、
 *            SourceAddress 命中范围）：
 *            先透传调用原函数完成拷贝，再把「读取范围 ∩ 保护范围」那一段
 *            在调用方目标缓冲区里清零。
 *
 *          MiCopyVirtualMemory 是通用拷贝，方向由「目标进程」决定：
 *            读：Source = 被读进程，Target = 调用方
 *            写：Source = 调用方，  Target = 被写进程
 *
 *          「自己人」放行：SourceProcess == TargetProcess（被保护进程读写自己的
 *          内存）时不拦截、不清零 —— 否则会破坏它自身的数据。
 *
 *          未配置保护范围（Size==0）时纯透传，对系统零影响。
 *
 * @param SourceProcess  源进程（从它读 / 写入时是调用方）
 * @param SourceAddress  源地址
 * @param TargetProcess  目标进程（写到它 / 读取时是调用方）
 * @param TargetAddress  目标地址
 * @param BufferSize     请求字节数
 * @param PreviousMode   KernelMode / UserMode
 * @param ReturnSize     可选，返回实际拷贝字节数
 */
NTSTATUS NTAPI FakeMiCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize)
{
	NTSTATUS  result;
	ULONG_PTR protBase;
	ULONG_PTR protSize;
	ULONG_PTR bytesTransferred;
	BOOLEAN   haveByteCount;
	ULONG     targetPid;

	/* trampoline 未就绪：不能调原函数（会死循环），直接返回错误 */
	if (old_MiCopyVirtualMemory == NULL)
		return STATUS_INVALID_DEVICE_STATE;

	protSize = g_MiRWM_ProtectSize;

	/*
	 * 未配置保护范围 -> 纯透传。
	 * 注意：即使不拦截，也必须把 7 个参数原样传给原函数。
	 */
	if (protSize == 0) {
		return old_MiCopyVirtualMemory(
			SourceProcess, SourceAddress, TargetProcess,
			TargetAddress, BufferSize, PreviousMode, ReturnSize);
	}

	protBase  = g_MiRWM_ProtectBase;
	targetPid = (ULONG)g_MiRWM_TargetPid;

	/*
	 * ============================================================
	 * 写入方向：直接拦截（必须在调用原函数之前！）
	 * ============================================================
	 * 拦截条件：写入方是「别人」（SourceProcess != TargetProcess），
	 *           目标进程 == 被保护进程，且目标地址范围落在保护范围。
	 *
	 * 「自己写自己」（SourceProcess == TargetProcess == 被保护进程）要放行 ——
	 * 那是被保护进程操作自己的内存，属于正常行为，拦了会破坏它自身。
	 *
	 * 写入一旦放行就无法收回（内存已被改写），所以这里提前返回错误、不执行拷贝。
	 */
	if (TargetProcess != NULL && TargetAddress != NULL &&
	    SourceProcess != TargetProcess &&                       /* 自己写自己 -> 放行 */
	    (ULONG)(ULONG_PTR)PsGetProcessId(TargetProcess) == targetPid &&
	    RangesOverlap((ULONG_PTR)TargetAddress, BufferSize, protBase, protSize)) {

		if (ReturnSize) {
			__try {
				/* ReturnSize 可能是内核指针，不能 Probe；直接写在 __try 里兜底 */
				*ReturnSize = 0;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				/* 忽略：ReturnSize 不可写时也不影响拦截结果 */
			}
		}

		/* 限流日志：只打印前 MIRWM_HOOK_LOG_LIMIT 次写入拦截 */
		{
			ULONG hit = (ULONG)InterlockedIncrement(&g_MiRWM_WriteBlockCount);
			if (hit <= MIRWM_HOOK_LOG_LIMIT) {
				SimpleHvLog("[MiCopy Hook] #%u BLOCKED WRITE pid=%u dst=[0x%llx, +0x%llx) "
				            "hits protect range [0x%llx, +0x%llx) -> write denied",
				            hit, targetPid,
				            (UINT64)(ULONG_PTR)TargetAddress, (UINT64)BufferSize,
				            (UINT64)protBase, (UINT64)protSize);
				if (hit == MIRWM_HOOK_LOG_LIMIT)
					SimpleHvLog("[MiCopy Hook] write-block log limit reached (%u); "
					            "further hits silent", MIRWM_HOOK_LOG_LIMIT);
			}
		}

		return MICOPY_WRITE_BLOCK_STATUS;   /* 直接拦截，不调用原函数 */
	}

	/* ---- 读取方向：先让原函数完成真正的拷贝（7 参数全透传！） ---- */
	result = old_MiCopyVirtualMemory(
		SourceProcess, SourceAddress, TargetProcess,
		TargetAddress, BufferSize, PreviousMode, ReturnSize);

	/* 只处理成功、且参数有效的情况 */
	if (!SourceProcess || !TargetAddress ||
	    (result != STATUS_SUCCESS && result != STATUS_PARTIAL_COPY)) {
		return result;
	}

	/*
	 * 进程身份（读取方向）：
	 *   - 「源进程」必须是被保护进程（即有人在从被保护进程读）；
	 *   - 且源/目标是不同进程 —— 被保护进程读自己的内存属于「自己人」，放行，
	 *     否则会把它的目标缓冲区清零，破坏它自己的数据。
	 * （ULONG_PTR 中转，避免 HANDLE -> ULONG 截断告警。）
	 */
	if ((ULONG)(ULONG_PTR)PsGetProcessId(SourceProcess) != targetPid ||
	    SourceProcess == TargetProcess)
		return result;

	/*
	 * ---- 计算实际拷贝字节数 ----
	 * 关键：ReturnSize 可能是 **内核指针**！
	 *   NtReadVirtualMemory -> MiReadWriteVirtualMemory 调 MiCopyVirtualMemory 时，
	 *   传进来的 ReturnSize 是它自己的局部变量地址（内核栈），而此时 PreviousMode
	 *   仍是 UserMode。若对它做 ProbeForRead，内核地址会直接抛异常，被 __except
	 *   吞掉后误判成「拿不到字节数」而漏掉清零 —— 这正是「读不到拦截」的原因。
	 * 因此：不做 Probe，直接在 __try 里读；读不到就退回默认值（按请求字节数算）。
	 */
	bytesTransferred = BufferSize;
	haveByteCount = (result == STATUS_SUCCESS);

	if (ReturnSize) {
		__try {
			SIZE_T n = *ReturnSize;
			if (n <= BufferSize) {
				bytesTransferred = n;
				haveByteCount = TRUE;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			/* 读不到就沿用上面的默认值 */
		}
	}

	/* ---- 计算交集并清零；无论是否命中都打一条限流诊断日志 ---- */
	/*
	 * 走到这里说明：有人在从「被保护进程」读。
	 * 诊断价值：如果连 "READ ... reached hook" 都看不到，就说明该读取路径
	 *           根本没有经过 MiCopyVirtualMemory（而不是我们的条件写错了）。
	 *
	 * 目标缓冲区必须位于**当前地址空间**才敢直接写（TargetAddress 是 TargetProcess
	 * 里的地址）。典型读取场景 TargetProcess == 调用方 == 当前进程，成立。
	 */
	{
		ULONG_PTR readStart  = (ULONG_PTR)SourceAddress;
		ULONG_PTR zeroOffset = 0;
		ULONG_PTR zeroSize   = 0;
		BOOLEAN   dstInCur   = (TargetProcess == PsGetCurrentProcess());

		if (haveByteCount && bytesTransferred != 0 && dstInCur &&
		    bytesTransferred <= MAXULONG_PTR - readStart &&
		    protSize        <= MAXULONG_PTR - protBase) {

			ULONG_PTR readEnd    = readStart + bytesTransferred;
			ULONG_PTR protEnd    = protBase + protSize;
			ULONG_PTR isectStart = (readStart > protBase) ? readStart : protBase;
			ULONG_PTR isectEnd   = (readEnd   < protEnd)   ? readEnd   : protEnd;

			if (isectStart < isectEnd) {
				zeroOffset = isectStart - readStart;  /* 在目标缓冲区中的偏移 */
				zeroSize   = isectEnd - isectStart;   /* 需要清零的字节数 */

				if (zeroSize <= MAXULONG_PTR - (ULONG_PTR)TargetAddress) {
					PVOID dest = (PVOID)((ULONG_PTR)TargetAddress + zeroOffset);

					__try {
						/* 直接写：地址已被原函数验证过，__try 兜底异常即可 */
						RtlZeroMemory(dest, (SIZE_T)zeroSize);
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
						SimpleHvLogError("[MiCopy Hook] clear buffer failed: 0x%x",
						                 GetExceptionCode());
						zeroSize = 0;
					}
				} else {
					zeroSize = 0;
				}
			}
		}

		/* 限流日志：只打印前 MIRWM_HOOK_LOG_LIMIT 次 */
		{
			ULONG hit = (ULONG)InterlockedIncrement(&g_MiRWM_HookHitCount);
			if (hit <= MIRWM_HOOK_LOG_LIMIT) {
				if (zeroSize) {
					SimpleHvLog("[MiCopy Hook] #%u pid=%u READ [0x%llx, +0x%llx) hits "
					            "protect range -> zeroed 0x%llx bytes (buf+0x%llx)",
					            hit, targetPid, (UINT64)readStart, (UINT64)bytesTransferred,
					            (UINT64)zeroSize, (UINT64)zeroOffset);
				} else {
					SimpleHvLog("[MiCopy Hook] #%u pid=%u READ [0x%llx, +0x%llx) reached hook "
					            "but NOT zeroed (prot=[0x%llx, +0x%llx) haveBytes=%u dstInCurProc=%u)",
					            hit, targetPid, (UINT64)readStart, (UINT64)bytesTransferred,
					            (UINT64)protBase, (UINT64)protSize,
					            (ULONG)haveByteCount, (ULONG)dstInCur);
				}
				if (hit == MIRWM_HOOK_LOG_LIMIT)
					SimpleHvLog("[MiCopy Hook] log limit reached (%u); further hits silent",
					            MIRWM_HOOK_LOG_LIMIT);
			}
		}
	}

	return result;
}
