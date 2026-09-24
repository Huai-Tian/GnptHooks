#include"hook.h"
#include"svm.h"
#include"vmcb.h"
#include"npt.h"
#include"LDasm.h"

//====================================================================
// Hook引擎实现(双NPT detour)
//
//触发链: Secondary视图hooked页(=CodePage)目标偏移14B绝对跳转 →
//  跳板槽(mov r10,entry; jmp GnptStubEntry) → GnptStubEntry
//  (hook-asm.asm): SAVE_ALL → GnptCallbackDispatch → 用户回调 →
//  ret回调用者(rax=回调返回值)
//
//GnptCallOriginal经LDE重定位跳板(视图无关)。
//Remove: 还原CodePage被覆盖字节+双视图PTE恒等还原+全核TLB同步
//  →hook失效; 在途回调安全完成(槽/条目延迟到卸载释放)
//====================================================================

#define HOOK_POOL_TAG        'MemN'     //中性池tag
#define HOOK_SLOT_SIZE       64         //跳板槽(24B机器码+余量)
#define HOOK_SLOT_PER_PAGE   (PAGE_SIZE / HOOK_SLOT_SIZE)
#define HOOK_REPLAY_BUF      96         //重定位跳板缓冲(最坏prologue+尾跳)
#define NPF_SWITCH_LOOP_MAX  16         //同(gpa)连续切换逃生阈值

//NPF错误码位(§15.25.6)
#define NPF_ERR_RW           (1ULL << 1)
#define NPF_ERR_ID           (1ULL << 4)

//内部条目(安装后除Removed外不可变→分发器无锁读安全)
typedef struct _GNPT_ENTRY
{
	volatile LONG Used;        //1=占用
	volatile LONG Removed;     //1=已移除(Enumerate/引擎跳过; 内存延迟释放)
	GNPT_HOOK pub;             //Target/Callback/Context/StackArgs
	PUCHAR Slot;               //跳板槽(mov r10,entry; jmp stub)
	PUCHAR ReplayVA;           //LDE重定位跳板
	ULONG  ReplayLen;          //重定位覆盖字节数(=CodePage跳转覆盖长度)
	PUCHAR CodePageVa;         //目标页补丁副本
	ULONG64 CodePagePa;
	ULONG64 TargetPa;          //目标页物理基址(NPF引擎hooked页判定键)
} GNPT_ENTRY, *PGNPT_ENTRY;

static GNPT_ENTRY g_hooks[GNPT_MAX_HOOKS];
static volatile LONG g_hookLive = 0;      //已安装未移除数(引擎快速门)
static PUCHAR g_slotPool = NULL;           //跳板槽池(1页, 懒分配)
static volatile LONG g_slotUsed = 0;

//每核当前视图(0=Primary 1=Secondary)+detour上下文(嵌套save-restore)
static volatile LONG g_view[64];
static PGNPT_ENTRY volatile g_curHook[64];
static PGUEST_REGS volatile g_curRegs[64];

//hook-asm.asm入口
extern VOID GnptStubEntry(VOID);
//GnptCallOrigAsm参数块(偏移与hook-asm.asm硬契约, 改一处须同步):
//  +00h Target  +08h StackArgs源  +10h Count  +18h..30h Arg1-4
typedef struct _GNPT_ORIG_CALL
{
	ULONG64 Target;
	ULONG64 StackArgs;
	ULONG64 Count;
	ULONG64 Arg1;
	ULONG64 Arg2;
	ULONG64 Arg3;
	ULONG64 Arg4;
} GNPT_ORIG_CALL;
extern ULONG64 GnptCallOrigAsm(GNPT_ORIG_CALL* Call);

//==================== 跳板槽 ====================
//槽机器码(24B): [0..9]=mov r10,imm64(条目) | [10..15]=jmp [rip+0]
//| [16..23]=GnptStubEntry地址(指针落t+16: jmp的RIP_after=t+16,
//disp32=0→CPU从t+16读操作数)。回读自检防编码错位(jmp处#GP)
static PUCHAR HookAllocSlot(PGNPT_ENTRY Entry)
{
	if (g_slotPool == NULL)
	{
		g_slotPool = (PUCHAR)ExAllocatePoolWithTag(
			NonPagedPool, PAGE_SIZE, HOOK_POOL_TAG);
		if (g_slotPool == NULL)
		{
			return NULL;
		}
		RtlZeroMemory(g_slotPool, PAGE_SIZE);
	}
	if (g_slotUsed >= HOOK_SLOT_PER_PAGE)
	{
		return NULL;    //64槽上限
	}
	LONG idx = InterlockedIncrement(&g_slotUsed) - 1;
	PUCHAR t = g_slotPool + (ULONG)idx * HOOK_SLOT_SIZE;
	t[0] = 0x49;  t[1] = 0xBA;                       //mov r10, imm64
	*(ULONG64*)(t + 2) = (ULONG64)Entry;
	t[10] = 0xFF; t[11] = 0x25;                      //jmp [rip+0]
	*(ULONG32*)(t + 12) = 0;
	*(ULONG64*)(t + 16) = (ULONG64)&GnptStubEntry;
	if (*(volatile ULONG64*)(t + 16) != (ULONG64)&GnptStubEntry)
	{
		return NULL;    //回读自检FAIL(编码回归)
	}
	return t;
}

//==================== detour分发与CallOriginal ====================
//asm stub调用(rcx=API条目, rdx=GUEST_REGS帧): 设置每核detour上下文
//后进用户回调。StackArgs>0时回调收第5+参数指针(=触发帧上实参
//regs->rsp+28h, 可读可写, 写后按改写值转发)
ULONG64 GnptCallbackDispatch(PVOID EntryPtr, PGUEST_REGS Regs)
{
	PGNPT_ENTRY e = (PGNPT_ENTRY)EntryPtr;
	ULONG cpu = KeGetCurrentProcessorNumber();
	//分发面包屑(首条+每4096条采样; 触发链定位用)
	{
		static volatile LONG s_dispCnt[64] = { 0 };
		LONG dn = InterlockedIncrement(&s_dispCnt[cpu & 63]);
		if (dn == 1 || (dn & 0xFFF) == 0)
		{
			FlRingPush('H', cpu, 0, (ULONG64)(ULONG_PTR)e->pub.Target, (ULONG64)dn, 0);
		}
	}
	PGNPT_ENTRY prevHook = g_curHook[cpu];
	PGUEST_REGS prevRegs = g_curRegs[cpu];
	g_curHook[cpu] = e;
	g_curRegs[cpu] = Regs;
	ULONG64* stackArgs = (e->pub.StackArgs != 0)
		? (ULONG64*)(Regs->rsp + 0x28) : NULL;
	ULONG64 ret = e->pub.Callback(e->pub.Context,
		Regs->rcx, Regs->rdx, Regs->r8, Regs->r9, stackArgs);
	g_curHook[cpu] = prevHook;
	g_curRegs[cpu] = prevRegs;
	return ret;
}

ULONG64 GnptCallOriginal(ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	PGNPT_ENTRY e = g_curHook[cpu];
	if (e == NULL)
	{
		//非回调上下文调用(用户误用): 静默返回0+一次性留痕
		static volatile LONG s_warned = 0;
		if (InterlockedCompareExchange(&s_warned, 1, 0) == 0)
		{
			FlRingPush('w', cpu, 0, 0, 0, 0);
		}
		return 0;
	}
	//CallOriginal面包屑(首条+每4096条采样; 触发链定位用)
	{
		static volatile LONG s_origCnt[64] = { 0 };
		LONG on = InterlockedIncrement(&s_origCnt[cpu & 63]);
		if (on == 1 || (on & 0xFFF) == 0)
		{
			FlRingPush('O', cpu, 0, (ULONG64)(ULONG_PTR)e->ReplayVA, (ULONG64)on, 0);
		}
	}
	if (e->pub.StackArgs != 0 && g_curRegs[cpu] != NULL)
	{
		//StackArgs>0: GnptCallOrigAsm桩重建完整x64调用帧, 栈参源=
		//触发帧上实参(回调可能已改写)
		GNPT_ORIG_CALL oc;
		oc.Target = (ULONG64)e->ReplayVA;
		oc.StackArgs = g_curRegs[cpu]->rsp + 0x28;
		oc.Count = e->pub.StackArgs;
		oc.Arg1 = Arg1;
		oc.Arg2 = Arg2;
		oc.Arg3 = Arg3;
		oc.Arg4 = Arg4;
		return GnptCallOrigAsm(&oc);
	}
	typedef ULONG64(*GNPT_REPLAY_FN)(ULONG64, ULONG64, ULONG64, ULONG64);
	return ((GNPT_REPLAY_FN)e->ReplayVA)(Arg1, Arg2, Arg3, Arg4);
}

//==================== LDE重定位跳板生成器 ====================
//  ①逐指令解码到≥MinLen(整指令边界, 跳回点不错位); 无效/超长=拒
//  ②相对分支=拒(rel8无法跨页重定位)
//  ③RIP-relative寻址: 重算disp32=绝对有效地址-新RIP_after, 超±2GB=拒
//  ④尾接 FF 25 00000000 + <Target+Len> 位置无关绝对跳转
//  ⑤回扫自检: 重新解码逐条比对长度+字节(disp区除外)
static PUCHAR HookBuildRelocTrampoline(ULONG64 Target, ULONG MinLen, PULONG OutLen)
{
	if (OutLen != NULL)
	{
		*OutLen = 0;
	}
	PUCHAR buf = (PUCHAR)ExAllocatePoolWithTag(
		NonPagedPool, HOOK_REPLAY_BUF, HOOK_POOL_TAG);
	if (buf == NULL)
	{
		FlLog("[Reloc] 拒绝: 跳板缓冲分配失败");
		return NULL;
	}
	RtlZeroMemory(buf, HOOK_REPLAY_BUF);
	ULONG total = 0;
	ULONG64 src = Target;
	BOOLEAN bad = FALSE;
	while (total < MinLen)
	{
		ldasm_data ld = { 0 };
		ULONG len = ldasm((PVOID)src, &ld, TRUE);
		if (len == 0 || (ld.flags & F_INVALID) || total + len > 80)
		{
			FlLog("[Reloc] 拒绝: 偏移+%u处指令解码失败/超长(len=%u flags=%02X)",
				total, len, (ULONG)ld.flags);
			bad = TRUE;
			break;
		}
		//相对分支=拒
		if ((ld.flags & F_IMM) && (ld.flags & F_RELATIVE))
		{
			FlLog("[Reloc] 拒绝: 偏移+%u处相对分支指令(%02X %02X...)——prologue不可重定位",
				total, *(PUCHAR)src, *((PUCHAR)src + 1));
			bad = TRUE;
			break;
		}
		RtlCopyMemory(buf + total, (PVOID)src, len);
		//RIP-relative数据寻址: 重算disp32(保持同一绝对有效地址)
		if ((ld.flags & F_DISP) && (ld.flags & F_RELATIVE) && ld.disp_size == 4)
		{
			LONG64 oldDisp = *(LONG*)(buf + total + ld.disp_offset);
			ULONG64 effective = src + len + (ULONG64)oldDisp;
			LONG64 newDisp = (LONG64)effective - (LONG64)(buf + total + len);
			if (newDisp < -0x80000000LL || newDisp > 0x7FFFFFFFLL)
			{
				FlLog("[Reloc] 拒绝: 偏移+%u处RIP-relative目标超±2GB(disp需%llX)",
					total, (long long)newDisp);
				bad = TRUE;
				break;
			}
			*(LONG*)(buf + total + ld.disp_offset) = (LONG)newDisp;
		}
		total += len;
		src += len;
	}
	if (!bad)
	{
		//尾接位置无关绝对跳转 → Target+total
		buf[total] = 0xFF;
		buf[total + 1] = 0x25;
		*(ULONG32*)(buf + total + 2) = 0;
		*(ULONG64*)(buf + total + 6) = Target + total;
		//回扫自检: 按CPU视角重新解码生成物, 与原始指令序列逐条比对
		ULONG chk = 0;
		ULONG64 ori = Target;
		while (chk < total && !bad)
		{
			ldasm_data ldNew = { 0 };
			ldasm_data ldOld = { 0 };
			ULONG lNew = ldasm(buf + chk, &ldNew, TRUE);
			ULONG lOld = ldasm((PVOID)ori, &ldOld, TRUE);
			if (lNew == 0 || lNew != lOld || (ldNew.flags & F_INVALID))
			{
				FlLog("[Reloc] 回扫自检FAIL: 生成物偏移+%u解码异常(新len=%u 旧len=%u)",
					chk, lNew, lOld);
				bad = TRUE;
				break;
			}
			//逐字节比对(disp区=已重算, 跳过)
			ULONG dispStart = (ULONG)ldNew.disp_offset;
			ULONG dispEnd = dispStart + ldNew.disp_size;
			for (ULONG k = 0; k < lNew; k++)
			{
				if (k >= dispStart && k < dispEnd)
				{
					continue;
				}
				if (buf[chk + k] != *(PUCHAR)(ori + k))
				{
					FlLog("[Reloc] 回扫自检FAIL: 生成物偏移+%u字节%u不符(%02X vs %02X)",
						chk, k, buf[chk + k], *(PUCHAR)(ori + k));
					bad = TRUE;
					break;
				}
			}
			chk += lNew;
			ori += lOld;
		}
	}
	if (bad)
	{
		ExFreePoolWithTag(buf, HOOK_POOL_TAG);
		return NULL;
	}
	if (OutLen != NULL)
	{
		*OutLen = total;
	}
	return buf;
}

//==================== NPF视图切换引擎(svm.c exit handler调用) ====================
//返回TRUE=已处理(重入guest); FALSE=未处理(异常留痕由调用方)
static ULONG64 g_lastNpfGpa[64];
static ULONG g_npfLoopCnt[64];

//写VMCB切换视图; bring-up形态=每次切换置TLB_CONTROL=3(正确性优先,
//免flush的ASID配对切换=物理机定案阶段性能项)
static VOID HookSwitchView(PVMCB Vmcb, ULONG Cpu, ULONG View)
{
	Vmcb->Control.NCr3 = SvmNptViewNcr3(View);
	Vmcb->Control.GuestAsid = (View == GNPT_VIEW_SECONDARY)
		? NPT_ASID_SECONDARY : NPT_ASID_PRIMARY;
	Vmcb->Control.TlbControl = 3;    //本guest全部TLB条目下轮vmrun失效
	g_view[Cpu] = (LONG)View;
	//视图切换面包屑(首条+每4096条采样; 触发链定位用)
	{
		static volatile LONG s_swCnt[64] = { 0 };
		LONG vn = InterlockedIncrement(&s_swCnt[Cpu & 63]);
		if (vn == 1 || (vn & 0xFFF) == 0)
		{
			FlRingPush('V', Cpu, 0, (ULONG64)View, (ULONG64)vn, 0);
		}
	}
}

BOOLEAN GnptHookNpfEngine(PVMCB Vmcb, ULONG Cpu, ULONG64 ExitInfo1, ULONG64 ExitInfo2)
{
	if (g_hookLive == 0)
	{
		return FALSE;
	}
	//hooked页判定(物理页基址键)
	ULONG64 gpaPage = ExitInfo2 & ~(ULONG64)0xFFF;
	PGNPT_ENTRY hit = NULL;
	for (ULONG i = 0; i < GNPT_MAX_HOOKS; i++)
	{
		if (g_hooks[i].Used && !g_hooks[i].Removed &&
			g_hooks[i].TargetPa == gpaPage)
		{
			hit = &g_hooks[i];
			break;
		}
	}
	//风暴逃生: 同gpa连续切换超阈值='X'留痕(仍切换, 观测面)
	if (g_lastNpfGpa[Cpu] == ExitInfo2)
	{
		if (++g_npfLoopCnt[Cpu] == NPF_SWITCH_LOOP_MAX)
		{
			FlRingPush('X', Cpu, 0x400, ExitInfo2,
				ExitInfo1, g_view[Cpu]);
		}
	}
	else
	{
		g_lastNpfGpa[Cpu] = ExitInfo2;
		g_npfLoopCnt[Cpu] = 0;
	}
	if (ExitInfo1 & NPF_ERR_ID)
	{
		//取指NPF: hooked页→进Secondary; 非hooked页→Secondary态回Primary
		if (hit != NULL)
		{
			if (g_view[Cpu] == GNPT_VIEW_PRIMARY)
			{
				HookSwitchView(Vmcb, Cpu, GNPT_VIEW_SECONDARY);
				return TRUE;
			}
			//Secondary态hooked页取指fault=不可达(CodePage可执行)→留痕逃生
			FlRingPush('N', Cpu, 0x400, ExitInfo2, ExitInfo1, 0);
			HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
			return TRUE;
		}
		if (g_view[Cpu] == GNPT_VIEW_SECONDARY)
		{
			HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
			return TRUE;
		}
		return FALSE;    //Primary态非hooked取指fault=未覆盖/异常→留痕
	}
	//数据NPF: Secondary态对hooked页写(CodePage只读)→回Primary转发原页
	if (hit != NULL && (ExitInfo1 & NPF_ERR_RW) &&
		g_view[Cpu] == GNPT_VIEW_SECONDARY)
	{
		HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
		return TRUE;
	}
	return FALSE;
}

//==================== 安装/移除 ====================
//全核TLB同步: 每核vmcall(NPTSYNC)→exit handler置TLB_CONTROL=3
static ULONG_PTR NTAPI HookSyncIpi(ULONG_PTR Ignored)
{
	UNREFERENCED_PARAMETER(Ignored);
	ULONG cpu = KeGetCurrentProcessorNumber();
	if (cpu < 64 && g_svmVcpu[cpu].base.bInGuest)
	{
		(VOID)CmVmmCall(GNPT_VMCALL_NPTSYNC, 0, 0, 0);
	}
	return 0;
}

static VOID HookSyncAllCpus(VOID)
{
	(VOID)KeIpiGenericCall(HookSyncIpi, 0);
}

NTSTATUS GnptHookInstall(const GNPT_HOOK* Hook)
{
	if (Hook == NULL || Hook->Target == NULL || Hook->Callback == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}
	if (Hook->StackArgs > GNPT_MAX_STACK_ARGS)
	{
		FlLog("[Hook] Install拒绝: StackArgs=%u超上限%u(目标%p)",
			Hook->StackArgs, (ULONG)GNPT_MAX_STACK_ARGS, Hook->Target);
		return STATUS_INVALID_PARAMETER;
	}
	//安装gate: 引擎运行中(至少一核in-guest+NPT已建)
	{
		BOOLEAN ready = (SvmNptViewNcr3(GNPT_VIEW_PRIMARY) != 0);
		if (ready)
		{
			ULONG n = KeQueryActiveProcessorCount(NULL);
			ULONG inGuest = 0;
			for (ULONG i = 0; i < n && i < 64; i++)
			{
				if (g_svmVcpu[i].base.bInGuest)
				{
					inGuest++;
				}
			}
			ready = (inGuest != 0);
		}
		if (!ready)
		{
			FlLog("[Hook] Install拒绝: 引擎未运行(零核in-guest或NPT未建)");
			return STATUS_NOT_SUPPORTED;
		}
	}
	//页边界检查: 目标偏移+14B不得跨页
	ULONG off = (ULONG)((ULONG_PTR)Hook->Target & (PAGE_SIZE - 1));
	if (off + 14 > PAGE_SIZE)
	{
		FlLog("[Hook] Install拒绝: 目标%p偏移%u+14跨页", Hook->Target, off);
		return STATUS_UNSUCCESSFUL;
	}
	//条目分配+重复安装检查
	PGNPT_ENTRY e = NULL;
	for (ULONG i = 0; i < GNPT_MAX_HOOKS; i++)
	{
		if (g_hooks[i].Used && !g_hooks[i].Removed &&
			g_hooks[i].pub.Target == Hook->Target)
		{
			FlLog("[Hook] Install拒绝: 目标%p已安装(Remove后可重装)", Hook->Target);
			return STATUS_UNSUCCESSFUL;
		}
		if (e == NULL && !g_hooks[i].Used)
		{
			e = &g_hooks[i];
		}
	}
	if (e == NULL)
	{
		FlLog("[Hook] Install拒绝: 条目满(%u)", (ULONG)GNPT_MAX_HOOKS);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(e, sizeof(GNPT_ENTRY));
	e->pub = *Hook;
	e->Used = 1;
	e->Removed = 0;
	//LDE重定位跳板(MinLen=14=CodePage跳转覆盖长度, 两者同源同长)
	e->ReplayVA = HookBuildRelocTrampoline((ULONG64)Hook->Target, 14,
		&e->ReplayLen);
	if (e->ReplayVA == NULL)
	{
		e->Used = 0;
		FlLog("[Hook] Install失败: 目标%p prologue不可重定位(见[Reloc]行)",
			Hook->Target);
		return STATUS_UNSUCCESSFUL;
	}
	//跳板槽
	e->Slot = HookAllocSlot(e);
	if (e->Slot == NULL)
	{
		ExFreePoolWithTag(e->ReplayVA, HOOK_POOL_TAG);
		e->Used = 0;
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	//CodePage: 目标页整页副本+目标偏移14B绝对跳转→槽
	e->CodePageVa = (PUCHAR)ExAllocatePoolWithTag(
		NonPagedPool, PAGE_SIZE, HOOK_POOL_TAG);
	if (e->CodePageVa == NULL)
	{
		ExFreePoolWithTag(e->ReplayVA, HOOK_POOL_TAG);
		e->Used = 0;
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlCopyMemory(e->CodePageVa, (PVOID)((ULONG_PTR)Hook->Target & ~(ULONG_PTR)(PAGE_SIZE - 1)), PAGE_SIZE);
	e->CodePagePa = MmGetPhysicalAddress(e->CodePageVa).QuadPart;
	{
		PUCHAR patch = e->CodePageVa + off;
		patch[0] = 0xFF; patch[1] = 0x25;                  //jmp [rip+0]
		*(ULONG32*)(patch + 2) = 0;
		*(ULONG64*)(patch + 6) = (ULONG64)e->Slot;
	}
	e->TargetPa = MmGetPhysicalAddress(
		(PVOID)((ULONG_PTR)Hook->Target & ~(ULONG_PTR)(PAGE_SIZE - 1))).QuadPart;
	//双视图PTE布防(Secondary先布=布防窗口无害):
	//  Primary: 原页可读可写不可执行(取指NPF→切换)
	//  Secondary: CodePage只读可执行(写NPF→回Primary转发)
	SvmNptSetPte(GNPT_VIEW_SECONDARY, e->TargetPa, e->CodePagePa,
		NPT_PTE_FLAGS_HOOKS);
	SvmNptSetPte(GNPT_VIEW_PRIMARY, e->TargetPa, e->TargetPa,
		NPT_PTE_FLAGS_HOOKP);
	//全核TLB同步=布防即刻生效
	HookSyncAllCpus();
	InterlockedIncrement(&g_hookLive);
	FlLog("[Hook] Install OK: 目标=%p 回调=%p 跳板槽=%p 重定位跳板=%p(%uB) CodePage=%p(PA=%llX) 栈参=%u",
		Hook->Target, Hook->Callback, e->Slot, e->ReplayVA, e->ReplayLen,
		e->CodePageVa, e->CodePagePa, Hook->StackArgs);
	return STATUS_SUCCESS;
}

NTSTATUS GnptHookRemove(PVOID Target)
{
	for (ULONG i = 0; i < GNPT_MAX_HOOKS; i++)
	{
		PGNPT_ENTRY e = &g_hooks[i];
		if (!e->Used || e->Removed || e->pub.Target != Target)
		{
			continue;
		}
		//①还原CodePage被覆盖字节(源=原页, 原页从未被改)——
		//  尚持旧TLB翻译的核此刻也只见原始字节=hook死透
		ULONG off = (ULONG)((ULONG_PTR)Target & (PAGE_SIZE - 1));
		RtlCopyMemory(e->CodePageVa + off, (PUCHAR)Target, e->ReplayLen);
		//②双视图PTE恒等还原
		SvmNptRestoreIdentity(GNPT_VIEW_PRIMARY, e->TargetPa);
		SvmNptRestoreIdentity(GNPT_VIEW_SECONDARY, e->TargetPa);
		//③全核TLB同步(残留CodePage翻译被冲净)
		HookSyncAllCpus();
		e->Removed = 1;
		InterlockedDecrement(&g_hookLive);
		FlLog("[Hook] Remove OK: 目标=%p 还原%uB+双视图PTE恒等+全核TLB同步(在途回调安全完成)",
			Target, e->ReplayLen);
		return STATUS_SUCCESS;
	}
	return STATUS_NOT_FOUND;
}

//DriverUnload在关引擎**之前**调用: 移除全部live hook
//(在途回调此刻引擎仍开着=安全)
VOID GnptHookRemoveAll(VOID)
{
	ULONG n = 0;
	for (ULONG i = 0; i < GNPT_MAX_HOOKS; i++)
	{
		if (g_hooks[i].Used && !g_hooks[i].Removed)
		{
			if (NT_SUCCESS(GnptHookRemove(g_hooks[i].pub.Target)))
			{
				n++;
			}
		}
	}
	if (n != 0)
	{
		FlLog("[Hook] RemoveAll: 已移除%u个hook", n);
	}
}

//DriverUnload在关引擎**之后**调用(纯内存释放, 无引擎依赖):
//清零后释放(CodePage跳转码/条目指针不残留给PFN新拥有者)
VOID GnptHookFreeMemory(VOID)
{
	ULONG entries = 0, replays = 0, codepages = 0;
	for (ULONG i = 0; i < GNPT_MAX_HOOKS; i++)
	{
		PGNPT_ENTRY e = &g_hooks[i];
		if (!e->Used)
		{
			continue;
		}
		if (e->ReplayVA != NULL)
		{
			RtlZeroMemory(e->ReplayVA, HOOK_REPLAY_BUF);
			ExFreePoolWithTag(e->ReplayVA, HOOK_POOL_TAG);
			replays++;
		}
		if (e->CodePageVa != NULL)
		{
			RtlZeroMemory(e->CodePageVa, PAGE_SIZE);
			ExFreePoolWithTag(e->CodePageVa, HOOK_POOL_TAG);
			codepages++;
		}
		RtlZeroMemory(e, sizeof(GNPT_ENTRY));
		entries++;
	}
	if (g_slotPool != NULL)
	{
		RtlZeroMemory(g_slotPool, PAGE_SIZE);
		ExFreePoolWithTag(g_slotPool, HOOK_POOL_TAG);
		g_slotPool = NULL;
	}
	g_slotUsed = 0;
	g_hookLive = 0;
	if (entries != 0)
	{
		FlLog("[Hook] FreeMemory: 条目%u个(重定位跳板%u+CodePage%u)+槽池已释放(清零后释放)",
			entries, replays, codepages);
	}
}
