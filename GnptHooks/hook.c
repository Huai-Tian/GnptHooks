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
//  ①逐指令解码到源侧≥MinLen(整指令边界, 跳回点不错位); 无效/超长=拒
//  ②相对分支=拒(rel8无法跨页重定位)
//  ③RIP-relative寻址: 重算disp32保绝对有效地址; 超±2GB→改写为
//     mov reg,imm64绝对直存(仅REX.W lea, 不可改写=拒)
//  ④尾接 FF 25 00000000 + <Target+源覆盖长> 位置无关绝对跳转
//     (改写后生成物长度≠源覆盖长——跳回点必须按源侧算)
//  ⑤回扫自检: 重新解码逐条比对长度+字节(disp区除外); 改写段验
//     双长度吻合+直存值==绝对有效地址(等价性黄金校验)
//本生成器与 tests/test_reloc.c(用户态执行级单测)为镜像契约:
//逻辑改动必须双向同步并通过该测试(含真实CPU执行验证)

//改写记录(回扫自检用): At=生成物内偏移 OldLen=源指令长度 Value=直存值
typedef struct _HOOK_REWRITE_REC
{
	ULONG   At;
	ULONG   OldLen;
	ULONG64 Value;
} HOOK_REWRITE_REC;
#define HOOK_MAX_REWRITES 8

//lea reg,[rip+disp32]→mov reg,imm64绝对直存(RIP-rel超±2GB改写)。
//仅收无前缀REX.W lea(modrm mod=00 rm=101, 7B形态); 直存值=原绝对
//有效地址, 语义等价(模块内相对偏移运行期不变, KASLR下恒真)。
//mov等内存加载源不在改写范围=拒(需保持逐字语义, 防越权扩面)
static ULONG HookRewriteRipRelImm64(PUCHAR Dst, ldasm_data* Ld,
	ULONG OldLen, ULONG64 Value)
{
	if (OldLen != 7 || Ld->opcd_offset != 1 || Ld->opcd_size != 1 ||
		Dst[1] != 0x8D || (Ld->flags & F_PREFIX) || (Ld->flags & F_SIB) ||
		Ld->imm_size != 0 || Ld->disp_size != 4 || (Ld->rex & 0x08) == 0)
	{
		return 0;    //非"REX.W 8D /r"纯净7B形态=拒
	}
	if ((Ld->modrm & 0xC7) != 0x05)    //mod=00 rm=101=[rip+disp32]
	{
		return 0;
	}
	ULONG reg = ((Ld->modrm >> 3) & 7) + ((Ld->rex & 0x04) ? 8 : 0);
	Dst[0] = (UCHAR)(0x48 | (reg >= 8 ? 1 : 0));    //REX.W(+B)
	Dst[1] = (UCHAR)(0xB8 | (reg & 7));             //mov reg,imm64
	*(ULONG64*)(Dst + 2) = Value;
	return 10;
}

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
	HOOK_REWRITE_REC rewTab[HOOK_MAX_REWRITES];
	ULONG rewCount = 0;
	//循环按源侧覆盖长判定(非生成物长度): 改写膨胀不得计入"已
	//跳过patch区"的账——否则源侧<14即停, 跳回点落patch内=死循环
	while ((ULONG)(src - Target) < MinLen)
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
		//RIP-relative数据寻址(非分支): 保绝对有效地址不变。
		//近区(±2GB内)=重算disp32; 超距(Zw桩形如lea r10,[rip±2TB])=
		//改写为等价mov reg,imm64绝对直存(见HookRewriteRipRelImm64)
		if ((ld.flags & F_DISP) && (ld.flags & F_RELATIVE) && ld.disp_size == 4)
		{
			LONG64 oldDisp = *(LONG*)(buf + total + ld.disp_offset);
			ULONG64 effective = src + len + (ULONG64)oldDisp;
			LONG64 newDisp = (LONG64)effective - (LONG64)(buf + total + len);
			if (newDisp >= -0x80000000LL && newDisp <= 0x7FFFFFFFLL)
			{
				*(LONG*)(buf + total + ld.disp_offset) = (LONG)newDisp;
			}
			else
			{
				//超±2GB: lea reg,[rip+d]→mov reg,imm64直存。
				//生成物按新长推进, 源/自检按原长推进(两账分开)
				ULONG rew = 0;
				if (rewCount < HOOK_MAX_REWRITES &&
					total + 10 + 14 <= HOOK_REPLAY_BUF)
				{
					rew = HookRewriteRipRelImm64(buf + total, &ld, len, effective);
				}
				if (rew == 0)
				{
					FlLog("[Reloc] 拒绝: 偏移+%u处RIP-rel超±2GB且不可改写"
						"(disp需%llX 字节%02X %02X %02X)",
						total, (long long)newDisp,
						*(PUCHAR)src, *((PUCHAR)src + 1), *((PUCHAR)src + 2));
					bad = TRUE;
					break;
				}
				rewTab[rewCount].At = total;
				rewTab[rewCount].OldLen = len;
				rewTab[rewCount].Value = effective;
				rewCount++;
				total += rew;    //生成物: mov reg,imm64=10B
				src += len;      //源: 原指令长度
				continue;
			}
		}
		total += len;
		src += len;
	}
	if (!bad)
	{
		//尾接位置无关绝对跳转 → Target+源覆盖长(=src; 改写后生成
		//物长度≠源覆盖长, 跳回点必须按源侧算, 否则落指令中途)
		buf[total] = 0xFF;
		buf[total + 1] = 0x25;
		*(ULONG32*)(buf + total + 2) = 0;
		*(ULONG64*)(buf + total + 6) = src;
		//回扫自检: 按CPU视角重新解码生成物, 与原始指令序列逐条比对
		ULONG chk = 0;
		ULONG64 ori = Target;
		while (chk < total && !bad)
		{
			ldasm_data ldNew = { 0 };
			ldasm_data ldOld = { 0 };
			ULONG lNew = ldasm(buf + chk, &ldNew, TRUE);
			ULONG lOld = ldasm((PVOID)ori, &ldOld, TRUE);
			//改写段: 不比字节(必然不同), 验解码有效+双长度吻合+
			//直存值==改写时记录的绝对有效地址(等价性黄金校验)
			ULONG r;
			for (r = 0; r < rewCount; r++)
			{
				if (rewTab[r].At == chk)
				{
					break;
				}
			}
			if (r < rewCount)
			{
				if (lNew == 0 || (ldNew.flags & F_INVALID) || lNew != 10 ||
					lOld != rewTab[r].OldLen ||
					(buf[chk] & 0xF0) != 0x40 || (buf[chk] & 0x08) == 0 ||
					(buf[chk + 1] & 0xF8) != 0xB8 ||
					*(ULONG64*)(buf + chk + 2) != rewTab[r].Value)
				{
					FlLog("[Reloc] 回扫自检FAIL: 改写段偏移+%u校验不符"
						"(新len=%u 旧len=%u 直存=%llX 应存=%llX)",
						chk, lNew, lOld,
						(long long)*(ULONG64*)(buf + chk + 2),
						(long long)rewTab[r].Value);
					bad = TRUE;
					break;
				}
				chk += lNew;
				ori += rewTab[r].OldLen;
				continue;
			}
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
		//源侧覆盖长(≠生成物长度): CodePage还原宽度+尾跳落点依据
		*OutLen = (ULONG)(src - Target);
	}
	return buf;
}

//==================== TF+#DB单步原语(AMD无MTF的读透明基础件) ====================
//窗口式拦截: PUSHF/POPF仅单步窗口开(窗口外零开销); #DB拦截常驻
//(窗口外残余TF的guest可见#DB=0x3B/0x1E致命, 常驻
//+IDLE吞+清TF=最后一道网, guest调试兼容性让位于稳定性)。
//IRET/SYSCALL/SYSRET不拦(清TF类→LeakCheck收口); INTn不拦但arm时
//探测+#DB收尾清洗int帧内TF。
static VOID HookSwitchView(PVMCB Vmcb, ULONG Cpu, ULONG View);    //前向(定义在NPF引擎段)
#define RFLAGS_TF               (1ULL << 8)
#define RFLAGS_FIXED1           (1ULL << 1)
//POPF合法可写位掩码(CF..IOPL..AC..ID; RF弹值忽略, VM/VIF/VIP/NT清0)
#define RFLAGS_POPF_WRITEABLE   0x0000000000243FD7ULL
#define DR6_BS                  (1ULL << 14)   //bit14=单步引发(APM页855)
#define STEP_WINDOW_INTERCEPTS  (INTERCEPT_PUSHF | INTERCEPT_POPF)

//单步用途
#define STEP_IDLE               0     //无单步
#define STEP_READ_TRANS         1     //方案A: #DB时切回Secondary
#define STEP_TEMP_RW            2     //方案B: #DB时撤临时RW页集(视图不动)
#define STEP_REHIDE             3     //TRANSPARENT: #DB时本核副本复位潜伏P=0

//每核单步状态
static volatile LONG g_stepUse[64];        //用途(STEP_*)
static volatile LONG g_stepRwMask[64];     //方案B页集(bit i=g_hooks[i]临时RW中)
static volatile LONG64 g_stepTfShadow[64];  //guest TF影子(arm时初始化, popf仿真同步)
static volatile LONG g_stepHookIdx[64];    //arm时的hook条目(REHIDE收尾用)
static volatile LONG g_stepRetView[64];    //READ_TRANS归返视图(HIDE或HOOKS)
static volatile LONG g_stepArmIntn[64];    //arm时步进指令=INTn(0xCD): 收尾须清int帧内注入TF
//NPF乒乓计数(定义于此: #DB收尾与泄漏收口都要复位; 引擎主体在NPF段)
static ULONG64 g_lastNpfGpa[64];
static ULONG g_npfLoopCnt[64];

//hooked页PTE临时RW开/撤(方案B; 调用方统一置TlbControl=3)
static VOID HookTempRwSet(ULONG HookIdx, ULONG Cpu, BOOLEAN On)
{
	if (HookIdx >= GNPT_MAX_HOOKS)
	{
		return;
	}
	PGNPT_ENTRY e = &g_hooks[HookIdx];
	if (!e->Used || e->Removed)
	{
		return;    //条目已移除: 撤除跳过(Remove已还原恒等, 重写=复活已死hook)
	}
	if (On)
	{
		SvmNptSetPte(GNPT_VIEW_SECONDARY, e->TargetPa, e->CodePagePa,
			NPT_PTE_FLAGS_HOOKS | NPT_PTE_RW);
		g_stepRwMask[Cpu] |= (LONG)(1UL << HookIdx);
	}
	else
	{
		SvmNptSetPte(GNPT_VIEW_SECONDARY, e->TargetPa, e->CodePagePa,
			NPT_PTE_FLAGS_HOOKS);
		g_stepRwMask[Cpu] &= ~(LONG)(1UL << HookIdx);
	}
}

//arm单步: 注入TF+开窗口拦截(方案A切视图由调用方先行)
static VOID HookStepArm(PVMCB Vmcb, ULONG Cpu, LONG Use, ULONG HookIdx)
{
	g_stepTfShadow[Cpu] = (LONG64)((Vmcb->State.Rflags & RFLAGS_TF) >> 8);
	g_stepHookIdx[Cpu] = (LONG)HookIdx;
	//步进指令INTn探测: int压栈的是活RFLAGS=含注入TF→
	//handler iret复活=guest自发#DB(0x1E级)。#DB收尾清帧内TF
	//(见GnptHookStepDbExit)。读原页真字节(host直译=原页恒在)
	{
		ldasm_data la = { 0 };
		ULONG al = ldasm((PVOID)(ULONG_PTR)Vmcb->State.Rip, &la, TRUE);
		g_stepArmIntn[Cpu] = (al != 0 && !(la.flags & F_INVALID) &&
			la.opcd_size == 1 &&
			((PUCHAR)(ULONG_PTR)Vmcb->State.Rip)[la.opcd_offset] == 0xCD)
			? 1 : 0;
	}
	if (Use == STEP_TEMP_RW)
	{
		g_stepRwMask[Cpu] = 0;
		HookTempRwSet(HookIdx, Cpu, TRUE);
		Vmcb->Control.TlbControl = 3;    //临时RW即刻生效
	}
	Vmcb->State.Rflags |= RFLAGS_TF;
	Vmcb->Control.InterceptException |= EXCP_INTERCEPT_DB;
	Vmcb->Control.InterceptMisc1 |= STEP_WINDOW_INTERCEPTS;
	g_stepUse[Cpu] = Use;
	//面包屑(首条+每4096条采样; 扫描器循环读=高频, 防刷爆)
	{
		static volatile LONG s_armCnt[64] = { 0 };
		LONG an = InterlockedIncrement(&s_armCnt[Cpu & 63]);
		if (an == 1 || (an & 0xFFF) == 0)
		{
			FlRingPush('s', Cpu, (ULONG)Use, HookIdx, (ULONG64)an, 0);
		}
	}
}

//svm.c exit handler调用(0x41): #DB认领分发。
//返回TRUE=已处理(重入guest); FALSE=非单步窗口(svm.c防御留痕)
BOOLEAN GnptHookStepDbExit(PVMCB Vmcb, ULONG Cpu)
{
	if (g_stepUse[Cpu] == STEP_IDLE)
	{
		return FALSE;
	}
	//认领: armed窗口内#DB一律认领——含BS=0的
	//Dr断点#DB(注入回guest无调试接手→0x1E)。BS降级面包屑;
	//guest自身单步(影子TF)嵌套验收场景无此形态, 物理机再评
	BOOLEAN bs = (Vmcb->State.Dr6 & DR6_BS) != 0;
	//INTn步进收尾: TF-trap落点=int handler首指令(指令已完整执行,
	//int帧已压栈)。帧[+0x10]=RFLAGS(同CPL无SS:RSP槽, §6.14.2)——
	//压入的是活RFLAGS=含注入TF, 不清则handler iret弹回=TF复活进
	//EFLAGS→后续窗口shadow投毒→忠实还原连环泄漏→guest可见#DB
	//(0x3B级)。**不可bs门控**: 嵌套环境可能以DR6.BS=0投递TF陷阱,
	//bs恒假=清洗被跳过。栈=内核栈(window仅hooked页取指可达)
	if (g_stepArmIntn[Cpu])
	{
		*(ULONG64*)(Vmcb->State.Rsp + 0x10) &= ~RFLAGS_TF;
		static volatile LONG s_inCnt[64] = { 0 };
		LONG in = InterlockedIncrement(&s_inCnt[Cpu & 63]);
		if (in == 1 || (in & 0xFF) == 0)
		{
			FlRingPush('I', Cpu, 0, (ULONG64)(ULONG_PTR)Vmcb->State.Rip,
				*(ULONG64*)(Vmcb->State.Rsp + 0x10), 0);
		}
	}
	//收尾(所有armed场景: guest事件抢先也意味着窗口指令已完成)
	LONG use = g_stepUse[Cpu];
	g_stepUse[Cpu] = STEP_IDLE;
	if (use == STEP_READ_TRANS)
	{
		HookSwitchView(Vmcb, Cpu, (ULONG)g_stepRetView[Cpu]);   //归返原视图
	}
	else if (use == STEP_TEMP_RW)
	{
		ULONG mask = (ULONG)g_stepRwMask[Cpu];
		g_stepRwMask[Cpu] = 0;
		for (ULONG i = 0; mask != 0 && i < GNPT_MAX_HOOKS; i++, mask >>= 1)
		{
			if (mask & 1)
			{
				HookTempRwSet(i, Cpu, FALSE);
			}
		}
		Vmcb->Control.TlbControl = 3;    //撤RW即刻生效
	}
	else if (use == STEP_REHIDE)
	{
		//TRANSPARENT: 窗口指令执行完毕——ASID配对切回HIDE潜伏树
		//(§15.16换ASID=零flush; 树静态无PTE写)。他核恒
		//潜伏→读hooked页=fault→原始字节(破洞=0)
		HookSwitchView(Vmcb, Cpu, GNPT_VIEW_HIDE);
	}
	//关窗口拦截位(仅PUSHF/POPF; #DB拦截常驻——窗口外任何
	//残余TF的#DB→svm.c IDLE吞+清TF, 杜绝guest可见#DB=0x3B/0x1E)
	Vmcb->Control.InterceptMisc1 &= ~STEP_WINDOW_INTERCEPTS;
	//TF忠实还原: 撤注入TF, 重应用guest自身TF(影子)
	if (g_stepTfShadow[Cpu])
	{
		Vmcb->State.Rflags |= RFLAGS_TF;
	}
	else
	{
		Vmcb->State.Rflags &= ~RFLAGS_TF;
	}
	g_npfLoopCnt[Cpu] = 0;    //窗口收口=NPF乒乓计数复位(舞步逐指令同gpa不误触[X])
	{
		static volatile LONG s_finCnt[64] = { 0 };
		LONG fn = InterlockedIncrement(&s_finCnt[Cpu & 63]);
		if (fn == 1 || (fn & 0xFFF) == 0)
		{
			//'e': b=0(BS=1 TF引发)/b=1(BS=0 Dr断点抢入已吞)
			FlRingPush('e', Cpu, (ULONG)use, bs ? 0 : 1, (ULONG64)fn, 0);
		}
	}
	return TRUE;    //不注入(trap语义RIP已下一条, 不再推)
}

//svm.c exit handler调用(0x70): PUSHF仿真(EFLAGS影子——guest不看见注入TF)
BOOLEAN GnptHookStepEmuPushf(PVMCB Vmcb, ULONG Cpu)
{
	if (g_stepUse[Cpu] == STEP_IDLE)
	{
		return FALSE;
	}
	//压影子RFLAGS(清注入TF); 栈页两视图均RW(普通页)
	ULONG64 rsp = Vmcb->State.Rsp - 8;
	*(ULONG64*)rsp = Vmcb->State.Rflags & ~RFLAGS_TF;
	Vmcb->State.Rsp = rsp;
	Vmcb->State.Rip = Vmcb->Control.NRip;    //指令拦截NRIP有效
	{
		static volatile LONG s_pfCnt[64] = { 0 };
		LONG pn = InterlockedIncrement(&s_pfCnt[Cpu & 63]);
		if (pn == 1 || (pn & 0xFFF) == 0)
		{
			FlRingPush('P', Cpu, 0, (ULONG64)(ULONG_PTR)Vmcb->State.Rip,
				(ULONG64)pn, 0);
		}
	}
	return TRUE;
}

//svm.c exit handler调用(0x71): POPF仿真(影子同步+保注入TF+防御位清洗)
BOOLEAN GnptHookStepEmuPopf(PVMCB Vmcb, ULONG Cpu)
{
	if (g_stepUse[Cpu] == STEP_IDLE)
	{
		return FALSE;
	}
	ULONG64 val = *(ULONG64*)Vmcb->State.Rsp;
	Vmcb->State.Rsp += 8;
	//影子同步: guest想改TF(记录意图; 重应用=物理机再评)
	g_stepTfShadow[Cpu] = (LONG64)((val & RFLAGS_TF) >> 8);
	//新RFLAGS=合法可写位 | bit1固定1; TF=注入态保留(窗口未收尾)
	ULONG64 rf = (val & RFLAGS_POPF_WRITEABLE) | RFLAGS_FIXED1;
	if (Vmcb->State.Rflags & RFLAGS_TF)
	{
		rf |= RFLAGS_TF;
	}
	Vmcb->State.Rflags = rf;
	Vmcb->State.Rip = Vmcb->Control.NRip;
	{
		static volatile LONG s_poCnt[64] = { 0 };
		LONG pon = InterlockedIncrement(&s_poCnt[Cpu & 63]);
		if (pon == 1 || (pon & 0xFFF) == 0)
		{
			FlRingPush('p', Cpu, 0, (ULONG64)(ULONG_PTR)Vmcb->State.Rip,
				(ULONG64)pon, 0);
		}
	}
	return TRUE;
}

//==================== NPF视图切换引擎(svm.c exit handler调用) ====================
//返回TRUE=已处理(重入guest); FALSE=未处理(异常留痕由调用方)

//写VMCB切换视图(四视图ASID配对): NCr3+ASID同写——TLB条目按
//ASID tag(§15.25.1), 四套翻译并存互不命中, 切换零flush零PTE写
//(§15.16同ASID改翻译才须flush, 留给临时RW/NPTSYNC)。
//clean bits全0=两字段每轮vmrun必从VMCB加载, 写即生效
static const ULONG k_viewAsid[GNPT_VIEW_COUNT] = {
	NPT_ASID_PRIMARY, NPT_ASID_SECONDARY, NPT_ASID_HIDE, NPT_ASID_EXEC
};

static VOID HookSwitchView(PVMCB Vmcb, ULONG Cpu, ULONG View)
{
	View &= (GNPT_VIEW_COUNT - 1);
	Vmcb->Control.NCr3 = SvmNptViewNcr3(View);
	Vmcb->Control.GuestAsid = k_viewAsid[View];
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

//svm.c每exit首查: 单步窗口泄漏防御收口。
//泄漏形态: 步进指令属清/搬运TF类(syscall清TF/sysret-iret弹回值,
//按设计不拦)→#DB永不到达→PUSHF/POPF/#DB拦截位+EXEC视图
//永久泄漏→全系统pushf/popf exit风暴+兜底"推进"跳过指令的
//标志/栈效应=guest状态破坏(0x1E级)。
//判据: armed而guest TF已失=窗口死亡铁证。按use收尾+解除拦截+
//影子TF忠实还原。开销: 窗口外2读+1比较/exit。
VOID GnptHookStepLeakCheck(PVMCB Vmcb, ULONG Cpu)
{
	if (g_stepUse[Cpu] == STEP_IDLE ||
		(Vmcb->State.Rflags & RFLAGS_TF) != 0)
	{
		return;    //无窗口或TF仍活(窗口健康, #DB必达)
	}
	LONG use = g_stepUse[Cpu];
	g_stepUse[Cpu] = STEP_IDLE;
	if (use == STEP_REHIDE)
	{
		HookSwitchView(Vmcb, Cpu, GNPT_VIEW_HIDE);
	}
	else if (use == STEP_READ_TRANS)
	{
		HookSwitchView(Vmcb, Cpu, (ULONG)g_stepRetView[Cpu]);
	}
	else if (use == STEP_TEMP_RW)
	{
		ULONG mask = (ULONG)g_stepRwMask[Cpu];
		g_stepRwMask[Cpu] = 0;
		for (ULONG i = 0; mask != 0 && i < GNPT_MAX_HOOKS; i++, mask >>= 1)
		{
			if (mask & 1)
			{
				HookTempRwSet(i, Cpu, FALSE);
			}
		}
		Vmcb->Control.TlbControl = 3;
	}
	Vmcb->Control.InterceptMisc1 &= ~STEP_WINDOW_INTERCEPTS;    //#DB拦截常驻
	if (g_stepTfShadow[Cpu])
	{
		Vmcb->State.Rflags |= RFLAGS_TF;    //影子TF忠实还原(guest自有单步)
	}
	g_npfLoopCnt[Cpu] = 0;
	{
		static volatile LONG s_lkCnt[64] = { 0 };
		LONG ln = InterlockedIncrement(&s_lkCnt[Cpu & 63]);
		if (ln == 1 || (ln & 0xFF) == 0)
		{
			FlRingPush('L', Cpu, (ULONG)use,
				(ULONG64)(ULONG_PTR)Vmcb->State.Rip,
				Vmcb->State.Rflags, 0);
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
		//取指NPF。TRANSPARENT: P(NX)/HIDE(P=0)两视图的取指fault
		//统一→EXEC窗口(切树+TF, #DB切回HIDE; 零PTE写零flush)
		if (hit != NULL)
		{
			if (hit->pub.Flags & HOOK_TRANSPARENT)
			{
				HookSwitchView(Vmcb, Cpu, GNPT_VIEW_EXEC);
				HookStepArm(Vmcb, Cpu, STEP_REHIDE,
					(ULONG)(hit - g_hooks));
				return TRUE;
			}
			//常规hook: P态→HOOKS驻留; HOOKS态取指fault
			//理论不可达(CodePage可执行)——防御留痕+切P自愈
			if (g_view[Cpu] == GNPT_VIEW_PRIMARY)
			{
				HookSwitchView(Vmcb, Cpu, GNPT_VIEW_SECONDARY);
				return TRUE;
			}
			FlRingPush('N', Cpu, 0x400, ExitInfo2, ExitInfo1, 0);
			HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
			return TRUE;
		}
		if (g_view[Cpu] != GNPT_VIEW_PRIMARY)
		{
			//非hooked页取指fault: 各驻留树恒等RWX下理论不可达
			//(防御保留)——回P自愈
			HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
			return TRUE;
		}
		return FALSE;    //Primary态非hooked取指fault=未覆盖/异常→留痕
	}
	//TRANSPARENT潜伏态(HIDE)的非取指fault(P=0拦数据访问, 读透明):
	//外部读→切P+TF读原始字节(#DB归返HIDE); 外部写→切P惰性落原页。
	//自读/自写不存在于此形态(EXEC窗口内代码跑CodePage全权)
	if (hit != NULL && g_view[Cpu] == GNPT_VIEW_HIDE &&
		(hit->pub.Flags & HOOK_TRANSPARENT))
	{
		g_stepRetView[Cpu] = GNPT_VIEW_HIDE;
		HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
		if ((ExitInfo1 & NPF_ERR_RW) == 0)
		{
			HookStepArm(Vmcb, Cpu, STEP_READ_TRANS, (ULONG)(hit - g_hooks));
		}
		return TRUE;
	}
	//数据NPF(读写fault分流; 仅常规hook可达——
	//TRANSPARENT潜伏态由上分支拦截, EXEC窗口内数据访问不fault):
	//自读/自写判定: faulting RIP与目标同4K页(纯VA比较; 同页⇔代码流
	//在hooked页=hook自身代码, CallOriginal走池页ReplayVA不在此)
	if (hit != NULL && g_view[Cpu] == GNPT_VIEW_SECONDARY)
	{
		ULONG idx = (ULONG)(hit - g_hooks);
		ULONG64 page = (ULONG64)(ULONG_PTR)hit->pub.Target & ~(ULONG64)0xFFF;
		BOOLEAN self = ((Vmcb->State.Rip & ~(ULONG64)0xFFF) == page);
		if (ExitInfo1 & NPF_ERR_RW)
		{
			//写fault
			if (self)
			{
				//自写(代码页自修改): 方案B临时RW+单步(防乒乓死锁)
				HookStepArm(Vmcb, Cpu, STEP_TEMP_RW, idx);
				return TRUE;
			}
			//外部写: M3惰性(切Primary落真实页, 下次取指自愈切回)
			HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
			return TRUE;
		}
		if (!(ExitInfo1 & NPF_ERR_ID))
		{
			//读fault(Secondary的hooked页RW=0)
			if (g_stepUse[Cpu] != STEP_IDLE)
			{
				//armed中嵌套读fault(movs多地址): 只登记临时RW放行本条,
				//不重arm(防用途覆盖丢失)
				HookTempRwSet(idx, Cpu, TRUE);
				Vmcb->Control.TlbControl = 3;
				return TRUE;
			}
			if (self)
			{
				//自读(hook代码读自己页): 方案B——留Secondary+临时RW
				//+单步(方案A会取指NX fault→乒乓死锁)
				HookStepArm(Vmcb, Cpu, STEP_TEMP_RW, idx);
			}
			else
			{
				//外部读(扫描器/PG): 方案A——切Primary+单步, 读到
				//原页原始字节, #DB归返HOOKS(读透明)
				g_stepRetView[Cpu] = GNPT_VIEW_SECONDARY;
				HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
				HookStepArm(Vmcb, Cpu, STEP_READ_TRANS, idx);
			}
			return TRUE;
		}
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
	//多视图PTE布防(静态一次写死, 运行时零PTE写):
	//  P: 原页可读可写不可执行(取指NPF→进detour视图)
	//  常规hook   → HOOKS树=CodePage只读可执行(写NPF→回P转发)
	//  TRANSPARENT→ HIDE树=P=0潜伏 + EXEC树=CodePage全权
	if (Hook->Flags & HOOK_TRANSPARENT)
	{
		SvmNptSetPte(GNPT_VIEW_HIDE, e->TargetPa, e->CodePagePa,
			NPT_PTE_FLAGS_HOOKT_HIDE);
		SvmNptSetPte(GNPT_VIEW_EXEC, e->TargetPa, e->CodePagePa,
			NPT_PTE_FLAGS_HOOKT_EXEC);
	}
	else
	{
		SvmNptSetPte(GNPT_VIEW_SECONDARY, e->TargetPa, e->CodePagePa,
			NPT_PTE_FLAGS_HOOKS);
	}
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
		//②布防树PTE恒等还原(按条目模式: 不触碰未布防树
		//  =不烧无关树的拆分区配额)
		SvmNptRestoreIdentity(GNPT_VIEW_PRIMARY, e->TargetPa);
		if (e->pub.Flags & HOOK_TRANSPARENT)
		{
			SvmNptRestoreIdentity(GNPT_VIEW_HIDE, e->TargetPa);
			SvmNptRestoreIdentity(GNPT_VIEW_EXEC, e->TargetPa);
		}
		else
		{
			SvmNptRestoreIdentity(GNPT_VIEW_SECONDARY, e->TargetPa);
		}
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
