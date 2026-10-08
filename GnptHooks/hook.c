#include"hook.h"
#include"svm.h"
#include"vmcb.h"
#include"npt.h"
#include"LDasm.h"
#include<ntimage.h>      //PE结构体(IMAGE_DOS_HEADER/NT_HEADERS/
                         //SECTION_HEADER/FIRST_SECTION——ntifs/ntddk
                         //链不含, 槽池选址用)

//RtlPcToFileHeader: 本机映像基定位(ntoskrnl导出, wdm.h族未声明
//=显式声明; 与任何在位声明签名兼容, 版本无关)
NTKERNELAPI PVOID RtlPcToFileHeader(
	_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);

//单参包装: 返回Pc所属映像基(NULL=裸内存地址)。原语双参形态
//(PcValue, &BaseOfImage), 成功时出参=映像基; 失败出参未定义=
//预置NULL兜底(调用点一律走本包装)
static PVOID HookImageBaseOf(PVOID Pc)
{
	PVOID base = NULL;
	RtlPcToFileHeader(Pc, &base);
	return base;
}

//====================================================================
// Hook引擎实现(双模式)
//
//普通模式(NPT视图): P视图hooked页NX(取指NPF)→切HOOKS视图=CodePage
//  (目标页副本, 偏移处14B绝对跳转)→跳板槽(mov r10,entry; jmp
//  GnptStubEntry)→GnptStubEntry(hook-asm.asm): SAVE_ALL→
//  GnptCallbackDispatch→用户回调→ret回调用者(rax=回调返回值)。
//  首取指后该核驻留HOOKS=后续调用零exit; 外部读透明/自修改代码
//  由单步机件(STEP_READ_TRANS/STEP_TEMP_RW)承载
//
//TRANSPARENT模式(DR机件): DR0-3线性地址执行断点作入口陷阱,
//  原页恒等不动(零NPT布防); 入口#DB→root改道RIP=跳板槽(同槽
//  同效)。见下方DR-TRANSPARENT机件节
//
//GnptCallOriginal经LDE重定位跳板(视图无关)。
//工件隐蔽(普通模式): Install后CodePage身份PTE两视图改译零页
//  (挂靠自我隐蔽登记表)——guest物理扫描只见零, 补丁签名不可寻;
//  Remove按[布防PTE恒等还原→全核同步→root memcpy还原补丁字节→
//  解除隐蔽(恒等+登记表移除)→全核同步]次序, 各步之间无暴露窗口
//  (补丁存在期间恒被零页翻译掩护)。在途回调安全完成
//  (槽/条目延迟到卸载释放)
//====================================================================

#define HOOK_POOL_TAG        'MemN'     //中性池tag
#define HOOK_SLOT_SIZE       64         //跳板槽(24B机器码+余量)
#define HOOK_SLOT_PER_PAGE   (PAGE_SIZE / HOOK_SLOT_SIZE)
#define HOOK_REPLAY_BUF      96         //重定位跳板缓冲(最坏prologue+尾跳)
#define NPF_SWITCH_LOOP_MAX  16         //同(gpa)连续切换逃生阈值

//root写原语包装(隐蔽配套): 隐蔽生效后guest态直写NPT页=落零页
//静默丢失, Install/Remove(PASSIVE guest态)的PTE写必经vmmcall进
//exit handler(GIF=0 root态直访物理)。exit handler内的写(视图切换/
//临时RW)本就root态, 无需此路
static VOID HookNptSetPteRoot(ULONG View, ULONG64 Gpa, ULONG64 Pa,
	ULONG64 Flags)
{
	CmVmmCall(GNPT_VMCALL_NPTSET, Gpa,
		(Pa & 0x0000FFFFFFFFFFFFULL) | ((ULONG64)View << 48), Flags);
}

static VOID HookNptRestoreRoot(ULONG View, ULONG64 Gpa)
{
	CmVmmCall(GNPT_VMCALL_NPTRES, Gpa, View, 0);
}

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
	PUCHAR CodePageVa;         //目标页补丁副本(TRANSPARENT恒NULL)
	ULONG64 CodePagePa;
	ULONG64 TargetPa;          //目标页物理基址(NPF引擎hooked页判定键;
	                           //TRANSPARENT恒0=不参与NPF匹配)
	UCHAR  DrSlot;             //TRANSPARENT的DR槽号(0-3; 0xFF=普通模式)
} GNPT_ENTRY, *PGNPT_ENTRY;

static GNPT_ENTRY g_hooks[GNPT_MAX_HOOKS];
static volatile LONG g_hookLive = 0;      //已安装未移除数(引擎快速门)
static PUCHAR g_slotPool = NULL;           //跳板槽池(1页, 懒分配)
static volatile LONG g_slotUsed = 0;

//每核当前视图(0=Primary 1=Secondary)
static volatile LONG g_view[64];

//NX-FENCE每核状态(机件节见下方NX-FENCE段): 在途detour旗(入口NPF
//置/stub尾rearm清; 跨核迁移时由GnptCallbackDispatch远程清)+fence页
//邻函数驻留旗(页级NX连坐切HOOKS时置/任意exit信标消费)
static volatile LONG g_nxInDetour[64];
static volatile LONG g_nxFenceRes[64];

//detour上下文环(迁移安全): 每核槽位方案在回调跨核迁移时失配
//(丢调用或误调他hook原函数)。改用全局序号环按发起线程解析——
//同线程顺序执行, 其最大序号条目=当前最内层分发; 嵌套=内层序号
//更大, 跨核迁移天然正确。环深度上界=并发在途回调数(16核×浅
//嵌套<<128); 超环覆写=降级为丢调用(非误调), 概率可忽略
#define HOOK_CTX_RING  128             //2的幂(槽位掩码)
typedef struct _HOOK_CTX
{
	volatile LONG64 seq;            //0=空; 发布序号(最后写=发布点)
	PVOID volatile   thread;        //发起线程(分发期有效)
	PGNPT_ENTRY volatile hook;
	PGUEST_REGS volatile regs;
} HOOK_CTX;
static HOOK_CTX g_ctx[HOOK_CTX_RING];
static volatile LONG64 g_ctxSeq = 0;

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
//
//槽池选址(LBR被动残余缓解): 池页地址必须落在某模块映像范围内
//——guest LBR栈记录目标→槽的jmp, 分支目标=池地址; 池地址在
//裸内存区(ExAllocatePool返回的系统VA区无模块归属)=任何正常
//系统都不存在的分支目标形态=LBR栈扫描指纹。槽池挂靠模块后
//分支目标=模块内地址=与正常调用形态不可区分。挂靠失败
//(无可用洞)=回退池分配(fail-open: 功能保全, LBR残余在)
static PUCHAR HookSlotPoolAlloc(VOID)
{
	//候选: 本驱动映像(节尾对齐空隙)。映像基=RtlPcToFileHeader
	//(本函数地址属于映像)——槽池落本驱动映像范围内即达"模块
	//归属"目的(检测者无法区分是哪个模块的code cave)。驱动
	//映像大小由SectionAlignment界(4KB), 实际映像尾与PE声明
	//SizeOfImage间=驻留洞; 运行期以映像头SizeOfImage字段
	//自证边界, 洞搜索=映像尾页的页内余量
	PUCHAR base = (PUCHAR)HookImageBaseOf((PVOID)HookSlotPoolAlloc);
	if (base != NULL)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
		if (dos->e_magic == IMAGE_DOS_SIGNATURE)
		{
			PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)
				(base + dos->e_lfanew);
			if (nt->Signature == IMAGE_NT_SIGNATURE &&
				nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			{
				//末节尾部碎片: 节对齐后通常无整页洞——常态走池
				//回退; 判据在=形态自适应(链接器布局变化时自动挂靠)
				PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
				PIMAGE_SECTION_HEADER last =
					&sec[nt->FileHeader.NumberOfSections - 1];
				ULONG lastEnd = last->VirtualAddress + last->Misc.VirtualSize;
				ULONG lastAligned = (lastEnd + nt->OptionalHeader.SectionAlignment - 1) &
					~(nt->OptionalHeader.SectionAlignment - 1);
				ULONG tailGap = lastAligned - lastEnd;
				ULONG imgSize = nt->OptionalHeader.SizeOfImage;
				//整页洞条件: 尾节页内碎片≥1页且洞全在SizeOfImage内
				//(理论常态不成立——保底判据, 命中即用)
				if (tailGap >= PAGE_SIZE && lastAligned <= imgSize)
				{
					return base + lastEnd;
				}
			}
		}
	}
	return (PUCHAR)ExAllocatePoolWithTag(
		NonPagedPool, PAGE_SIZE, HOOK_POOL_TAG);
}

static PUCHAR HookAllocSlot(PGNPT_ENTRY Entry)
{
	if (g_slotPool == NULL)
	{
		g_slotPool = HookSlotPoolAlloc();
		if (g_slotPool == NULL)
		{
			return NULL;
		}
		//挂靠形态(映像尾页): 槽码落映像范围内=模块归属达成;
		//池形态: 首槽清零(池页语义); 挂靠页本为零区不动
		if (HookImageBaseOf((PVOID)g_slotPool) == NULL)
		{
			RtlZeroMemory(g_slotPool, PAGE_SIZE);
		}
		FlLog("[Hook] 槽池选址: %p(%s)",
			g_slotPool,
			(HookImageBaseOf((PVOID)g_slotPool) != NULL) ?
			"模块映像code cave=LBR指纹缓解" : "池分配(挂靠失败回退)");
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
	//分发面包屑(触发链定位用; Release构建零开销)
	{
		static volatile LONG s_dispCnt[64] = { 0 };
		GNPT_CRUMB(s_dispCnt, 0xFFF, cpu,
			FlRingPush('H', cpu, 0, (ULONG64)(ULONG_PTR)e->pub.Target,
				(ULONG64)gnCrumb, 0));
	}
	//发布detour上下文到全局序号环(线程键; seq最后写=发布点,
	//读者以seq双重校验条目未被覆写/回收)
	LONG64 mySeq = InterlockedIncrement64(&g_ctxSeq);
	HOOK_CTX* slot = &g_ctx[mySeq & (HOOK_CTX_RING - 1)];
	slot->thread = PsGetCurrentThread();
	slot->hook = e;
	slot->regs = Regs;
	slot->seq = mySeq;
	ULONG64* stackArgs = (e->pub.StackArgs != 0)
		? (ULONG64*)(Regs->rsp + 0x28) : NULL;
	ULONG64 ret = e->pub.Callback(e->pub.Context,
		Regs->rcx, Regs->rdx, Regs->r8, Regs->r9, stackArgs);
	//回收(条目未被环覆写才清; 此时本线程已无扫描者, 清序无害)
	if (slot->seq == mySeq)
	{
		slot->thread = NULL;
		slot->seq = 0;
	}
	//NX-FENCE收尾: 视图回P重武装fence(stub尾ret回调用者前)。
	//入口仅自P视图fault=回P即归位; vmmcall经签名门(外来者#UD),
	//exit全账走TSC补偿壳(两exit之一)。回调异常不返回=旗滞留
	//(该核fence miss, 边界=回调契约)
	//跨核迁移自愈: 回调期间线程迁移(入口核cpu≠当前核)=入口核的
	//在途旗+HOOKS视图滞留(其rearm永不至=beacon被护旗旗永久挡死
	//=该核fence无界miss)。远程清入口核在途旗+置其驻留旗——入口
	//核的下个任意exit信标即回P(fence重武装)。边界: trap→stub首
	//指令间的迁移窗口不在覆盖内(见hook.h纪律9⑤)
	if (e->pub.Flags & HOOK_NXFENCE)
	{
		ULONG curCpu = KeGetCurrentProcessorNumber();
		if (curCpu != cpu && cpu < 64)
		{
			g_nxInDetour[cpu] = 0;    //弃置核在途旗远程清
			g_nxFenceRes[cpu] = 1;    //弃置核驻留旗置=下个exit信标回P
		}
		CmVmmCall(GNPT_VMCALL_NXREARM, 0, 0, 0);
	}
	return ret;
}

ULONG64 GnptCallOriginal(ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4)
{
	ULONG cpu = KeGetCurrentProcessorNumber();
	//解析当前线程最内层分发: 环内该线程最大序号条目(跨核迁移/
	//嵌套均正确; seq双重校验排除覆写与回收竞态)
	PVOID tid = PsGetCurrentThread();
	PGNPT_ENTRY e = NULL;
	PGUEST_REGS regs = NULL;
	LONG64 best = 0;
	for (ULONG i = 0; i < HOOK_CTX_RING; i++)
	{
		HOOK_CTX* s = &g_ctx[i];
		LONG64 sq = s->seq;
		if (sq <= best)
		{
			continue;    //空槽或已有更新条目
		}
		if (s->thread != tid || s->seq != sq)
		{
			continue;    //他线程条目或已被覆写/回收
		}
		best = sq;
		e = s->hook;
		regs = s->regs;
	}
	if (e == NULL)
	{
		//非回调上下文调用(用户误用): 静默返回0+一次性留痕
		//(留痕仅Debug构建; Release无观测面)
#if DBG
		{
			static volatile LONG s_warned = 0;
			if (InterlockedCompareExchange(&s_warned, 1, 0) == 0)
			{
				FlRingPush('w', cpu, 0, 0, 0, 0);
			}
		}
#endif
		return 0;
	}
	//CallOriginal面包屑(触发链定位用; Release构建零开销)
	{
		static volatile LONG s_origCnt[64] = { 0 };
		GNPT_CRUMB(s_origCnt, 0xFFF, cpu,
			FlRingPush('O', cpu, 0, (ULONG64)(ULONG_PTR)e->ReplayVA,
				(ULONG64)gnCrumb, 0));
	}
	if (e->pub.StackArgs != 0 && regs != NULL)
	{
		//StackArgs>0: GnptCallOrigAsm桩重建完整x64调用帧, 栈参源=
		//触发帧上实参(回调可能已改写)
		GNPT_ORIG_CALL oc;
		oc.Target = (ULONG64)e->ReplayVA;
		oc.StackArgs = regs->rsp + 0x28;
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
//本生成器与 DbgTools/test_reloc.c(用户态执行级单测)为镜像契约:
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
static NTSTATUS HookNxFenceInstall(const GNPT_HOOK* Hook);       //前向(定义在NX-FENCE段)
#define RFLAGS_TF               (1ULL << 8)
#define RFLAGS_RF               (1ULL << 16)  //Resume Flag: 压制指令断点一指令(架构位)
#define RFLAGS_FIXED1           (1ULL << 1)
//POPF合法可写位掩码(CF..IOPL..AC..ID; RF弹值忽略, VM/VIF/VIP/NT清0)
#define RFLAGS_POPF_WRITEABLE   0x0000000000243FD7ULL
#define DR6_BS                  (1ULL << 14)   //bit14=单步引发(APM Vol2 §13.1.1.3)
#define STEP_WINDOW_INTERCEPTS  (INTERCEPT_PUSHF | INTERCEPT_POPF)

//单步用途
#define STEP_IDLE               0     //无单步
#define STEP_READ_TRANS         1     //读透明: #DB时切回归返视图(普通模式外部读)
#define STEP_TEMP_RW            2     //临时RW: #DB时撤临时RW页集(视图不动)

//每核单步状态
static volatile LONG g_stepUse[64];        //用途(STEP_*)
static volatile LONG64 g_stepRwMask[64];   //临时RW页集(bit i=g_hooks[i]临时RW中)
static volatile LONG64 g_stepTfShadow[64];  //guest TF影子(arm时初始化, popf仿真同步)
static volatile LONG g_stepRetView[64];    //READ_TRANS归返视图(HOOKS)
static volatile LONG g_stepArmIntn[64];    //arm时步进指令=INTn(0xCD): 收尾须清int帧内注入TF
//NPF乒乓计数('X'风暴逃生探针用, 仅Debug构建读写; #DB收尾与泄漏
//收口复位防误触)
static ULONG64 g_lastNpfGpa[64];
static ULONG g_npfLoopCnt[64];

//hooked页PTE临时RW开/撤(临时RW; 调用方统一置TlbControl=3)
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
		g_stepRwMask[Cpu] |= (LONG64)(1ULL << HookIdx);
	}
	else
	{
		SvmNptSetPte(GNPT_VIEW_SECONDARY, e->TargetPa, e->CodePagePa,
			NPT_PTE_FLAGS_HOOKS);
		g_stepRwMask[Cpu] &= ~(LONG64)(1ULL << HookIdx);
	}
}

//arm单步: 注入TF+开窗口拦截(READ_TRANS切视图由调用方先行)
static VOID HookStepArm(PVMCB Vmcb, ULONG Cpu, LONG Use, ULONG HookIdx)
{
	g_stepTfShadow[Cpu] = (LONG64)((Vmcb->State.Rflags & RFLAGS_TF) >> 8);
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
	//面包屑(扫描器循环读=高频, Release构建零开销)
	{
		static volatile LONG s_armCnt[64] = { 0 };
		GNPT_CRUMB(s_armCnt, 0xFFF, Cpu,
			FlRingPush('s', Cpu, (ULONG)Use, HookIdx,
				(ULONG64)gnCrumb, 0));
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
	//Dr断点#DB(注入回guest无调试接手→0x1E)。BS位随窗口一并
	//消费(我方注入TF的陷阱, 防DrBpDbExit的guest投递路径误投);
	//BS状态位入'e'面包屑载荷(b=0:BS=1 TF引发/b=1:BS=0 Dr断点
	//抢入已吞)。guest自身单步(影子TF)嵌套验收场景无此形态,
	//物理机再评
	BOOLEAN bs = (Vmcb->State.Dr6 & DR6_BS) != 0;
	Vmcb->State.Dr6 &= ~DR6_BS;
	//INTn步进收尾: TF-trap落点=int handler首指令(指令已完整执行,
	//int帧已压栈)。帧[+0x10]=RFLAGS(同CPL无SS:RSP槽, §6.14.2)——
	//压入的是活RFLAGS=含注入TF, 不清则handler iret弹回=TF复活进
	//EFLAGS→后续窗口shadow投毒→忠实还原连环泄漏→guest可见#DB
	//(0x3B级)。**不可BS门控**: 嵌套环境可能以DR6.BS=0投递TF陷阱,
	//BS恒假=清洗被跳过。栈=内核栈(window仅hooked页取指可达)
	if (g_stepArmIntn[Cpu])
	{
		*(ULONG64*)(Vmcb->State.Rsp + 0x10) &= ~RFLAGS_TF;
		static volatile LONG s_inCnt[64] = { 0 };
		GNPT_CRUMB(s_inCnt, 0xFF, Cpu,
			FlRingPush('I', Cpu, 0, (ULONG64)(ULONG_PTR)Vmcb->State.Rip,
				*(ULONG64*)(Vmcb->State.Rsp + 0x10), 0));
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
		ULONG64 mask = (ULONG64)g_stepRwMask[Cpu];
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
#if DBG
	g_npfLoopCnt[Cpu] = 0;    //窗口收口=NPF乒乓计数复位(窗口内同gpa不误触[X])
#endif
	{
		static volatile LONG s_finCnt[64] = { 0 };
		//'e': b=0(BS=1 TF引发)/b=1(BS=0 Dr断点抢入已吞)
		GNPT_CRUMB(s_finCnt, 0xFFF, Cpu,
			FlRingPush('e', Cpu, (ULONG)use,
				((Vmcb->State.Dr6 & DR6_BS) != 0) ? 0 : 1,
				(ULONG64)gnCrumb, 0));
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
		GNPT_CRUMB(s_pfCnt, 0xFFF, Cpu,
			FlRingPush('P', Cpu, 0, (ULONG64)(ULONG_PTR)Vmcb->State.Rip,
				(ULONG64)gnCrumb, 0));
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
		GNPT_CRUMB(s_poCnt, 0xFFF, Cpu,
			FlRingPush('p', Cpu, 0, (ULONG64)(ULONG_PTR)Vmcb->State.Rip,
				(ULONG64)gnCrumb, 0));
	}
	return TRUE;
}

//==================== DR-TRANSPARENT机件(TRANSPARENT模式本体) ====================
//DR0-3硬件执行断点(线性地址标记)作入口陷阱。驻留形态=原页恒等
//原始字节(P视图RWX, 外部读=读透明结构性成立, 零exit); 入口取指
//#DB fault(执行前, APM Vol1 §13.1.3)→root改道RIP=跳板槽(与14B
//补丁跳转同栈同效)→detour→回调→GnptCallOriginal(ReplayVA重放
//prologue+尾跳Target+ReplayLen=非断点地址不再触发)→函数体余下
//自原页执行零exit。
//寄存器分工(APM §15.5/§15.8.1/Table C-1): DR0-3不在VMCB=硬件
//持续跨VMRUN(每核一次武装终身有效); DR6/DR7=VMCB guest state
//(引擎全权); MOV DR拦截=逐寄存器位图(VMCB +0x004/+0x006),
//exit code 0x20-0x3F自带方向+寄存器号。
//成本=每次目标调用恰1 exit(AMD结构最优: 无VMFUNC类guest态
//视图切换原语, 入口陷阱≥1 exit为架构下界); 零翻译翻转=op-cache
//类陈旧译码缺陷结构性缺席。
//
//==== DR所有权: guest优先租用制(探测隐蔽性定案) ====
//调试子系统必须对guest"正常工作"(裸机等价)——单步/分支单步/
//硬断/GD被吞或吸收=裸机不可能的hypervisor指纹(检测方以
//"设TF观察#DB是否到达"即可秒杀影子吸收形态)。规则:
//  · guest写DR0-3/DR7只进影子(读=影子, DR7回读恒含bit10 RA1);
//  · 槽位所有权=每核影子DR7启用该槽(L/G位)者归guest: guest
//    启用时硬件DRn装填其影子值(其断点真实可触发), 我方该槽
//    让位(fail-open); guest释放时(DR7写关闭)我方自动重武装;
//  · 我方hook租用guest未启用的槽(逻辑槽位全局分配g_hookDr,
//    每核武装状态按所有权推导);
//  · 探测期让位: 我方BP命中时guest TF置位(单步中)=不改道
//    原指令原地重执行; guest断点同场=忠实投递其#DB并让位
//    该次调用(裸机等价优先于hook命中);
//  · DR7.GD置位后的MOV DR访问=投递#DB(BD位, 硬件GD语义仿真
//    ——MOV DR全拦故硬件GD永不自触发)。
//DR7武装位(slot n的L/G=bit(2n)/(2n+1), R/W n与LEN n恒00=仅执行
//+1B): GD=bit13恒取guest配置; bit10 RA1恒置(裸机回读形态)
#define DR6_BP_MASK          0xFULL        //B0-3=断点条件触发位
#define DR6_BD               (1ULL << 13)  //bit13=GD看守触发
#define DR7_GD               (1ULL << 13)  //DR7 bit13=general detect
//DR槽位表(-1=空): 槽号→hook条目索引(单写者契约下由Install/Remove
//维护; #DB handler只读)
static volatile LONG g_hookDr[4] = { -1, -1, -1, -1 };
//每核MOV DR影子(DR0-7的guest视角值; guest读写只到影子——其
//断点值+配置的权威载体, 硬件装填由所有权规则推导)。DR7影子
//初值=0x400(bit10保留位RA1, 裸机Windows恒读值; 0≠裸机=可检测
//差异)
static ULONG64 g_drShadow[64][8];
//影子DR7裸机初值(bit10 RA1; DR0-6影子恒0=裸机等价)
#define DR7_SHADOW_INIT 0x400ULL

//每核影子初始化(svm.c的SvmFillVmcb DR卫生段调用——发起线程
//裸机上下文, __readdr合法): DR6影子=接管瞬间硬件快照(保留位
//同值, 与VMCB.State.Dr6同源), DR7影子=裸机恒读值0x400(bit10
//RA1)。guest首个读DR6/DR7的MOV DR exit零差异; 写后读=影子幂等
VOID GnptHookDrShadowInit(ULONG Cpu)
{
	if (Cpu < 64)
	{
		g_drShadow[Cpu][6] = __readdr(6);
		g_drShadow[Cpu][7] = DR7_SHADOW_INIT;
	}
}

//DR槽live hook判定(逻辑槽位全局分配; 每核武装状态另行推导)
static BOOLEAN HookDrSlotLive(ULONG Slot, PGNPT_ENTRY* Out)
{
	LONG idx = g_hookDr[Slot];
	if (idx < 0 || idx >= GNPT_MAX_HOOKS)
	{
		return FALSE;
	}
	PGNPT_ENTRY e = &g_hooks[idx];
	if (!e->Used || e->Removed)
	{
		return FALSE;
	}
	if (Out != NULL)
	{
		*Out = e;
	}
	return TRUE;
}

//每核槽所有权: guest iff该核影子DR7启用该槽(L/G位)。guest写
//DR0-3未启用期间=惰性(裸机poke未启用槽无行为效应, 我方同构
//不挤占); DR7启用=占用, DR7释放=归还(我方经合并路径重武装)
static BOOLEAN HookDrSlotGuestOwned(ULONG Cpu, ULONG Slot)
{
	return (g_drShadow[Cpu & 63][7] & (3ULL << (2 * Slot))) != 0;
}

//__writedr/__readdr内建要求寄存器号为编译期常量(MSVC C2841):
//变量槽号统一经本常量分派(调用方契约: 槽号恒0-3)
static VOID HookDrWriteReg(ULONG Slot, ULONG64 Addr)
{
	switch (Slot)
	{
	case 0: __writedr(0, Addr); break;
	case 1: __writedr(1, Addr); break;
	case 2: __writedr(2, Addr); break;
	case 3: __writedr(3, Addr); break;
	default: break;    //越界=防御性忽略(契约外不可达)
	}
}

//每核武装/解除(svm.c的DRSET case调用, root态): guest优先租用制。
//武装: guest占用该槽=让位('f'留痕, 该核fail-open; guest释放时
//经MOV DR7合并路径自动重武装); 否则__writedr+VMCB.Dr7合并置位
//(槽位R/W+LEN强制00=仅执行1B)。解除: 仅清我方位(guest的位/值
//不动; DRn不写=guest可能持有其值, 清使能即惰性)
VOID GnptHookDrArmCore(PVMCB Vmcb, ULONG Cpu, ULONG Slot, BOOLEAN On,
	ULONG64 Addr)
{
	if (On)
	{
		if (HookDrSlotGuestOwned(Cpu, Slot))
		{
			static volatile LONG s_foCnt[64] = { 0 };
			GNPT_CRUMB(s_foCnt, 0xFF, Cpu,
				FlRingPush('f', Cpu & 63, 2, Addr, (ULONG64)gnCrumb, 0));
			return;    //让位: 该核fail-open
		}
		HookDrWriteReg(Slot, Addr);
		Vmcb->State.Dr7 &= ~(0xFULL << (16 + 4 * Slot));
		Vmcb->State.Dr7 |= 0x400ULL | (3ULL << (2 * Slot));
	}
	else
	{
		if (!HookDrSlotGuestOwned(Cpu, Slot))
		{
			Vmcb->State.Dr7 &= ~(3ULL << (2 * Slot));
		}
	}
}

//svm.c的0x41 case入口(单步机件之后调用): DR6位路由+guest #DB
//忠实投递。guest自己的断点/TF陷阱=裸机等价投递(调试子系统
//"正常工作"); 我方断点=改道, 探测期让位。返回TRUE=已处理;
//FALSE=真残余(无B无BS, 调用方吞——我方簿记畸形的最后防线)
BOOLEAN GnptHookDrBpDbExit(PVMCB Vmcb, ULONG Cpu)
{
	ULONG64 b = Vmcb->State.Dr6 & DR6_BP_MASK;
	BOOLEAN bs = (Vmcb->State.Dr6 & DR6_BS) != 0;
	if (b == 0)
	{
		//纯BS=guest自身TF陷阱(单步机件窗口IDLE时到达此处)
		//——忠实投递(trap语义RIP已下一条, TF保持, 影子DR6
		//记BS)。旧形态"IDLE一律吞"会废掉guest单步=裸机不可能
		if (!bs)
		{
			return FALSE;    //真残余→调用方吞
		}
		g_drShadow[Cpu & 63][6] |= DR6_BS;
		Vmcb->State.Dr6 &= ~DR6_BS;
		{
			static volatile LONG s_gdCnt[64] = { 0 };
			GNPT_CRUMB(s_gdCnt, 0xFF, Cpu,
				FlRingPush('a', Cpu & 63, (ULONG)DR6_BS,
					(ULONG64)(ULONG_PTR)Vmcb->State.Rip,
					g_drShadow[Cpu & 63][6], 0));
		}
		Vmcb->Control.EventInj = EVENTINJ_MAKE(1, EVENTINJ_TYPE_EXCP, 0, 0);
		return TRUE;    //trap语义: RIP已下一条, 不推
	}
	//B位分流: guest槽(影子DR7启用)=其断点; 我方槽=我们的hook;
	//其余(陈旧位)=静默消费
	ULONG64 guestB = 0, ourB = 0;
	for (ULONG n = 0; n < 4; n++)
	{
		if ((b & (1ULL << n)) == 0)
		{
			continue;
		}
		if (HookDrSlotGuestOwned(Cpu, n))
		{
			guestB |= 1ULL << n;
		}
		else if (HookDrSlotLive(n, NULL))
		{
			ourB |= 1ULL << n;
		}
	}
	if (guestB != 0)
	{
		//guest断点忠实投递(fault语义: RIP不动TF不动); 我方同场
		//位一并消费=该次调用让位(探测者在目标上下断点时, 裸机
		//形态优先于hook命中)
		g_drShadow[Cpu & 63][6] |= guestB | (bs ? DR6_BS : 0);
		Vmcb->State.Dr6 &= ~(DR6_BP_MASK | DR6_BS);
		{
			static volatile LONG s_gdCnt[64] = { 0 };
			GNPT_CRUMB(s_gdCnt, 0xFF, Cpu,
				FlRingPush('a', Cpu & 63, (ULONG)guestB,
					(ULONG64)(ULONG_PTR)Vmcb->State.Rip,
					g_drShadow[Cpu & 63][6], 0));
		}
		if (ourB != 0)
		{
			static volatile LONG s_foCnt[64] = { 0 };
			GNPT_CRUMB(s_foCnt, 0xFF, Cpu,
				FlRingPush('f', Cpu & 63, 3,
					(ULONG64)(ULONG_PTR)Vmcb->State.Rip,
					(ULONG64)gnCrumb, 0));
		}
		Vmcb->Control.EventInj = EVENTINJ_MAKE(1, EVENTINJ_TYPE_EXCP, 0, 0);
		return TRUE;    //fault语义: 不推RIP
	}
	if (ourB != 0)
	{
		if (Vmcb->State.Rflags & RFLAGS_TF)
		{
			//探测期让位: guest单步中——消费我方位, 原指令原地
			//重执行, 其TF陷阱下一exit自然投递(裸机等价: 单步者
			//看到的是原函数原样执行)。
			//RF必置: B0为fault类(RIP=入口未执行), 静默消费无
			//IRET置RF机会→重执行将再触发我方断点=exit死循环;
			//RF压制指令断点恰一指令(该地址无guest断点——有则
			//guestB路径先行投递), 不影响TF陷阱(RF只压指令断点)
			//→BS照常到达; 裸机对照: TF帧RF恒0, 但此处帧=guest
			//自己的TF trap(RF=0), 我方RF仅驻VMCB.Rflags一指令
			//即硬件自动清, 不入任何guest可见帧
			Vmcb->State.Rflags |= RFLAGS_RF;
			Vmcb->State.Dr6 &= ~(DR6_BP_MASK | DR6_BS);
			{
				static volatile LONG s_foCnt[64] = { 0 };
				GNPT_CRUMB(s_foCnt, 0xFF, Cpu,
					FlRingPush('f', Cpu & 63, 1,
						(ULONG64)(ULONG_PTR)Vmcb->State.Rip,
						(ULONG64)gnCrumb, 0));
			}
			return TRUE;    //不注入不改道: 重执行原指令
		}
		//常规改道: RIP=跳板槽(等价14B补丁跳转), 事件整体消费
		BOOLEAN redirected = FALSE;
		for (ULONG n = 0; n < 4; n++)
		{
			if ((ourB & (1ULL << n)) == 0)
			{
				continue;
			}
			PGNPT_ENTRY e = NULL;
			if (HookDrSlotLive(n, &e) && e->Slot != NULL)
			{
				Vmcb->State.Rip = (ULONG64)(ULONG_PTR)e->Slot;
				redirected = TRUE;
			}
		}
		Vmcb->State.Dr6 &= ~(DR6_BP_MASK | DR6_BS);
		if (redirected)
		{
			//改道面包屑(热靶高频; Release构建零开销)
			static volatile LONG s_drCnt[64] = { 0 };
			GNPT_CRUMB(s_drCnt, 0xFFF, Cpu,
				FlRingPush('y', Cpu & 63, (ULONG)ourB,
					(ULONG64)(ULONG_PTR)Vmcb->State.Rip,
					(ULONG64)gnCrumb, 0));
		}
		return TRUE;
	}
	//仅陈旧位(无主槽位): 静默消费(防御)
	Vmcb->State.Dr6 &= ~(DR6_BP_MASK | DR6_BS);
	return TRUE;
}

//MOV DR手工译码(0F 21读/0F 23写, mod=11; DR=reg域, GPR=rm域):
//DecodeAssists的EXITINFO1[3:0]位亦载GPR号(Table 15-3), 但译码
//自足=不依赖特性, ExitInfo1仅作交叉采样。返回FALSE=非MOV DR
//形态(防御#UD)
static BOOLEAN HookDrDecodeMov(PVMCB Vmcb, ULONG* DrOut,
	ULONG* GprOut, BOOLEAN* WriteOut)
{
	PUCHAR p = (PUCHAR)(ULONG_PTR)Vmcb->State.Rip;
	ULONG i = 0;
	UCHAR rex = 0;
	for (i = 0; i < 4; i++)
	{
		if ((p[i] & 0xF0) == 0x40)
		{
			rex = p[i];    //REX(最后一个生效)
			continue;
		}
		break;
	}
	if (p[i] != 0x0F)
	{
		return FALSE;
	}
	UCHAR op = p[i + 1];
	if (op != 0x21 && op != 0x23)
	{
		return FALSE;
	}
	UCHAR modrm = p[i + 2];
	if ((modrm >> 6) != 3)
	{
		return FALSE;    //MOV DR恒寄存器-寄存器(mod=11)
	}
	ULONG dr = (modrm >> 3) & 7;
	ULONG gpr = modrm & 7;
	if (rex & 0x04)
	{
		dr |= 8;         //REX.R→DR8-15
	}
	if (rex & 0x01)
	{
		gpr |= 8;        //REX.B→R8-15
	}
	*DrOut = dr;
	*GprOut = gpr;
	*WriteOut = (op == 0x23);
	return TRUE;
}

//svm.c的0x20-0x3F分发入口: MOV DR仿真(guest优先租用制)。
//读=影子(DR7回读恒含bit10 RA1=裸机等价); 写DR0-3=仅影子
//(硬件装填延迟到DR7启用的合并点——裸机上DRn值只有配合DR7
//使能才有行为效应, 延迟装填语义不可见, 且poke未启用槽=惰性
//同构); 写DR7=合并重算(guest配置照搬+guest启用槽装填其值+
//我方未挤占槽自动重武装)。DR4/5(CR4.DE=1语义)与DR8-15/非法
//形态=注入#UD。GD置位后的访问=投递#DB(BD)。恒返回TRUE(已处理)
BOOLEAN GnptHookDrMovExit(PVMCB Vmcb, ULONG Cpu, PGUEST_REGS Regs,
	ULONG ExitCode)
{
	//CPL门先行: MOV DR的CPL0特权检查先于一切(Vol1 §13.1.1——
	//CPL>0执行=裸机#GP); 且root直读用户态RIP字节会撞SMAP
	//(无probe的内核态访问用户页=物理#PF), CPL门=译码前置条件
	if (Vmcb->State.Cpl != 0)
	{
		Vmcb->Control.EventInj = EVENTINJ_MAKE(13, EVENTINJ_TYPE_EXCP,
			1, 0);
		FlRingPush('q', Cpu & 63, ExitCode,
			(ULONG64)(ULONG_PTR)Vmcb->State.Rip, 2, 0);
		return TRUE;    //fault语义: 不推RIP
	}
	//GD门(裸机DR7.GD语义): 置位后任何MOV DR访问触发#DB(BD位)。
	//MOV DR全拦=硬件GD永不自触发, 此处仿真投递(反反调试的
	//"调试寄存器看守"探测面); 置位指令本身不触发(先查后更新
	//影子=与裸机时序一致)
	if ((g_drShadow[Cpu & 63][7] & DR7_GD) != 0)
	{
		g_drShadow[Cpu & 63][6] |= DR6_BD;
		FlRingPush('a', Cpu & 63, (ULONG)DR6_BD,
			(ULONG64)(ULONG_PTR)Vmcb->State.Rip,
			g_drShadow[Cpu & 63][6], 0);
		Vmcb->Control.EventInj = EVENTINJ_MAKE(1, EVENTINJ_TYPE_EXCP, 0, 0);
		return TRUE;    //fault语义: 不推RIP(指令未执行)
	}
	ULONG dr = ExitCode & 0xF;
	BOOLEAN isWrite = (ExitCode & 0x10) != 0;
	ULONG gpr = 0;
	BOOLEAN ok = HookDrDecodeMov(Vmcb, &dr, &gpr, &isWrite);
	if (!ok || dr > 7)
	{
		//DR8-15/非法形态: x86无此寄存器——#UD(裸机等价)
		Vmcb->Control.EventInj = EVENTINJ_MAKE(6, EVENTINJ_TYPE_EXCP, 0, 0);
		FlRingPush('q', Cpu & 63, ExitCode,
			(ULONG64)(ULONG_PTR)Vmcb->State.Rip, 0, 0);
		return TRUE;    //fault语义: 不推RIP
	}
	if (dr == 4 || dr == 5)
	{
		//CR4.DE=1(Windows恒置)下DR4/5=别名禁访——#UD
		Vmcb->Control.EventInj = EVENTINJ_MAKE(6, EVENTINJ_TYPE_EXCP, 0, 0);
		FlRingPush('q', Cpu & 63, ExitCode,
			(ULONG64)(ULONG_PTR)Vmcb->State.Rip, 1, 0);
		return TRUE;
	}
	//GUEST_REGS字段序=RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI,R8..R15
	//=x64寄存器号序(ModRM rm编码)——直接数组化索引
	PULONG64 preg = &((ULONG64*)Regs)[gpr];
	if (isWrite)
	{
		g_drShadow[Cpu & 63][dr] = *preg;
		if (dr <= 3)
		{
			//仅影子: 硬件装填延迟到DR7启用合并点(见函数头);
			//该写本身零硬件副作用(poke探测=惰性同构)
		}
		else
		{
			//DR7写=合并重算(guest配置照搬含GD/LE/GE;
			//guest启用槽→硬件DRn装填其影子值(其断点真实可
			//触发); guest未启用且我方live→强制仅执行1B+装填
			//我方地址(释放槽的自动重武装点))
			ULONG64 v = *preg;
			ULONG64 merged = v | 0x400ULL;
			for (ULONG n = 0; n < 4; n++)
			{
				if (v & (3ULL << (2 * n)))
				{
					HookDrWriteReg(n, g_drShadow[Cpu & 63][n]);
				}
				else
				{
					PGNPT_ENTRY e = NULL;
					if (HookDrSlotLive(n, &e))
					{
						merged &= ~(0xFULL << (16 + 4 * n));
						merged |= 3ULL << (2 * n);
						HookDrWriteReg(n, (ULONG64)(ULONG_PTR)e->pub.Target);
					}
				}
			}
			Vmcb->State.Dr7 = merged;
		}
	}
	else
	{
		//读=影子; DR7回读恒含bit10(裸机RA1语义——写0读回
		//0x400; 影子存原始写值+读时置位)
		ULONG64 val = g_drShadow[Cpu & 63][dr];
		if (dr == 7)
		{
			val |= DR7_SHADOW_INIT;
		}
		*preg = val;
		if (gpr == 0)
		{
			//RAX写回契约: exit stub物理丢弃帧rax槽(恢复GPR时
			//跳过, vmrun从VMCB.RAX加载)——目标GPR=RAX时帧槽写
			//无效, 必须写VMCB(否则guest读到exit时刻残留RAX)
			Vmcb->State.Rax = val;
		}
	}
	Vmcb->State.Rip = Vmcb->Control.NRip;    //指令拦截NRIP有效
	                                             //(同PUSHF/POPF仿真样式)
	{
		static volatile LONG s_mvCnt[64] = { 0 };
		GNPT_CRUMB(s_mvCnt, 0x3FF, Cpu,
			FlRingPush('q', Cpu & 63, ExitCode,
				(ULONG64)(ULONG_PTR)Vmcb->State.Rip, (ULONG64)gnCrumb,
				Vmcb->Control.ExitInfo1));
	}
	return TRUE;
}

//KeGenericCallDpc族=未文档化内核导出(WDK无声明, 签名源=ReactOS
//NDK), 显式原型消除隐式声明告警(全核同步/DR武装广播共用)
VOID KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context);
VOID KeSignalCallDpcDone(_In_ PVOID SystemArgument1);
LOGICAL KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

//DR武装/解除全核广播(参数经全局传递=单写者契约): 每核自我
//vmcall(DRSET)→本核exit handler root态__writedr+VMCB.Dr7置/撤位
static volatile LONG64 g_drArmArg1 = 0;
static volatile LONG64 g_drArmArg2 = 0;
//park态降级载体: IPI回调(停泊核只服务中断不跑DPC——KeGenericCallDpc
//对它=永等)。in-guest核执行DRSET; 停泊核跳过(其硬件DR残留由
//下次VMCB init卫生清零兜底, 本会话不再运行guest代码)
static ULONG_PTR NTAPI HookDrArmIpi(ULONG_PTR Ignored)
{
	UNREFERENCED_PARAMETER(Ignored);
	ULONG cpu = KeGetCurrentProcessorNumber();
	if (cpu < 64 && g_svmVcpu[cpu].base.bInGuest)
	{
		(VOID)CmVmmCall(GNPT_VMCALL_DRSET,
			(ULONG64)g_drArmArg1, (ULONG64)g_drArmArg2, 0);
	}
	return 0;
}
static VOID HookDrArmDpc(struct _KDPC* Dpc, PVOID DeferredContext,
	PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	ULONG cpu = KeGetCurrentProcessorNumber();
	if (cpu < 64 && g_svmVcpu[cpu].base.bInGuest)
	{
		(VOID)CmVmmCall(GNPT_VMCALL_DRSET,
			(ULONG64)g_drArmArg1, (ULONG64)g_drArmArg2, 0);
	}
	else
	{
		FlRingPush('j', cpu, GNPT_VMCALL_DRSET, 0, 0, 0);
	}
	if (SystemArgument1)
	{
		KeSignalCallDpcDone(SystemArgument1);
	}
	if (SystemArgument2)
	{
		KeSignalCallDpcSynchronize(SystemArgument2);
	}
}

static VOID HookDrArmBroadcast(ULONG Slot, BOOLEAN On, ULONG64 Addr)
{
	g_drArmArg1 = (LONG64)(Slot | (On ? 0x100 : 0));
	g_drArmArg2 = (LONG64)Addr;
	if (g_gnptParkedMask != 0)
	{
		//park态: DPC对停泊核=永等, 降级IPI(与HookSyncAllCpus同判)
		KeIpiGenericCall(HookDrArmIpi, 0);
		return;
	}
	KeGenericCallDpc(HookDrArmDpc, NULL);
}

//==================== 安装/移除阶段机件 ====================
//阶段号(观测用): 'J'环即时留痕+HB行st=字段——冻结吞掉环尾时,
//冻结后存活的任一HB行仍能指示最后到达阶段(判读锚点)。
//位置约束: 阶段面包屑为安装/移除全路径共享, 必须先于首个
//调用者(DR安装路径)定义
volatile LONG g_gnptHookStage = 0;
static VOID HookStage(ULONG Stage)
{
	g_gnptHookStage = (LONG)Stage;
	FlRingPush('J', (Stage & 0xFF), Stage, 0, 0, 0);
}
//阶段表: 10入口 11CodePage就绪 12钉核 13发布(live++) 14布防
//15隐蔽 16同步 17自证 30移除入口 31布防还原 32同步
//33拷贝 34解除 35同步2 36完成 99回滚
#define HKST_INS_ENTRY    10
#define HKST_INS_CPALLOC  11
#define HKST_INS_PIN      12
#define HKST_INS_LIVE     13
#define HKST_INS_ARMED    14
#define HKST_INS_CONCEAL  15
#define HKST_INS_SYNC1    16
#define HKST_INS_SELFCHK  17
#define HKST_RM_ENTRY     30
#define HKST_RM_ARMED     31
#define HKST_RM_SYNC1     32
#define HKST_RM_MCPY      33
#define HKST_RM_REVEAL    34
#define HKST_RM_SYNC2     35
#define HKST_RM_DONE      36
#define HKST_FAIL         99

//安装阶段步进(诊断, 仅Debug构建驻留一拍): 每阶段的[HB]st=行落盘
//——若再冻结, 冻结前的最后心跳行即冻结阶段(证据在盘不在内存)。
//发布先行(见Install)使步进窗口内fault皆有进展, 步进本身安全。
//Release构建仅记阶段号不睡(安装全速)
#define GNPT_HOOK_STEP_MS  300
static VOID HookStagePaced(ULONG Stage)
{
	HookStage(Stage);
#if DBG
	LARGE_INTEGER w;
	w.QuadPart = -(LONGLONG)GNPT_HOOK_STEP_MS * 10000LL;
	KeDelayExecutionThread(KernelMode, FALSE, &w);
#endif
}

//TRANSPARENT安装的DR路径(GnptHookInstall早期分流): 无CodePage/
//无NPT布防/无工件隐蔽/无热探测——仅DR槽+重定位跳板+跳板槽+全核
//武装。原页零接触=读/写透明结构性成立
static NTSTATUS HookDrInstall(const GNPT_HOOK* Hook)
{
	HookStage(HKST_INS_ENTRY);    //阶段面包屑(无步进: 零混合翻译窗口)
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
	//14B页边界: 重定位跳板与普通模式同源同长(MinLen=14), 越界=拒绝
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
			FlLog("[Hook] Install拒绝: 目标%p已安装(Remove后可重装)",
				Hook->Target);
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
	//DR槽分配(每核≤4=DR0-3硬件数, fail-loud)
	LONG slot = -1;
	for (LONG s = 0; s < 4; s++)
	{
		if (g_hookDr[s] < 0)
		{
			slot = s;
			break;
		}
	}
	if (slot < 0)
	{
		FlLog("[Hook] Install拒绝: DR槽满(每核上限4个TRANSPARENT hook)");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(e, sizeof(GNPT_ENTRY));
	e->pub = *Hook;
	e->Used = 1;
	e->Removed = 0;
	e->DrSlot = (UCHAR)slot;
	//LDE重定位跳板(MinLen=14: 入口指令从未执行, CallOriginal重放
	//覆盖字节后尾跳Target+ReplayLen=非断点地址不再触发)
	e->ReplayVA = HookBuildRelocTrampoline((ULONG64)Hook->Target, 14,
		&e->ReplayLen);
	if (e->ReplayVA == NULL)
	{
		e->Used = 0;
		e->DrSlot = 0xFF;
		FlLog("[Hook] Install失败: 目标%p prologue不可重定位(见[Reloc]行)",
			Hook->Target);
		return STATUS_UNSUCCESSFUL;
	}
	e->Slot = HookAllocSlot(e);
	if (e->Slot == NULL)
	{
		ExFreePoolWithTag(e->ReplayVA, HOOK_POOL_TAG);
		e->Used = 0;
		e->DrSlot = 0xFF;
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	//发布: live++(卸载/RemoveAll账目)+槽占位先行, 武装广播随后
	InterlockedIncrement(&g_hookLive);
	g_hookDr[slot] = (LONG)(e - g_hooks);
	HookStage(HKST_INS_LIVE);
	HookDrArmBroadcast((ULONG)slot, TRUE, (ULONG64)(ULONG_PTR)Hook->Target);
	HookStage(HKST_INS_ARMED);
	FlLog("[Hook] Install OK(DR槽%u): 目标=%p 回调=%p 跳板槽=%p "
		"重定位跳板=%p(%uB) 原页恒等不动 栈参=%u",
		(ULONG)slot, Hook->Target, Hook->Callback, e->Slot, e->ReplayVA,
		e->ReplayLen, Hook->StackArgs);
	return STATUS_SUCCESS;
}

//TRANSPARENT移除的DR路径(GnptHookRemove分流): 解除广播+槽释放。
//在途改道已过RIP改写(原子), Slot/Replay延迟到卸载释放
static NTSTATUS HookDrRemove(PGNPT_ENTRY e)
{
	HookStage(HKST_RM_ENTRY);
	ULONG slot = e->DrSlot;
	HookDrArmBroadcast(slot, FALSE, 0);
	g_hookDr[slot] = -1;
	e->DrSlot = 0xFF;
	e->Removed = 1;
	InterlockedDecrement(&g_hookLive);
	HookStage(HKST_RM_DONE);
	FlLog("[Hook] Remove OK(DR槽%u): 目标=%p 全核解除+槽释放"
		"(在途回调安全完成)", slot, e->pub.Target);
	return STATUS_SUCCESS;
}

//==================== NX-FENCE机件(HOOK_NXFENCE容量位) ====================
//PG安全+无限容量的第三模式: 目标页P视图置NX(可读可写不可执行),
//HOOKS视图保持恒等RWX(零PTE写)。入口取指NPF(P视图)→root改道
//RIP=跳板槽+切HOOKS(detour/CallOriginal/函数体自HOOKS执行);
//回调返回前经CmVmmCall(NXREARM)回P=fence重新武装。稳态2 exit/
//调用。零工件(无CodePage无补丁字节, 两视图皆原始字节=读透明
//结构性成立, PG覆盖目标可用)。边界见hook.h使用纪律9
//每核状态数组见文件头(g_nxInDetour/g_nxFenceRes)

//svm.c的NXREARM case入口(stub尾vmmcall, GIF=0上下文): 在途detour
//收尾——清旗+视图回P(入口仅自P视图fault=回P即归位)。旗不在=
//移除后补发等竞态形态: 静默(调用方仅推进RIP)
VOID GnptHookNxRearm(PVMCB Vmcb, ULONG Cpu)
{
	if (g_nxInDetour[Cpu & 63] != 0)
	{
		g_nxInDetour[Cpu & 63] = 0;
		HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
		{
			static volatile LONG s_reCnt[64] = { 0 };
			GNPT_CRUMB(s_reCnt, 0xFFF, Cpu,
				FlRingPush('r', Cpu & 63, 0,
					(ULONG64)(ULONG_PTR)Vmcb->State.Rip,
					(ULONG64)gnCrumb, 0));
		}
	}
}

//svm.c的exit外壳统一信标(先于CPUID短路): fence页邻函数执行曾
//驻留HOOKS(旗在)且无在途detour→回P(fence重新武装)。任意exit皆
//信标(CPUID/MSR等常规流量秒级必达)=miss窗口有界; 在途detour护旗
//(其中段exit不得翻视图——函数体自HOOKS执行)
VOID GnptHookNxBeacon(PVMCB Vmcb, ULONG Cpu)
{
	if (g_nxFenceRes[Cpu & 63] == 0 || g_nxInDetour[Cpu & 63] != 0)
	{
		return;
	}
	g_nxFenceRes[Cpu & 63] = 0;
	if (g_view[Cpu & 63] != GNPT_VIEW_PRIMARY)
	{
		HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
		{
			static volatile LONG s_bcCnt[64] = { 0 };
			GNPT_CRUMB(s_bcCnt, 0xFFF, Cpu,
				FlRingPush('A', Cpu & 63, 0,
					(ULONG64)(ULONG_PTR)Vmcb->State.Rip,
					(ULONG64)gnCrumb, 0));
		}
	}
}

//==================== NPF视图切换引擎(svm.c exit handler调用) ====================
//返回TRUE=已处理(重入guest); FALSE=未处理(异常留痕由调用方)

//写VMCB切换视图(两视图ASID配对): NCr3+ASID同写——TLB条目按
//ASID tag(§15.25.1), 两套翻译并存互不命中, 切换零flush零PTE写
//(§15.16同ASID改翻译才须flush, 留给临时RW/NPTSYNC)。
//clean bits全0=两字段每轮vmrun必从VMCB加载, 写即生效
static const ULONG k_viewAsid[GNPT_VIEW_COUNT] = {
	NPT_ASID_PRIMARY, NPT_ASID_SECONDARY
};

static VOID HookSwitchView(PVMCB Vmcb, ULONG Cpu, ULONG View)
{
	View &= (GNPT_VIEW_COUNT - 1);
	Vmcb->Control.NCr3 = SvmNptViewNcr3(View);
	Vmcb->Control.GuestAsid = k_viewAsid[View];
	g_view[Cpu] = (LONG)View;
	//视图切换面包屑(触发链定位用; Release构建零开销)
	{
		static volatile LONG s_swCnt[64] = { 0 };
		GNPT_CRUMB(s_swCnt, 0xFFF, Cpu,
			FlRingPush('V', Cpu, 0, (ULONG64)View,
				(ULONG64)gnCrumb, 0));
	}
}

//svm.c每exit首查: 单步窗口泄漏防御收口。
//泄漏形态: 步进指令属清/搬运TF类(syscall清TF/sysret-iret弹回值,
//按设计不拦)→#DB永不到达→PUSHF/POPF/#DB拦截位永久泄漏→
//全系统pushf/popf exit风暴+兜底"推进"跳过指令的标志/栈效应
//=guest状态破坏(0x1E级)。
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
	if (use == STEP_READ_TRANS)
	{
		HookSwitchView(Vmcb, Cpu, (ULONG)g_stepRetView[Cpu]);
	}
	else if (use == STEP_TEMP_RW)
	{
		ULONG64 mask = (ULONG64)g_stepRwMask[Cpu];
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
#if DBG
	g_npfLoopCnt[Cpu] = 0;    //'X'探针簿记复位(窗口内同gpa不误触)
#endif
	{
		static volatile LONG s_lkCnt[64] = { 0 };
		GNPT_CRUMB(s_lkCnt, 0xFF, Cpu,
			FlRingPush('L', Cpu, (ULONG)use,
				(ULONG64)(ULONG_PTR)Vmcb->State.Rip,
				Vmcb->State.Rflags, 0));
	}
}

BOOLEAN GnptHookNpfEngine(PVMCB Vmcb, ULONG Cpu, ULONG64 ExitInfo1, ULONG64 ExitInfo2)
{
	if (g_hookLive == 0)
	{
		//无live hook≠无布防痕迹: 最后一个hook刚被移除的微窗口内,
		//他核陈旧翻译(残留NX项)的fault仍会到达——非P视图回P,
		//P视图冲净后重执行(fault语义留痕给真fault)。不处理=该核在
		//'N'路径(不推RIP不冲净)无限重试=单核冻结
		if (g_view[Cpu] != GNPT_VIEW_PRIMARY)
		{
			HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
			return TRUE;
		}
		Vmcb->Control.TlbControl = 3;
		return FALSE;
	}
	//hooked页判定(物理页基址键; TargetPa=0=TRANSPARENT条目
	//不参与NPT匹配, 非零匹配同时防御gpa 0的病理性fault误配)
	ULONG64 gpaPage = ExitInfo2 & ~(ULONG64)0xFFF;
	PGNPT_ENTRY hit = NULL;
	if (gpaPage != 0)
	{
		for (ULONG i = 0; i < GNPT_MAX_HOOKS; i++)
		{
			if (g_hooks[i].Used && !g_hooks[i].Removed &&
				g_hooks[i].TargetPa == gpaPage)
			{
				hit = &g_hooks[i];
				break;
			}
		}
	}
#if DBG
	//风暴逃生探针: 同gpa连续切换超阈值='X'留痕(仍切换, 观测面)
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
#endif
	if (ExitInfo1 & NPF_ERR_ID)
	{
		//取指NPF
		if (hit != NULL)
		{
			//NX-FENCE入口甄别(先于驻留路径; 同页唯一fence安装门
			//→hit即fence条目): 取指fault的RIP精确命中fence入口=
			//入口陷阱——置在途旗+切HOOKS+改道跳板槽(fault语义:
			//RIP=入口未执行, 改道后slot自HOOKS取指)
			if ((hit->pub.Flags & HOOK_NXFENCE) != 0 &&
				(ULONG64)(ULONG_PTR)hit->pub.Target == Vmcb->State.Rip)
			{
				g_nxInDetour[Cpu] = 1;
				HookSwitchView(Vmcb, Cpu, GNPT_VIEW_SECONDARY);
				Vmcb->State.Rip = (ULONG64)(ULONG_PTR)hit->Slot;
#if DBG
				g_npfLoopCnt[Cpu] = 0;    //fence稳态同gpa高频fault=合法形态, 防'X'误触
#endif
				{
					static volatile LONG s_fxCnt[64] = { 0 };
					GNPT_CRUMB(s_fxCnt, 0xFFF, Cpu,
						FlRingPush('k', Cpu, 0x400,
							(ULONG64)(ULONG_PTR)Vmcb->State.Rip,
							ExitInfo2, 0));
				}
				return TRUE;
			}
			//常规hook: P态→HOOKS驻留(该核后续取指零exit);
			//HOOKS态取指fault理论不可达(CodePage可执行)——
			//防御留痕+切P自愈
			if (g_view[Cpu] == GNPT_VIEW_PRIMARY)
			{
				HookSwitchView(Vmcb, Cpu, GNPT_VIEW_SECONDARY);
				//fence页邻函数驻留(页级NX连坐): 置旗=下个任意
				//exit信标回P重武装fence(miss窗口=exit间隔)
				if (hit->pub.Flags & HOOK_NXFENCE)
				{
					g_nxFenceRes[Cpu] = 1;
				}
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
		//P态非hooked取指fault: 恒等树(512GB覆盖)下唯一现实来源=
		//布防解除竞态的残留NX翻译(移除后本核陈旧TLB)——冲净本核
		//重执行(已恢复的恒等RWX直通); 持续fault由'X'环路计数限流
		//留痕(真实未覆盖fault本就不可恢复, 行为不变劣)
		Vmcb->Control.TlbControl = 3;
		return TRUE;
	}
	//数据NPF(读写fault分流; 仅常规hook可达):
	//自读/自写判定: faulting RIP与目标同4K页(纯VA比较; 同页<=>代码流
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
				//自写(代码页自修改): 临时RW+单步(防乒乓死锁)
				HookStepArm(Vmcb, Cpu, STEP_TEMP_RW, idx);
				return TRUE;
			}
			//外部写: 惰性处理(切Primary落真实页, 下次取指自愈切回)
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
				//自读(hook代码读自己页): 留Secondary+临时RW+单步
				//(READ_TRANS会取指NX fault→乒乓死锁)
				HookStepArm(Vmcb, Cpu, STEP_TEMP_RW, idx);
			}
			else
			{
				//外部读(扫描器/PG): 切Primary+单步, 读到原页
				//原始字节, #DB归返HOOKS(读透明)
				g_stepRetView[Cpu] = GNPT_VIEW_SECONDARY;
				HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
				HookStepArm(Vmcb, Cpu, STEP_READ_TRANS, idx);
			}
			return TRUE;
		}
	}
	//非Primary视图的非hooked数据fault: 布防解除(移除)竞态的
	//陈旧翻译形态——回P(切视图即冲净)重执行; P树512GB恒等下再fault
	//=真异常('N'路径留痕)。不补此分支=陈旧翻译上无限重试=单核活锁
	if (g_view[Cpu] != GNPT_VIEW_PRIMARY)
	{
		HookSwitchView(Vmcb, Cpu, GNPT_VIEW_PRIMARY);
		return TRUE;
	}
	return FALSE;
}

//全核TLB同步: 每核自我vmcall(NPTSYNC)→本核exit handler置
//TLB_CONTROL=3。常态走DPC广播(DISPATCH级)——单核卡死时其余核
//照常运转, 哨兵v2的挂死判定(12s→0xDEADC1DE蓝屏取证)得以开火;
//非in-guest核跳过留痕('j'环)。park态降级IPI: park核停泊循环只
//服务中断不跑DPC, DPC广播对它=永等
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

static VOID HookSyncDpc(struct _KDPC* Dpc, PVOID DeferredContext,
	PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	ULONG cpu = KeGetCurrentProcessorNumber();
	if (cpu < 64 && g_svmVcpu[cpu].base.bInGuest)
	{
		(VOID)CmVmmCall(GNPT_VMCALL_NPTSYNC, 0, 0, 0);
	}
	else
	{
		FlRingPush('j', cpu, GNPT_VMCALL_NPTSYNC, 0, 0, 0);
	}
	if (SystemArgument1)
	{
		KeSignalCallDpcDone(SystemArgument1);
	}
	if (SystemArgument2)
	{
		KeSignalCallDpcSynchronize(SystemArgument2);
	}
}

static VOID HookSyncAllCpus(VOID)
{
	if (g_gnptParkedMask != 0)
	{
		(VOID)KeIpiGenericCall(HookSyncIpi, 0);    //park态: IPI可被停泊核服务
		return;
	}
	KeGenericCallDpc(HookSyncDpc, NULL);
}

NTSTATUS GnptHookInstall(const GNPT_HOOK* Hook)
{
	if (Hook == NULL || Hook->Target == NULL || Hook->Callback == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}
	//模式标志互斥: TRANSPARENT与NXFENCE为不同机件, 同置=参数错误
	if ((Hook->Flags & (HOOK_TRANSPARENT | HOOK_NXFENCE)) ==
		(HOOK_TRANSPARENT | HOOK_NXFENCE))
	{
		FlLog("[Hook] Install拒绝: TRANSPARENT与NXFENCE互斥(目标%p)",
			Hook->Target);
		return STATUS_INVALID_PARAMETER;
	}
	//TRANSPARENT分流(DR机件): 独立路径——无CodePage/无NPT布防/
	//无工件隐蔽, 与普通模式机制正交(可并存, hook.h使用纪律7)
	if (Hook->Flags & HOOK_TRANSPARENT)
	{
		return HookDrInstall(Hook);
	}
	//NX-FENCE分流(容量位): P视图页级NX入口陷阱, 独立路径
	//(无CodePage/无DR/零工件)
	if (Hook->Flags & HOOK_NXFENCE)
	{
		return HookNxFenceInstall(Hook);
	}
	HookStagePaced(HKST_INS_ENTRY);
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
	e->DrSlot = 0xFF;    //普通模式(零值0=合法槽号, 不可默认)
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
	//CodePage: 目标页整页副本+目标偏移14B绝对跳转→槽。
	//Mm连续分配钳NPT覆盖界内——身份PTE改译(工件隐蔽)的前提;
	//常规池在大物理机可落覆盖界外=改译必然失败, 不如分配时即钳
	PHYSICAL_ADDRESS cpLow, cpCeil, cpBound;
	cpLow.QuadPart = 0;
	cpCeil.QuadPart = (LONGLONG)SvmNptCoverageBytes();
	cpBound.QuadPart = 0;
	if (cpCeil.QuadPart == 0)
	{
		cpCeil.QuadPart = 0x7FFFFFFFFF;    //树未建(安装gate已拦, 防御)
	}
	e->CodePageVa = (PUCHAR)MmAllocateContiguousMemorySpecifyCache(
		PAGE_SIZE, cpLow, cpCeil, cpBound, MmCached);
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
	//目标物理覆盖预检: 超NPT覆盖(PML4[0]界)=布防PTE无处落, 静默
	//缺防=永不触发的死hook——fail-loud拒绝
	if (e->TargetPa >= SvmNptCoverageBytes())
	{
		ExFreePoolWithTag(e->ReplayVA, HOOK_POOL_TAG);
		MmFreeContiguousMemory(e->CodePageVa);
		e->Used = 0;
		FlLog("[Hook] Install拒绝: 目标%p物理%llX超NPT覆盖%llX",
			Hook->Target, (unsigned long long)e->TargetPa,
			(unsigned long long)SvmNptCoverageBytes());
		return STATUS_NOT_SUPPORTED;
	}
	//fence同页互斥门(对称): 本Install的恒等还原路径会拔掉同页
	//fence的页级NX布防=fence静默死亡
	for (ULONG i = 0; i < GNPT_MAX_HOOKS; i++)
	{
		PGNPT_ENTRY o = &g_hooks[i];
		if (o->Used && !o->Removed && (o->pub.Flags & HOOK_NXFENCE) != 0 &&
			o->TargetPa == e->TargetPa)
		{
			ExFreePoolWithTag(e->ReplayVA, HOOK_POOL_TAG);
			MmFreeContiguousMemory(e->CodePageVa);
			e->Used = 0;
			FlLog("[Hook] Install拒绝: 目标%p与fence hook%p同页"
				"(普通模式恒等还原会拔掉fence页级NX)",
				Hook->Target, o->pub.Target);
			return STATUS_UNSUCCESSFUL;
		}
	}
	HookStagePaced(HKST_INS_CPALLOC);
	//root原语前置: 钉到虚拟化核集(SMT隔离下裸机兄弟核
	//vmmcall=#UD→0x7E); 完事还原亲和
	KAFFINITY oldAff = SvmPinVirtualizedCpus();
	if (oldAff == 0)
	{
		MmFreeContiguousMemory(e->CodePageVa);
		ExFreePoolWithTag(e->ReplayVA, HOOK_POOL_TAG);
		e->Used = 0;
		FlLog("[Hook] Install失败: 引擎未起(无虚拟化核)");
		return STATUS_NOT_SUPPORTED;
	}
	HookStagePaced(HKST_INS_PIN);
	//发布先行: live++置于首个树写之前。引擎不变量"树内NX=>
	//live>0"——live==0时P态取指fault走零进展分支(冲净不切视图
	//不推RIP), 布防后热页fault即核级陷阱(热Ke*页千次/秒, 窗口
	//毫秒级必中); 发布后窗口内一切fault走正常引擎路径(有进展)。
	//失败回滚路径以Removed CAS对称递减
	InterlockedIncrement(&g_hookLive);
	HookStagePaced(HKST_INS_LIVE);
	//多视图PTE布防(静态一次写死, 运行时零PTE写; root原语=隐蔽生效):
	//  P: 原页可读可写不可执行(取指NPF→进detour视图)
	//  HOOKS树=CodePage只读可执行(写NPF→回P转发)
	HookNptSetPteRoot(GNPT_VIEW_SECONDARY, e->TargetPa, e->CodePagePa,
		NPT_PTE_FLAGS_HOOKS);
	HookNptSetPteRoot(GNPT_VIEW_PRIMARY, e->TargetPa, e->TargetPa,
		NPT_PTE_FLAGS_HOOKP);
	//布防即刻全核同步: PTE组写完→IPI全核TLB冲净。把同步推迟(步进轮
	//窗口)会让系统处于混合翻译态(陈旧TLB核跑原代码/新鲜walk核跑补丁
	//翻译/P-HOOKS不对称/拆分PDE刚换)——实测崩溃形态为SECONDARY常留核
	//在窗口内对新arm页的首次取指-数据读序列收到not-present fault
	//(软件侧任何可达状态均不可推导)。窗口压缩到IPI广播延迟(~百µs)
	//后, 混合态不再可观察
	HookSyncAllCpus();
	HookStagePaced(HKST_INS_ARMED);
	//CodePage工件隐蔽(root原语, 挂靠自我隐蔽登记表): 身份PTE两视图
	//改译零页+登记游标排水(布防拆分新增的页表页一并隐蔽)。自我隐蔽
	//未启用(构建失败继续形态)时跳过——无零页即无工件隐蔽,
	//仅布防同步。失败或自证FAIL=统一回滚: 布防还原+解除登记(幂等)
	//+释放, 无半隐蔽态
	if (SvmNptHideZeroPa() != 0)
	{
		BOOLEAN ok = (CmVmmCall(GNPT_VMCALL_CONCEAL, e->CodePagePa, 0, 0)
			!= 0);
		//隐蔽改译即刻全核生效(同上): 零页改译也是PTE组写,
		//写完即同步, 不留步进级窗口(原延迟到stage16同步, 300ms暴露)
		HookSyncAllCpus();
		HookStagePaced(HKST_INS_CONCEAL);
		if (ok)
		{
			//全核TLB同步=布防+隐蔽一次覆盖, 而后guest态读自证
			HookSyncAllCpus();
			HookStagePaced(HKST_INS_SYNC1);
			ok = (*(volatile ULONG64*)(e->CodePageVa + off) == 0);
			HookStagePaced(HKST_INS_SELFCHK);
			if (ok)
			{
				FlLog("[Hook] CodePage隐蔽自证: 读=0(零页翻译, 工件物理不可见)");
			}
		}
		if (!ok)
		{
			HookStage(HKST_FAIL);
			HookNptRestoreRoot(GNPT_VIEW_PRIMARY, e->TargetPa);
			HookNptRestoreRoot(GNPT_VIEW_SECONDARY, e->TargetPa);
			//对称回滚发布(发布先行): CAS防双重递减
			if (InterlockedCompareExchange(&e->Removed, 1, 0) == 0)
			{
				InterlockedDecrement(&g_hookLive);
			}
			//解除登记(未登记时NPTRES/表移除均幂等无害)+清翻译
			HookNptRestoreRoot(0xF, e->CodePagePa);
			SvmNptConcealRemove(e->CodePagePa);
			HookSyncAllCpus();
			MmFreeContiguousMemory(e->CodePageVa);
			ExFreePoolWithTag(e->ReplayVA, HOOK_POOL_TAG);
			e->Used = 0;
			FlLog("[Hook] Install失败: CodePage隐蔽登记/自证FAIL('c'环留痕)");
			KeSetSystemAffinityThread(oldAff);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	else
	{
		HookSyncAllCpus();    //布防即刻生效(无隐蔽面形态)
	}
	FlLog("[Hook] Install OK: 目标=%p 回调=%p 跳板槽=%p 重定位跳板=%p(%uB) CodePage=%p(PA=%llX) 栈参=%u",
		Hook->Target, Hook->Callback, e->Slot, e->ReplayVA, e->ReplayLen,
		e->CodePageVa, e->CodePagePa, Hook->StackArgs);
	KeSetSystemAffinityThread(oldAff);
	return STATUS_SUCCESS;
}

//NX-FENCE安装(GnptHookInstall分流): 重定位跳板+跳板槽+P视图页级
//NX布防+全核同步。无CodePage/无工件隐蔽/无DR——零工件PG安全,
//容量仅受条目数限(同页唯一=页级NX共享资产)
static NTSTATUS HookNxFenceInstall(const GNPT_HOOK* Hook)
{
	HookStage(HKST_INS_ENTRY);
	//安装gate: 引擎运行中(同DR/普通)
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
	//14B页边界(重定位跳板同源同长)
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
			FlLog("[Hook] Install拒绝: 目标%p已安装(Remove后可重装)",
				Hook->Target);
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
	//目标物理页+覆盖预检(同普通模式)
	ULONG64 pa = MmGetPhysicalAddress(
		(PVOID)((ULONG_PTR)Hook->Target & ~(ULONG_PTR)(PAGE_SIZE - 1))).QuadPart;
	if (pa >= SvmNptCoverageBytes())
	{
		FlLog("[Hook] Install拒绝: 目标%p物理%llX超NPT覆盖%llX",
			Hook->Target, (unsigned long long)pa,
			(unsigned long long)SvmNptCoverageBytes());
		return STATUS_NOT_SUPPORTED;
	}
	//同页互斥门(fail-loud): 页级NX为共享资产——同页任何live hook
	//(普通模式布防的恒等还原/另一fence的还原判定)与其冲突
	for (ULONG i = 0; i < GNPT_MAX_HOOKS; i++)
	{
		PGNPT_ENTRY o = &g_hooks[i];
		if (o->Used && !o->Removed && o->TargetPa == pa)
		{
			FlLog("[Hook] Install拒绝: 目标%p与已装hook%p同页"
				"(fence页级NX=共享资产, 同页唯一)",
				Hook->Target, o->pub.Target);
			return STATUS_UNSUCCESSFUL;
		}
	}
	RtlZeroMemory(e, sizeof(GNPT_ENTRY));
	e->pub = *Hook;
	e->Used = 1;
	e->Removed = 0;
	e->DrSlot = 0xFF;    //非DR模式
	e->TargetPa = pa;
	e->ReplayVA = HookBuildRelocTrampoline((ULONG64)Hook->Target, 14,
		&e->ReplayLen);
	if (e->ReplayVA == NULL)
	{
		e->Used = 0;
		FlLog("[Hook] Install失败: 目标%p prologue不可重定位(见[Reloc]行)",
			Hook->Target);
		return STATUS_UNSUCCESSFUL;
	}
	e->Slot = HookAllocSlot(e);
	if (e->Slot == NULL)
	{
		ExFreePoolWithTag(e->ReplayVA, HOOK_POOL_TAG);
		e->Used = 0;
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	//root原语前置: 钉到虚拟化核集(P视图PTE写经vmmcall)
	KAFFINITY oldAff = SvmPinVirtualizedCpus();
	if (oldAff == 0)
	{
		ExFreePoolWithTag(e->ReplayVA, HOOK_POOL_TAG);
		e->Used = 0;
		FlLog("[Hook] Install失败: 引擎未起(无虚拟化核)");
		return STATUS_NOT_SUPPORTED;
	}
	//发布先行(live++先于树写, 同普通模式不变量)
	InterlockedIncrement(&g_hookLive);
	HookStage(HKST_INS_LIVE);
	//P视图布防: 原页RW|NX(取指NPF入口陷阱)。HOOKS树保持恒等
	//RWX零PTE写(detour函数体执行面); 布防即刻全核同步(混合
	//翻译窗口压缩到IPI延迟, 同普通模式纪律)
	HookNptSetPteRoot(GNPT_VIEW_PRIMARY, e->TargetPa, e->TargetPa,
		NPT_PTE_FLAGS_HOOKP);
	HookSyncAllCpus();
	HookStage(HKST_INS_ARMED);
	FlLog("[Hook] Install OK(NX-Fence): 目标=%p 回调=%p 跳板槽=%p "
		"重定位跳板=%p(%uB) 零工件(PG面) 稳态2exit/调用 栈参=%u",
		Hook->Target, Hook->Callback, e->Slot, e->ReplayVA,
		e->ReplayLen, Hook->StackArgs);
	KeSetSystemAffinityThread(oldAff);
	return STATUS_SUCCESS;
}

//NX-FENCE移除(GnptHookRemove分流; 路由已钉核): P视图恒等还原+
//全核同步。在途detour(他核HOOKS执行函数体)不受影响——stub尾
//rearm照常(per-core旗), 页已恒等=回P无害; 槽/条目延迟到卸载释放
static NTSTATUS HookNxFenceRemove(PGNPT_ENTRY e)
{
	HookStage(HKST_RM_ENTRY);
	HookNptRestoreRoot(GNPT_VIEW_PRIMARY, e->TargetPa);
	HookStage(HKST_RM_ARMED);
	HookSyncAllCpus();
	e->Removed = 1;
	InterlockedDecrement(&g_hookLive);
	HookStage(HKST_RM_DONE);
	FlLog("[Hook] Remove OK(NX-Fence): 目标=%p 全核恒等还原+同步"
		"(在途回调安全完成)", e->pub.Target);
	return STATUS_SUCCESS;
}

NTSTATUS GnptHookRemove(PVOID Target)
{
	//root原语前置: 钉到虚拟化核集(还原路径同发NPTRES)
	KAFFINITY oldAff = SvmPinVirtualizedCpus();
	if (oldAff == 0)
	{
		return STATUS_NOT_SUPPORTED;
	}
	for (ULONG i = 0; i < GNPT_MAX_HOOKS; i++)
	{
		PGNPT_ENTRY e = &g_hooks[i];
		if (!e->Used || e->Removed || e->pub.Target != Target)
		{
			continue;
		}
		//NX-FENCE分流(容量位): P视图恒等还原+同步(路由已钉核)
		if (e->pub.Flags & HOOK_NXFENCE)
		{
			NTSTATUS fst = HookNxFenceRemove(e);
			KeSetSystemAffinityThread(oldAff);    //钉核还原(提前返回)
			return fst;
		}
		//TRANSPARENT分流(DR机件): 解除广播+槽释放, 无NPT/CodePage工作
		if (e->DrSlot != 0xFF)
		{
			NTSTATUS dst = HookDrRemove(e);
			KeSetSystemAffinityThread(oldAff);    //钉核还原(提前返回)
			return dst;
		}
		HookStage(HKST_RM_ENTRY);
		//①布防树PTE恒等还原(root原语)
		HookNptRestoreRoot(GNPT_VIEW_PRIMARY, e->TargetPa);
		HookNptRestoreRoot(GNPT_VIEW_SECONDARY, e->TargetPa);
		HookStage(HKST_RM_ARMED);
		//②全核TLB同步: 冲净TargetPa→CodePage翻译——此后无核可取指
		//于CodePage(在途回调已过跳转码, 自槽/重定位跳板运行, 不取指
		//于此), ③的整块改写无跨核撕裂窗口
		HookSyncAllCpus();
		HookStage(HKST_RM_SYNC1);
		//③还原CodePage被覆盖字节(root拷贝原语: 隐蔽生效后guest态
		//直写该页=写fault, 必经exit handler代写)。源=原页(从未被改);
		//长度钳页尾(重定位覆盖长可跨页界, 越界=池损坏)
		ULONG off = (ULONG)((ULONG_PTR)Target & (PAGE_SIZE - 1));
		ULONG len = e->ReplayLen;
		if (len > PAGE_SIZE - off)
		{
			len = PAGE_SIZE - off;    //补丁14B必在页内, 钳位不伤补丁区
		}
		BOOLEAN cpOk = (CmVmmCall(GNPT_VMCALL_MEMCPY,
			(ULONG64)(e->CodePageVa + off), (ULONG64)(ULONG_PTR)Target,
			len) != 0);
		HookStage(HKST_RM_MCPY);
		//④解除CodePage隐蔽(释放前必做——PFN此后可归池复用, 残留
		//零页翻译落新拥有者=读零损坏): 两树恒等+登记表移除。
		//拷贝被拒(仅理论: len∈(0,4KB]恒成立)时保持隐蔽=补丁字节
		//不外泄; PFN归池前树已释放(卸载契约), 无复用风险
		BOOLEAN revealed = FALSE;
		if (cpOk)
		{
			if (SvmNptHideZeroPa() != 0)
			{
				HookNptRestoreRoot(0xF, e->CodePagePa);
				SvmNptConcealRemove(e->CodePagePa);
			}
			revealed = TRUE;    //无隐蔽面形态: 本无登记, 直接视为已解除
		}
		else
		{
			FlLog("[Hook] Remove异常: CodePage字节还原被拒('M'环留痕), 保持隐蔽");
		}
		HookStage(HKST_RM_REVEAL);
		//⑤全核TLB同步: 冲净CodePage零页翻译
		HookSyncAllCpus();
		HookStage(HKST_RM_SYNC2);
		//⑥解除自证: 恒等恢复后guest态读=原页真实字节
		{
			ULONG64 s = *(volatile ULONG64*)(e->CodePageVa + off);
			FlLog("[Hook] CodePage解除自证: 读=%llX(%s)",
				(unsigned long long)s,
				(revealed && s != 0) ? "非零=还原已生效" :
				revealed ? "零=解除未生效/还原异常(复检'c'环与'M'环)" :
				"零=隐蔽保持(拷贝被拒路径)");
		}
		e->Removed = 1;
		InterlockedDecrement(&g_hookLive);
		HookStage(HKST_RM_DONE);
		FlLog("[Hook] Remove OK: 目标=%p 布防恒等+root还原%uB+%s+全核TLB同步(在途回调安全完成)",
			Target, len, revealed ? "解除工件隐蔽" : "工件隐蔽保持");
		KeSetSystemAffinityThread(oldAff);
		return STATUS_SUCCESS;
	}
	KeSetSystemAffinityThread(oldAff);
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

//枚举live hook(语义与MSR侧一致): Buffer=NULL→*InOutCount=数量;
//容量不足→STATUS_BUFFER_TOO_SMALL并回填所需数量。条目只拷公开
//字段(Removed/内部指针不出)
NTSTATUS GnptHookEnumerate(GNPT_HOOK* Buffer, ULONG* InOutCount)
{
	if (InOutCount == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}
	ULONG cnt = 0;
	for (ULONG i = 0; i < GNPT_MAX_HOOKS; i++)
	{
		if (g_hooks[i].Used && !g_hooks[i].Removed)
		{
			cnt++;
		}
	}
	if (Buffer == NULL)
	{
		*InOutCount = cnt;
		return STATUS_SUCCESS;
	}
	if (cnt > *InOutCount)
	{
		*InOutCount = cnt;
		return STATUS_BUFFER_TOO_SMALL;
	}
	ULONG n = 0;
	for (ULONG i = 0; i < GNPT_MAX_HOOKS; i++)
	{
		if (g_hooks[i].Used && !g_hooks[i].Removed)
		{
			Buffer[n++] = g_hooks[i].pub;
		}
	}
	*InOutCount = cnt;
	return STATUS_SUCCESS;
}

//DriverUnload在关引擎**之后**调用(纯内存释放, 无引擎依赖):
//清零后释放(CodePage跳转码/条目指针不残留给PFN新拥有者)。
//隐蔽生命周期: live条目在Remove已解除; 其余残留条目保持隐蔽到
//此处——关引擎后NPT已释放, PFN归池时零页翻译不存在, 无复用风险
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
			MmFreeContiguousMemory(e->CodePageVa);
			codepages++;
		}
		RtlZeroMemory(e, sizeof(GNPT_ENTRY));
		entries++;
	}
	if (g_slotPool != NULL)
	{
		RtlZeroMemory(g_slotPool, PAGE_SIZE);
		//挂靠形态(映像code cave)=映像内存不可ExFreePool(非法
		//池指针=池损坏), 只清零(映像随驱动卸载整体回收);
		//池形态=正常释放
		if (HookImageBaseOf((PVOID)g_slotPool) == NULL)
		{
			ExFreePoolWithTag(g_slotPool, HOOK_POOL_TAG);
		}
		g_slotPool = NULL;
	}
	g_slotUsed = 0;
	g_hookLive = 0;
	if (entries != 0)
	{
		FlLog("[Hook] FreeMemory: 条目%u个(重定位跳板%u+CodePage%u)"
			"+槽池已清零释放",
			entries, replays, codepages);
	}
}
