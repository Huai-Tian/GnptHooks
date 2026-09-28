#include"npt.h"
#include"svm.h"

//==================== NPT实例状态(四棵静态共享树) ====================
#define NPT_POOL_TAG        'MemN'          //中性池tag
#define NPT_COVER_LIMIT     0x8000000000ULL //512GB覆盖上限(对齐资源分配界)
//页表页数组容量: 4树×514 + 拆分PT页(自我隐蔽: 框架页聚簇后
//~170个2MB区/树, 256拆分区上限覆盖+余量; 含arena块数上限)
#define NPT_MAX_PAGES       (514 * GNPT_VIEW_COUNT + 1024 + 8)
#define NPT_MAX_SPLITS      256             //每树最大拆分区数(2MB区)

//页表页arena(自我隐蔽级联对策: 散池分配每页几乎独占一个2MB帧,
//隐蔽登记拆该帧=登记数级联放大): 页表页从2MB连续块切槽, 同帧
//第二页起零新拆分, 级联坍缩——2056树页+~700拆分PT页聚在~10个
//2MB帧内(vs散池~2000帧)。块数: (2056+1024+8)/512≈7块, 给8块
#define NPT_ARENA_BLOCKS    8
#define NPT_ARENA_SLOTS     512             //2MB/PAGE_SIZE

typedef struct _NPT_SPLIT
{
	ULONG64 Region;      //2MB区基址(已拆分)
	PULONG64 PtVa;        //拆分出的PT页VA(512个4KB条目)
	ULONG64 PtPa;
} NPT_SPLIT, *PNPT_SPLIT;

typedef struct _NPT_TREE
{
	PULONG64  Pml4Va;
	PULONG64  PdptVa;
	PULONG64  PdVa[512];      //PD页: 每页覆盖1GB(512个2MB条目)
	ULONG64   Ncr3;
	NPT_SPLIT Splits[NPT_MAX_SPLITS];
} NPT_TREE, *PNPT_TREE;

//树布局: [0]=P [1]=HOOKS [2]=HIDE [3]=EXEC(全核共享, 静态)
static NPT_TREE  g_nptTree[GNPT_VIEW_COUNT];
static PVOID     g_nptPages[NPT_MAX_PAGES];
static ULONG     g_nptPageCount = 0;
static ULONG64   g_nptCoverage = 0;

//arena块(2MB连续; MmAllocateContiguousMemorySpecifyCache保证物理连续)
static PVOID     g_nptArena[NPT_ARENA_BLOCKS];
static ULONG     g_nptArenaUsed = 0;         //已切槽bump(PASSIVE单线程)

//==== 自我隐蔽登记 ====
//零页: 四视图共享改译目标(guest物理扫描只见零)
static PVOID     s_hideZeroVa = NULL;
static ULONG64   s_hideZeroPa = 0;
//登记表: 已改译零页的框架页gpa(驱动.data, 非隐蔽页, root/guest均
//可读写); 改译循环与诊断API迭代它
#define NPT_CONCEAL_MAX     4096
static ULONG64   s_concealPa[NPT_CONCEAL_MAX];
static ULONG     s_concealCount = 0;
static volatile LONG s_concealHits = 0;      //'O'兜底恢复计数

ULONG64 SvmNptViewNcr3(ULONG View) { return g_nptTree[View & 3].Ncr3; }
ULONG64 SvmNptCoverageBytes(VOID) { return g_nptCoverage; }
ULONG SvmNptPageCount(VOID) { return g_nptPageCount; }

//覆盖范围=min(MAXPHYADDR地址空间, 512GB), 2MB对齐
//MAXPHYADDR=CPUID Fn8000_0008 EAX[7:0]
static ULONG64 SvmNptComputeCoverage(VOID)
{
	int info[4] = { 0 };
	__cpuidex(info, 0x80000008, 0);
	ULONG64 maxPhy = 1ULL << (info[0] & 0xFF);
	ULONG64 cover = (maxPhy < NPT_COVER_LIMIT) ? maxPhy : NPT_COVER_LIMIT;
	return cover & ~(0x200000ULL - 1);
}

//分配一页页表页: 从2MB连续arena块切槽(见头注释;
//同帧第二页起零新拆分)。PASSIVE单线程契约(构建/Install/Conceal)
static PVOID SvmNptAllocPage(PULONG64 paOut)
{
	if (g_nptPageCount >= NPT_MAX_PAGES)
	{
		return NULL;
	}
	//找空槽: 现块满→新块
	if ((g_nptArenaUsed % NPT_ARENA_SLOTS) == 0)
	{
		ULONG blk = g_nptArenaUsed / NPT_ARENA_SLOTS;
		if (blk >= NPT_ARENA_BLOCKS)
		{
			return NULL;    //arena耗尽
		}
		//512GB物理上限, 与svm.c资源分配同界(参数全五元, 物理地址三段)
		PHYSICAL_ADDRESS lowest, ceiling, boundary;
		lowest.QuadPart = 0;
		ceiling.QuadPart = 0x7FFFFFFFFF;
		boundary.QuadPart = 0;
		g_nptArena[blk] = MmAllocateContiguousMemorySpecifyCache(
			NPT_ARENA_SLOTS * PAGE_SIZE, lowest, ceiling, boundary, MmCached);
		if (g_nptArena[blk] == NULL)
		{
			return NULL;
		}
		RtlZeroMemory(g_nptArena[blk], NPT_ARENA_SLOTS * PAGE_SIZE);
	}
	PVOID va = (PUCHAR)g_nptArena[g_nptArenaUsed / NPT_ARENA_SLOTS]
		+ (SIZE_T)(g_nptArenaUsed % NPT_ARENA_SLOTS) * PAGE_SIZE;
	g_nptArenaUsed++;
	g_nptPages[g_nptPageCount++] = va;
	*paOut = MmGetPhysicalAddress(va).QuadPart;
	return va;
}

//构建单棵恒等树(PML4[0]->PDPT单页->512个PD页, PD级2MB大页leaf)
static BOOLEAN SvmNptBuildTree(PNPT_TREE Tree, ULONG64 Cover)
{
	ULONG64 pa = 0;
	Tree->Pml4Va = (PULONG64)SvmNptAllocPage(&pa);
	if (Tree->Pml4Va == NULL)
	{
		return FALSE;
	}
	Tree->PdptVa = (PULONG64)SvmNptAllocPage(&pa);
	if (Tree->PdptVa == NULL)
	{
		return FALSE;
	}
	Tree->Pml4Va[0] = pa | NPT_PTE_FLAGS_INTER;    //顶层链接: PML4[0]→PDPT(缺此=全NPF活锁冻结)
	ULONG64 pdPages = Cover >> 30;    //1GB区数=PD页数
	for (ULONG64 i = 0; i < pdPages; i++)
	{
		Tree->PdVa[i] = (PULONG64)SvmNptAllocPage(&pa);
		if (Tree->PdVa[i] == NULL)
		{
			return FALSE;
		}
		Tree->PdptVa[i] = pa | NPT_PTE_FLAGS_INTER;
		ULONG64 base = i << 30;
		for (ULONG64 k = 0; k < 512; k++)
		{
			Tree->PdVa[i][k] = (base + (k << 21)) | NPT_PTE_FLAGS_LEAF2MB;
		}
	}
	Tree->Ncr3 = MmGetPhysicalAddress(Tree->Pml4Va).QuadPart;
	return TRUE;
}

//==================== 构建(四棵共享) ====================
BOOLEAN SvmBuildNptViews(PULONG64 Ncr3Out,
	PULONG64 CoverOut, PULONG PagesOut)
{
	if (Ncr3Out != NULL)
	{
		RtlZeroMemory(Ncr3Out, sizeof(ULONG64) * GNPT_VIEW_COUNT);
	}
	if (g_nptTree[0].Ncr3 != 0)
	{
		return TRUE;    //已构建(幂等)
	}
	ULONG64 cover = SvmNptComputeCoverage();
	if (cover == 0)
	{
		return FALSE;
	}
	for (ULONG t = 0; t < GNPT_VIEW_COUNT; t++)
	{
		if (!SvmNptBuildTree(&g_nptTree[t], cover))
		{
			SvmFreeNpt();
			return FALSE;
		}
	}
	g_nptCoverage = cover;
	if (Ncr3Out != NULL)
	{
		for (ULONG t = 0; t < GNPT_VIEW_COUNT; t++)
		{
			Ncr3Out[t] = g_nptTree[t].Ncr3;
		}
	}
	if (CoverOut != NULL)
	{
		*CoverOut = cover;
	}
	if (PagesOut != NULL)
	{
		*PagesOut = g_nptPageCount;
	}
	return TRUE;
}

//==================== 4KB拆分与PTE操作 ====================
//定位gpa的PTE槽; 未拆分则现场拆(PT页512条恒等可执行, 再换PDE)。
//树内Split记录线性查找(≤16)
static PULONG64 SvmNptLocatePte(PNPT_TREE Tree, ULONG64 Gpa)
{
	if ((Gpa >> 39) != 0 || (Gpa & 0xFFF) != 0)
	{
		return NULL;    //超出PML4[0]覆盖(512GB界)或未4KB对齐
	}
	ULONG64 pdptIdx = (Gpa >> 30) & 511;
	ULONG64 pdIdx = (Gpa >> 21) & 511;
	ULONG64 region = Gpa & ~(ULONG64)0x1FFFFF;
	PULONG64 pd = Tree->PdVa[pdptIdx];
	if (pd == NULL)
	{
		return NULL;
	}
	ULONG64 ptIdx = (Gpa >> 12) & 511;
	//查找已有拆分
	for (ULONG i = 0; i < NPT_MAX_SPLITS; i++)
	{
		if (Tree->Splits[i].PtVa != NULL && Tree->Splits[i].Region == region)
		{
			return &Tree->Splits[i].PtVa[ptIdx];
		}
	}
	//现场拆分: 分配PT页, 512条4KB恒等(指原物理页, 可读可写可执行)
	ULONG64 pa = 0;
	PULONG64 pt = (PULONG64)SvmNptAllocPage(&pa);
	if (pt == NULL)
	{
		return NULL;
	}
	for (ULONG64 k = 0; k < 512; k++)
	{
		pt[k] = (region + (k << 12)) | NPT_PTE_FLAGS_LEAF4K_RWX;
	}
	//登记拆分记录
	PNPT_SPLIT slot = NULL;
	for (ULONG i = 0; i < NPT_MAX_SPLITS; i++)
	{
		if (Tree->Splits[i].PtVa == NULL)
		{
			slot = &Tree->Splits[i];
			break;
		}
	}
	if (slot == NULL)
	{
		return NULL;    //拆分区满(不会: 条目上限<拆分区上限)
	}
	slot->Region = region;
	slot->PtVa = pt;
	slot->PtPa = pa;
	//换PDE: 去PS位改指PT页(整页写完才换=硬件walker永不观察半填PT)
	pd[pdIdx] = pa | NPT_PTE_FLAGS_INTER;
	return &pt[ptIdx];
}

//把视图内gpa的4KB条目写为 Pa|Flags(现场拆分+置位)。
//仅Install/Remove/临时RW调用——热路径零PTE写
VOID SvmNptSetPte(ULONG View, ULONG64 Gpa, ULONG64 Pa, ULONG64 Flags)
{
	PULONG64 pte = SvmNptLocatePte(&g_nptTree[View & 3], Gpa);
	if (pte != NULL)
	{
		*pte = (Pa & 0x000FFFFFFFFFF000ULL) | Flags;
	}
}

//把视图内gpa的4KB条目恢复恒等(P|RW|US|A|D, 指回原物理页)
VOID SvmNptRestoreIdentity(ULONG View, ULONG64 Gpa)
{
	SvmNptSetPte(View, Gpa, Gpa, NPT_PTE_FLAGS_LEAF4K_RWX);
}

//释放全部页表页(四棵)+arena块; 构建失败路径与卸载共用(幂等)
VOID SvmFreeNpt(VOID)
{
	//arena块整体释放(页表页全在块内, 无独立释放)
	for (ULONG i = 0; i < NPT_ARENA_BLOCKS; i++)
	{
		if (g_nptArena[i] != NULL)
		{
			MmFreeContiguousMemory(g_nptArena[i]);
			g_nptArena[i] = NULL;
		}
	}
	g_nptArenaUsed = 0;
	g_nptPageCount = 0;
	g_nptCoverage = 0;
	RtlZeroMemory(g_nptTree, sizeof(g_nptTree));
	//零页释放(全核已裸机后调用: NPT已无walker, 残留改译无引用)
	if (s_hideZeroVa != NULL)
	{
		MmFreeContiguousMemory(s_hideZeroVa);
		s_hideZeroVa = NULL;
		s_hideZeroPa = 0;
	}
	s_concealCount = 0;
}

//==================== NPT自我隐蔽 ====================
//登记一页gpa(去重线性查; 隐蔽页数~2900, 构建期一次性)
static BOOLEAN SvmNptConcealAdd(ULONG64 Pa)
{
	if ((Pa & 0xFFF) != 0 || Pa == 0)
	{
		return TRUE;    //非物理页基, 跳过
	}
	for (ULONG i = 0; i < s_concealCount; i++)
	{
		if (s_concealPa[i] == Pa)
		{
			return TRUE;    //已登记(arena块页共享同一登记轮)
		}
	}
	if (s_concealCount >= NPT_CONCEAL_MAX)
	{
		return FALSE;
	}
	s_concealPa[s_concealCount++] = Pa;
	return TRUE;
}

//只读查PTE('O'兜底判定): 拆分区返回4KB条目值; 未拆分返回2MB
//大页条目值(调用方比对零页PFN即知是否隐蔽); 非法gpa返回0
ULONG64 SvmNptPeekPte(ULONG View, ULONG64 Gpa)
{
	if ((Gpa >> 39) != 0)
	{
		return 0;
	}
	PNPT_TREE tree = &g_nptTree[View & 3];
	ULONG64 pdptIdx = (Gpa >> 30) & 511;
	ULONG64 pdIdx = (Gpa >> 21) & 511;
	PULONG64 pd = tree->PdVa[pdptIdx];
	if (pd == NULL)
	{
		return 0;
	}
	ULONG64 region = Gpa & ~(ULONG64)0x1FFFFF;
	for (ULONG i = 0; i < NPT_MAX_SPLITS; i++)
	{
		if (tree->Splits[i].PtVa != NULL && tree->Splits[i].Region == region)
		{
			return tree->Splits[i].PtVa[(Gpa >> 12) & 511];
		}
	}
	return pd[pdIdx];    //2MB大页条目
}

//'O'兜底(exit handler): faulting页已隐蔽(gpa∈登记表)→四树恢复
//恒等+计数+留痕。返回TRUE=已处置(重执行=访问自愈)
BOOLEAN SvmNptConcealFaultFix(ULONG64 Gpa)
{
	ULONG64 page = Gpa & ~(ULONG64)0xFFF;
	ULONG64 cur = SvmNptPeekPte(GNPT_VIEW_PRIMARY, page);
	if ((cur & 0x000FFFFFFFFFF000ULL) != s_hideZeroPa || s_hideZeroPa == 0)
	{
		return FALSE;    //非隐蔽页(常规NPF路径)
	}
	for (ULONG v = 0; v < GNPT_VIEW_COUNT; v++)
	{
		SvmNptRestoreIdentity(v, page);
	}
	LONG n = InterlockedIncrement(&s_concealHits);
	if (n == 1 || (n & 0xFF) == 0)
	{
		FlRingPush('o', 0xFF, SVM_EXIT_NPF, page, Gpa, (ULONG64)(ULONG)n);
	}
	return TRUE;
}

//主入口: 全部核资源分配后+首核launch前调用(裸机root态=写NPT页
//直访物理自免疫; 见npt.h时序契约)
BOOLEAN SvmNptConcealAll(VOID)
{
	if (s_hideZeroVa != NULL)
	{
		return TRUE;    //已隐蔽(幂等)
	}
	//零页(内容恒零=Mm连续内存不清零, 显式清; 512GB物理上限同上)
	PHYSICAL_ADDRESS zLow, zCeil, zBound;
	zLow.QuadPart = 0;
	zCeil.QuadPart = 0x7FFFFFFFFF;
	zBound.QuadPart = 0;
	s_hideZeroVa = MmAllocateContiguousMemorySpecifyCache(
		PAGE_SIZE, zLow, zCeil, zBound, MmCached);
	if (s_hideZeroVa == NULL)
	{
		return FALSE;
	}
	RtlZeroMemory(s_hideZeroVa, PAGE_SIZE);
	s_hideZeroPa = MmGetPhysicalAddress(s_hideZeroVa).QuadPart;
	//登记: 每核资源页(VMCB/HSAVE/IOPM 3页/MSRPM 2页/VMM栈4页,
	//全部SvmAllocContig=物理连续, 逐页登)
	ULONG cpus = KeQueryActiveProcessorCount(NULL);
	if (cpus > 64)
	{
		cpus = 64;
	}
	for (ULONG c = 0; c < cpus; c++)
	{
		PGNPT_VCPU_SVM v = &g_svmVcpu[c];
		struct { PVOID va; ULONG pages; } res[] = {
			{ v->VmcbVa, 1 }, { v->HsaveVa, 1 }, { v->IopmVa, 3 },
			{ v->MsrpmVa, 2 }, { v->VmmStack, 4 },
		};
		for (ULONG r = 0; r < 5; r++)
		{
			if (res[r].va == NULL)
			{
				continue;
			}
			for (ULONG p = 0; p < res[r].pages; p++)
			{
				if (!SvmNptConcealAdd(
					MmGetPhysicalAddress((PUCHAR)res[r].va + p * PAGE_SIZE).QuadPart))
				{
					FlLog("NPT: 隐蔽登记溢出(核%u)", c);
					return FALSE;
				}
			}
		}
	}
	//登记: 全部页表页(树页+已拆分PT页, 全在arena块内)
	for (ULONG i = 0; i < g_nptPageCount; i++)
	{
		if (!SvmNptConcealAdd(MmGetPhysicalAddress(g_nptPages[i]).QuadPart))
		{
			FlLog("NPT: 隐蔽登记溢出(页表页%u)", i);
			return FALSE;
		}
	}
	//四树统一改译零页(P|US|A; RW=0=写fault, X=0=执行fault——
	//两路都进'O'兜底; 读=静默零)。改译的PTE写自身会拆分出新PT页
	//(arena槽)——新页也是框架页, 须登记并改译, 迭代到不动点
	//(arena聚簇使新PT页落在已拆分帧内, 收敛快)
	ULONG64 hideFlags = NPT_PTE_P | NPT_PTE_US | NPT_PTE_A;
	ULONG processed = 0;
	ULONG pagesReg = g_nptPageCount;    //已登记页表页游标
	for (ULONG round = 0; round < 8; round++)
	{
		//登记本轮拆分新增的页表页(改译副产物)
		for (ULONG i = pagesReg; i < g_nptPageCount; i++)
		{
			if (!SvmNptConcealAdd(
				MmGetPhysicalAddress(g_nptPages[i]).QuadPart))
			{
				FlLog("NPT: 隐蔽登记溢出(页表页%u)", i);
				return FALSE;
			}
		}
		pagesReg = g_nptPageCount;
		ULONG seen = s_concealCount;
		for (ULONG i = processed; i < seen; i++)
		{
			ULONG64 pa = s_concealPa[i];
			for (ULONG v = 0; v < GNPT_VIEW_COUNT; v++)
			{
				SvmNptSetPte(v, pa, s_hideZeroPa, hideFlags);
			}
		}
		processed = seen;
		if (pagesReg == g_nptPageCount && seen == s_concealCount)
		{
			break;    //不动点: 无新增页表页且无新增登记
		}
	}
	FlRingPush('Z', 0xFF, 0, s_hideZeroPa,
		(ULONG64)s_concealCount, (ULONG64)g_nptPageCount);
	FlLog("NPT: 自我隐蔽完成(%u页改译零页%llX, 页表页%u)",
		s_concealCount, s_hideZeroPa, g_nptPageCount);
	return TRUE;
}

ULONG64 SvmNptHideZeroPa(VOID) { return s_hideZeroPa; }
ULONG SvmNptConcealCount(VOID) { return s_concealCount; }
ULONG SvmNptConcealHits(VOID) { return (ULONG)s_concealHits; }
ULONG64 SvmNptConcealPa(ULONG Index)
{
	return (Index < s_concealCount) ? s_concealPa[Index] : 0;
}
