#include"npt.h"
#include"svm.h"

//==================== NPT实例状态(四棵静态共享树) ====================
#define NPT_POOL_TAG        'MemN'          //中性池tag
#define NPT_COVER_LIMIT     0x8000000000ULL //512GB覆盖上限(对齐资源分配界)
//页表页数组容量: 4树×514 + 拆分页(16区/树上限, 与条目上限匹配)
#define NPT_MAX_PAGES       (514 * GNPT_VIEW_COUNT + 64)
#define NPT_MAX_SPLITS      16              //每树最大拆分区数(2MB区)

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

//分配一页页表页: 页表页只需单页物理连续, 表间物理散列无妨
static PVOID SvmNptAllocPage(PULONG64 paOut)
{
	if (g_nptPageCount >= NPT_MAX_PAGES)
	{
		return NULL;
	}
	PVOID va = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, NPT_POOL_TAG);
	if (va == NULL)
	{
		return NULL;
	}
	RtlZeroMemory(va, PAGE_SIZE);    //全字段须确定态
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

//释放全部页表页(四棵); 构建失败路径与卸载共用(幂等)
VOID SvmFreeNpt(VOID)
{
	for (ULONG i = 0; i < g_nptPageCount; i++)
	{
		if (g_nptPages[i] != NULL)
		{
			ExFreePoolWithTag(g_nptPages[i], NPT_POOL_TAG);
			g_nptPages[i] = NULL;
		}
	}
	g_nptPageCount = 0;
	g_nptCoverage = 0;
	RtlZeroMemory(g_nptTree, sizeof(g_nptTree));
}
