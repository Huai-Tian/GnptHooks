#include<ntifs.h>
#include<intrin.h>
#include"common.h"
#include"svm.h"
#include"msr.h"

//====================================================================
// MSR拦截简易API实现(接口契约见msr.h头注释)
//
//条目模型(与hook.c一致的架构纪律):
//  - 静态数组(GNPT_MSR_MAX个, 零动态内存→卸载无需释放流程)
//  - Install/Remove持自旋锁(PASSIVE); 分发器无锁(条目字段
//    安装后不可变; Removed用Interlocked发布/撤销)
//  - 发布顺序: 填字段→置位图→InterlockedExchange(Removed,0)发布;
//    x64 TSO保证其他核看到Removed=0时字段与位图均已就绪
//  - Remove: 先标Removed(分发立即停止命中)再清位图; 在途exit
//    (已过查表)的回调安全完成(与detour hook同语义)
//
//位图写方式: 隐蔽生效后MSRPM页guest态直写=落零页静默丢失——
//Install/Remove的位图操作必经vmmcall root原语。位图改动即时
//生效(硬件每指令现查位图, 基址不变无clean bit/TLB问题)
//====================================================================

#define GNPT_MSR_MAX 16

typedef struct _GNPT_MSR_ENTRY
{
	volatile LONG Removed;   //1=空闲/已移除(分发跳过); 0=live
	ULONG32 Msr;
	PVOID Context;
	GNPT_MSR_READ_CB OnRead;    //NULL=读位不置(直通)
	GNPT_MSR_WRITE_CB OnWrite;  //NULL=写位不置(直通)
} GNPT_MSR_ENTRY, *PGNPT_MSR_ENTRY;

static GNPT_MSR_ENTRY s_msr[GNPT_MSR_MAX];
static KSPIN_LOCK s_msrLock;
static volatile LONG s_msrLockInit = 0;
static KIRQL s_msrOldIrql = 0;

static VOID GnptMsrLock(VOID)
{
	if (InterlockedCompareExchange(&s_msrLockInit, 1, 0) == 0)
	{
		KeInitializeSpinLock(&s_msrLock);
		//静态数组零初始化使Removed=0(语义=live)+Msr=0——显式标空,
		//消除"空槽被当成MSR 0的live条目"的意外语义
		for (ULONG i = 0; i < GNPT_MSR_MAX; i++)
		{
			s_msr[i].Removed = 1;
		}
	}
	KeAcquireSpinLock(&s_msrLock, &s_msrOldIrql);
}

static VOID GnptMsrUnlock(VOID)
{
	KeReleaseSpinLock(&s_msrLock, s_msrOldIrql);
}

//MSR号→MSRPM位定位(APM §15.11 Table 15-8三向量)。
//FALSE=范围外(0x2000+窗口/0xC0020000+等, 未覆盖)
//导出供svm.c故事面布防复用(置EFER/VM_CR/VM_HSAVE_PA读写双拦位)
BOOLEAN GnptMsrLocate(ULONG32 Msr, PULONG OutByteOff, UCHAR* OutBit)
{
	ULONG64 off;
	ULONG base;
	if (Msr <= 0x00001FFF)
	{
		base = 0x000;
		off = Msr;
	}
	else if (Msr >= 0xC0000000 && Msr <= 0xC0001FFF)
	{
		base = 0x800;
		off = Msr - 0xC0000000;
	}
	else if (Msr >= 0xC0010000 && Msr <= 0xC0011FFF)
	{
		base = 0x1000;
		off = Msr - 0xC0010000;
	}
	else
	{
		return FALSE;
	}
	*OutByteOff = base + (ULONG)(off / 4);
	*OutBit = (UCHAR)((off & 3) * 2);
	return TRUE;
}

//全核MSRPM位操作(root原语形态): 隐蔽生效后MSRPM页guest态
//直写=落零页静默丢失——必经vmmcall(7)进exit handler(GIF=0 root
//态直访物理)。isWrite=写位/set=置位。导出给svm.c的0x81 case调用
VOID GnptMsrBitmapRootAllCpus(ULONG32 Msr, BOOLEAN IsWrite, BOOLEAN Set)
{
	ULONG byteOff;
	UCHAR bit;
	if (!GnptMsrLocate(Msr, &byteOff, &bit))
	{
		return;
	}
	if (IsWrite)
	{
		bit++;    //msb=写拦截
	}
	UCHAR mask = (UCHAR)(1 << bit);
	ULONG cpus = KeQueryActiveProcessorCount(NULL);
	if (cpus > 64)
	{
		cpus = 64;
	}
	for (ULONG c = 0; c < cpus; c++)
	{
		PUCHAR map = (PUCHAR)g_svmVcpu[c].MsrpmVa;
		if (map == NULL)
		{
			continue;
		}
		if (Set)
		{
			map[byteOff] |= mask;
		}
		else
		{
			map[byteOff] &= (UCHAR)~mask;
		}
	}
}

//guest侧包装: 经vmmcall root原语全核位操作(Install/Remove调用)
static VOID GnptMsrBitmapAllCpus(ULONG32 Msr, BOOLEAN IsWrite, BOOLEAN Set)
{
	ULONG64 op = (ULONG64)((IsWrite ? 1 : 0) << 1) | (Set ? 1 : 0);
	CmVmmCall(GNPT_VMCALL_MSRBIT, Msr, op, 0);
}

//回调内取真实值(保留MSR勿调——root态真读=#GP蓝屏)
ULONG64 GnptMsrReadReal(ULONG32 Msr)
{
	return __readmsr(Msr);
}

//==== 分发器(exit handler上下文, 无锁: 条目不可变+Removed原子) ====
BOOLEAN GnptMsrDispatchRead(ULONG32 Msr, ULONG64* OutValue)
{
	for (ULONG i = 0; i < GNPT_MSR_MAX; i++)
	{
		PGNPT_MSR_ENTRY e = &s_msr[i];
		if (e->Removed != 0 || e->Msr != Msr)
		{
			continue;
		}
		if (e->OnRead == NULL)
		{
			return FALSE;    //仅写hook: 读直通
		}
		if (OutValue != NULL)
		{
			*OutValue = e->OnRead(e->Context, Msr);
		}
		return TRUE;
	}
	return FALSE;
}

BOOLEAN GnptMsrDispatchWrite(ULONG32 Msr, ULONG64 Value)
{
	for (ULONG i = 0; i < GNPT_MSR_MAX; i++)
	{
		PGNPT_MSR_ENTRY e = &s_msr[i];
		if (e->Removed != 0 || e->Msr != Msr)
		{
			continue;
		}
		if (e->OnWrite == NULL)
		{
			return TRUE;    //仅读hook: 写放行
		}
		return e->OnWrite(e->Context, Msr, Value);
	}
	return TRUE;
}

//引擎保留MSR判定: 三MSR属"SVM未激活"自洽故事面, exit 0x7C特判
//先于公共分发表——用户Install同号=死hook(特判吞掉永不达回调),
//fail-loud拒绝
BOOLEAN GnptMsrIsEngineReserved(ULONG32 Msr)
{
	return Msr == MSR_EFER || Msr == MSR_VM_CR || Msr == MSR_VM_HSAVE_PA;
}

NTSTATUS GnptMsrHookInstall(const GNPT_MSR_HOOK* Hook)
{
	if (Hook == NULL || (Hook->OnRead == NULL && Hook->OnWrite == NULL))
	{
		return STATUS_INVALID_PARAMETER;
	}
	if (GnptMsrIsEngineReserved(Hook->Msr))
	{
		FlLog("[MSR] Install拒绝: MSR=0x%X为引擎保留(S1故事面EFER/VM_CR/"
			"HSAVE_PA, exit特判先于用户表——用户hook永不达=死hook)", Hook->Msr);
		return STATUS_NOT_SUPPORTED;
	}
	ULONG byteOff;
	UCHAR bit;
	if (!GnptMsrLocate(Hook->Msr, &byteOff, &bit))
	{
		FlLog("[MSR] Install拒绝: MSR=0x%X超出MSRPM三向量覆盖范围"
			"(范围外MSR在MSR_PROT下本就自动exit, 无hook语义)", Hook->Msr);
		return STATUS_NOT_SUPPORTED;
	}
	//gate: 引擎运行中(与GnptHookInstall相同判据; 位图对in-guest核生效)
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	ULONG inGuest = 0;
	for (ULONG i = 0; i < cpuCount && i < 64; i++)
	{
		if (g_svmVcpu[i].base.bInGuest)
		{
			inGuest++;
		}
	}
	if (inGuest == 0)
	{
		FlLog("[MSR] Install拒绝: 零核in-guest(引擎未运行), 无处拦截");
		return STATUS_NOT_SUPPORTED;
	}
	//root原语前置: 位图vmmcall前钉到虚拟化核集(SMT隔离下
	//裸机兄弟核vmmcall=#UD→0x7E); 须在锁外(锁内DISPATCH)
	KAFFINITY oldAff = SvmPinVirtualizedCpus();
	if (oldAff == 0)
	{
		return STATUS_NOT_SUPPORTED;
	}
	//查重复+找空槽
	GnptMsrLock();
	LONG slot = -1;
	for (ULONG i = 0; i < GNPT_MSR_MAX; i++)
	{
		if (s_msr[i].Removed != 0)
		{
			if (slot < 0)
			{
				slot = (LONG)i;
			}
			continue;
		}
		if (s_msr[i].Msr == Hook->Msr)
		{
			GnptMsrUnlock();
			FlLog("[MSR] Install拒绝: MSR=0x%X已安装(Remove后可重装)", Hook->Msr);
			KeSetSystemAffinityThread(oldAff);
			return STATUS_UNSUCCESSFUL;
		}
	}
	if (slot < 0)
	{
		GnptMsrUnlock();
		FlLog("[MSR] Install拒绝: %u槽已满", (ULONG)GNPT_MSR_MAX);
		KeSetSystemAffinityThread(oldAff);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	PGNPT_MSR_ENTRY e = &s_msr[slot];
	e->Removed = 1;    //填充期间对分发器不可见
	e->Msr = Hook->Msr;
	e->Context = Hook->Context;
	e->OnRead = Hook->OnRead;
	e->OnWrite = Hook->OnWrite;
	//全核位图置位: 经vmmcall root原语(隐蔽生效后guest态直写无效)
	if (Hook->OnRead != NULL)
	{
		GnptMsrBitmapAllCpus(Hook->Msr, FALSE, TRUE);
	}
	if (Hook->OnWrite != NULL)
	{
		GnptMsrBitmapAllCpus(Hook->Msr, TRUE, TRUE);
	}
	InterlockedExchange(&e->Removed, 0);    //发布(字段+位图已就绪)
	GnptMsrUnlock();
	FlLog("[MSR] Install OK: MSR=0x%X 读=%s 写=%s 上下文=%p(root直写位图)",
		Hook->Msr, Hook->OnRead != NULL ? "拦截" : "直通",
		Hook->OnWrite != NULL ? "拦截" : "直通", Hook->Context);
	KeSetSystemAffinityThread(oldAff);
	return STATUS_SUCCESS;
}

NTSTATUS GnptMsrHookRemove(ULONG32 Msr)
{
	//root原语前置: 同Install——清位图vmmcall前钉虚拟化核集
	KAFFINITY oldAff = SvmPinVirtualizedCpus();
	if (oldAff == 0)
	{
		return STATUS_NOT_SUPPORTED;
	}
	GnptMsrLock();
	PGNPT_MSR_ENTRY found = NULL;
	for (ULONG i = 0; i < GNPT_MSR_MAX; i++)
	{
		if (s_msr[i].Removed == 0 && s_msr[i].Msr == Msr)
		{
			found = &s_msr[i];
			break;
		}
	}
	if (found == NULL)
	{
		GnptMsrUnlock();
		KeSetSystemAffinityThread(oldAff);
		return STATUS_NOT_FOUND;
	}
	//先标Removed(分发立即停止命中)再清位图; 在途回调安全完成
	found->Removed = 1;
	GnptMsrBitmapAllCpus(Msr, FALSE, FALSE);
	GnptMsrBitmapAllCpus(Msr, TRUE, FALSE);
	GnptMsrUnlock();
	FlLog("[MSR] Remove OK: MSR=0x%X(root直写清位, 在途回调安全完成)", Msr);
	KeSetSystemAffinityThread(oldAff);
	return STATUS_SUCCESS;
}

//枚举live MSR hook
//(Buffer=NULL→*InOutCount=数量; 容量不足→STATUS_BUFFER_TOO_SMALL
//并回填所需数量)。条目字段逐个复制(不拷Removed——那是内部状态)
NTSTATUS GnptMsrHookEnumerate(GNPT_MSR_HOOK* Buffer, ULONG* InOutCount)
{
	if (InOutCount == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}
	ULONG cnt = 0;
	GnptMsrLock();
	for (ULONG i = 0; i < GNPT_MSR_MAX; i++)
	{
		if (s_msr[i].Removed == 0)
		{
			cnt++;
		}
	}
	if (Buffer == NULL)
	{
		*InOutCount = cnt;
		GnptMsrUnlock();
		return STATUS_SUCCESS;
	}
	if (cnt > *InOutCount)
	{
		*InOutCount = cnt;
		GnptMsrUnlock();
		return STATUS_BUFFER_TOO_SMALL;
	}
	ULONG i2 = 0;
	for (ULONG i = 0; i < GNPT_MSR_MAX; i++)
	{
		if (s_msr[i].Removed == 0)
		{
			Buffer[i2].Msr = s_msr[i].Msr;
			Buffer[i2].Context = s_msr[i].Context;
			Buffer[i2].OnRead = s_msr[i].OnRead;
			Buffer[i2].OnWrite = s_msr[i].OnWrite;
			i2++;
		}
	}
	GnptMsrUnlock();
	*InOutCount = cnt;
	return STATUS_SUCCESS;
}
