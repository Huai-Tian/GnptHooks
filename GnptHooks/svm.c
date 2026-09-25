#include"svm.h"
#include"vmcb.h"
#include"npt.h"
#include"hook.h"

//==================== 常驻全局 ====================
volatile LONG g_gnptVcpuCpu = -1;      //观测锚点核(-1=未启动)
volatile LONG g_gnptParkedMask = 0;    //shutdown park核位掩码(bit i=cpu i)
GNPT_VCPU_SVM g_svmVcpu[64];           //每核SVM引擎态(BSS清零)
ULONG64 g_svmFeatBits = 0;             //Fn8000_000A_EDX特性快照(降级决策)
KEVENT g_svmShutdownEvent;             //卸载广播(通知事件: 一次唤醒全部发起线程)
static ULONG64 g_svmNcr3 = 0;          //Primary视图NCR3(SvmBuildDualNpt返回; Secondary经SvmNptViewNcr3)

//SVM可用性三态判定(APM §15.4):
//  0=可用 1=CPU无SVM 2=BIOS禁且不可解锁 3=BIOS禁但有SVM_KEY可能
ULONG CommCheckSvm(VOID)
{
	int cpuinfo[4] = { 0 };
	__cpuidex(cpuinfo, 0x80000001, 0);
	if (((cpuinfo[2] >> CPUID_SVM_ECX_BIT) & 1) == 0)
	{
		return 1;    //CPUID Fn8000_0001_ECX[SVM]=0: 处理器无SVM
	}
	ULONG64 vmCr = __readmsr(MSR_VM_CR);
	if ((vmCr & VM_CR_SVMDIS) == 0)
	{
		return 0;    //SVMDIS=0: SVM允许启用
	}
	//SVMDIS=1: BIOS禁用——SVML位决定是否理论可解锁
	__cpuidex(cpuinfo, CPUID_FN_SVM, 0);
	if ((cpuinfo[3] & SVM_FEAT_SVML) == 0)
	{
		return 2;    //无SVM lock: 固件设置永久锁死, 用户须改BIOS
	}
	return 3;        //有SVM lock: 理论可用SVM_KEY解锁(需固件/TPM配合)
}

//==================== 段attrib: GDT描述符直读 ====================
//12位=描述符bits55:52|47:40拼接(APM §15.5.1段格式节)。
//x64内核典型值: CS=0xA09B(L=1), SS/DS/ES=0xC093
static ULONG SvmGetSegAttrib(USHORT Selector)
{
	ULONG64 gdtBase = CmGetGdtBase();
	PSEGMENT_DESCRIPTOR desc = (PSEGMENT_DESCRIPTOR)(gdtBase + (Selector & ~(USHORT)7));
	ULONG attrib = desc->AttributesLow;
	attrib |= ((ULONG)(desc->AttributesHigh & 0xF)) << 8;
	return attrib;
}

//==================== 物理连续资源分配 ====================
//512GB物理上限(全平台MAXPHYADDR内)。VMCB/HSAVE须4KB对齐
//(页粒度天然满足); IOPM/MSRPM须物理连续(硬件按物理基址遍历)
static PVOID SvmAllocContig(SIZE_T bytes, PULONG64 paOut)
{
	PHYSICAL_ADDRESS lowest;
	PHYSICAL_ADDRESS ceiling;
	PHYSICAL_ADDRESS boundary;
	lowest.QuadPart = 0;               //最低物理地址(无下限)
	ceiling.QuadPart = 0x7FFFFFFFFF;  //512GB物理上限
	boundary.QuadPart = 0;            //0=无跨界约束
	PVOID va = MmAllocateContiguousMemorySpecifyCache(bytes, lowest, ceiling, boundary, MmCached);
	if (va == NULL)
	{
		return NULL;
	}
	RtlZeroMemory(va, bytes);    //Mm族不保证清零; VMCB全字段须确定态
	if (paOut != NULL)
	{
		*paOut = MmGetPhysicalAddress(va).QuadPart;
	}
	return va;
}

static VOID SvmFreeContig(PVOID va)
{
	if (va != NULL)
	{
		MmFreeContiguousMemory(va);
	}
}

//RIP推进: NRIP仅指令拦截类exit有效(§15.7), 其余exit硬件清零。
//零值不推进(fault/事件语义)
static VOID SvmAdvanceRip(PVMCB vmcb)
{
	if (vmcb->Control.NRip != 0)
	{
		vmcb->State.Rip = vmcb->Control.NRip;
	}
}

//==================== VMCB填充(发起线程内, EFER.SVME置位后调用) ====================
//契约: RIP/RSP由CmSvmEnter填(探针入口/探针栈); FS/GS/TR/LDTR隐藏态+KernelGsBase
//+STAR/LSTAR/CSTAR/SFMASK+SYSENTER三件由__svm_vmsave从当前硬件真值预同步
//(§15.5.2指令集, 不碰RIP/RSP/RAX/CR)
static VOID SvmFillVmcb(PGNPT_VCPU_SVM Vcpu)
{
	PVMCB vmcb = (PVMCB)Vcpu->VmcbVa;
	//---- guest寄存器快照(#VMEXIT回写同集, §15.6) ----
	vmcb->State.Efer = __readmsr(MSR_EFER);      //须含SVME=1(一致性检查要求, §15.5.1)
	vmcb->State.Cr0 = __readcr0();
	vmcb->State.Cr3 = __readcr3();
	vmcb->State.Cr4 = __readcr4();
	vmcb->State.Dr6 = __readdr(6);
	vmcb->State.Dr7 = __readdr(7);
	vmcb->State.Rflags = CmGetRflags();    //pushfq全宽读取(asm helper; MSVC无x64 RFLAGS intrinsics)
	vmcb->State.Rax = 0;                         //探针不依赖(恢复序列从探针栈弹出真值)
	vmcb->State.Cpl = 0;                         //x64发起线程恒CPL0
	vmcb->State.GPat = __readmsr(MSR_PAT);
	//---- 段四件套: selector/attrib/limit(x64基址恒0) ----
	vmcb->State.Cs.Selector = CmGetSegCs();
	vmcb->State.Cs.Attrib = (USHORT)SvmGetSegAttrib(vmcb->State.Cs.Selector);
	vmcb->State.Cs.Limit = CmGetSegLimitCs();
	vmcb->State.Cs.Base = 0;
	vmcb->State.Ss.Selector = CmGetSegSs();
	vmcb->State.Ss.Attrib = (USHORT)SvmGetSegAttrib(vmcb->State.Ss.Selector);
	vmcb->State.Ss.Limit = CmGetSegLimitSs();
	vmcb->State.Ss.Base = 0;
	vmcb->State.Ds.Selector = CmGetSegDs();
	vmcb->State.Ds.Attrib = (USHORT)SvmGetSegAttrib(vmcb->State.Ds.Selector);
	vmcb->State.Ds.Limit = CmGetSegLimitDs();
	vmcb->State.Ds.Base = 0;
	vmcb->State.Es.Selector = CmGetSegEs();
	vmcb->State.Es.Attrib = (USHORT)SvmGetSegAttrib(vmcb->State.Es.Selector);
	vmcb->State.Es.Limit = CmGetSegLimitEs();
	vmcb->State.Es.Base = 0;
	//---- GDTR/IDTR伪描述符(selector/attrib域RESERVED=0) ----
	vmcb->State.Gdtr.Limit = CmGetGdtLimit();
	vmcb->State.Gdtr.Base = CmGetGdtBase();
	vmcb->State.Idtr.Limit = CmGetIdtLimit();
	vmcb->State.Idtr.Base = CmGetIdtBase();
	//---- FS/GS/TR/LDTR+系统MSR集: 硬件真值预同步 ----
	__svm_vmsave((void*)(ULONG_PTR)Vcpu->VmcbPa);    //参数=VMCB物理地址(按指针值传递, MSVC契约)
	//---- 拦截配置(最小集; INTR不拦=中断直通) ----
	vmcb->Control.InterceptMisc1 = INTERCEPT_CPUID;    //0x72观测采样
	vmcb->Control.InterceptMisc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL;  //VMRUN位强制(一致性检查)+VMMCALL拦截
	vmcb->Control.IopmBasePa = Vcpu->IopmPa;     //位图全0=不拦任何端口
	vmcb->Control.MsrpmBasePa = Vcpu->MsrpmPa;   //位图全0=不拦任何MSR
	vmcb->Control.GuestAsid = 1;                 //0非法(一致性检查要求)
	//---- 嵌套分页布线: NP启用+NCR3(§15.25.3) ----
	vmcb->Control.NpEnable |= NP_ENABLE_NP;
	vmcb->Control.NCr3 = g_svmNcr3;
	//TscOffset/TlbControl/EventInj/VmcbClean=0(分配时已清零; clean bits全0
	//=vmrun全字段从VMCB加载, 正确性优先, 性能项待定案环境评估)
}

//==================== 每核发起线程 ====================
//T_i钉核->SVME+HSAVE->VMCB填充->CmSvmEnter世界开关->探针双vmmcall->KEEP
//(bInGuest=1)->guest态停泊(中断直通, 调度器原生唤醒)->事件唤醒->vmmcall(1)
//STOP桥回裸机(asm已stgi)->清SVME->线程退出
static VOID SvmVcpuThread(PVOID Context)
{
	PGNPT_VCPU_SVM Vcpu = (PGNPT_VCPU_SVM)Context;
	ULONG idx = (ULONG)(UCHAR)Vcpu->CpuIndex;
	KeSetSystemAffinityThread((KAFFINITY)1 << idx);    //钉核(单组上限)
	if (KeGetCurrentProcessorNumber() != idx)
	{
		Vcpu->base.bLaunchFailed = 1;
		FlLog("SVM: 核%u钉核失败(实到核%u), 本核不接管", idx, KeGetCurrentProcessorNumber());
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
		return;
	}
	//EFER.SVME置位(SVM指令族之门)+HSAVE基址
	ULONG64 efer = __readmsr(MSR_EFER);
	__writemsr(MSR_EFER, efer | EFER_SVME);
	__writemsr(MSR_VM_HSAVE_PA, Vcpu->HsavePa);
	Vcpu->base.bSvmOn = 1;
	SvmFillVmcb(Vcpu);
	FlLog("SVM: 核%u接管(vmrun循环就绪)", idx);
	FlArmLaunchWatch();      //vmrun观测预热(仅Debug构建有实体; Release空宏)
	CmSvmEnter(Vcpu);         //世界开关; "返回"=本核已guest化(launch失败除外)
	g_flLaunchHot = 0;
	if (Vcpu->base.bInGuest)
	{
		FlLog("SVM: 核%u已guest化(KEEP确认), 停泊等待", idx);
		//guest态停泊: INTR不拦截=中断直通, KeWait由guest调度器原生唤醒
		KeWaitForSingleObject(&g_svmShutdownEvent, Executive, KernelMode, FALSE, NULL);
		//醒来(仍在guest): STOP桥——返回=本核已去虚拟化(裸机, asm已stgi)
		(VOID)CmVmmCall(GNPT_VMCALL_STOP, 0, 0, 0);
	}
	else
	{
		//vmrun一致性失败('R'环留痕)或探针未确认(理论不可达): 本核未接管, 裸机收尾
		FlLog("SVM: 核%u未接管(%s), 裸机收尾", idx,
			Vcpu->base.bLaunchFailed ? "vmrun失败" : "探针未确认(异常)");
	}
	//---- 裸机收尾: 清EFER.SVME+回读验证 ----
	ULONG64 eferNow = __readmsr(MSR_EFER);
	__writemsr(MSR_EFER, eferNow & ~EFER_SVME);
	ULONG svmeBack = (ULONG)((__readmsr(MSR_EFER) >> 12) & 1);
	Vcpu->base.bSvmOn = 0;
	Vcpu->base.bInGuest = 0;
	FlLog("SVM: 核%u已去虚拟化(STOP桥返回, SVME回读=%u)", idx, svmeBack);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

//==================== 停机+释放(start回滚与卸载共用) ====================
//顺序: 广播事件->逐核有界等待(5s/核)->全核裸机后释放->清零。
//超时核: 资源保留(该核可能仍guest化, 释放=蓝屏; 泄漏是安全降级)
static VOID SvmStopAndFree(ULONG n, const char* why)
{
	ULONG leaked = 0;
	KeSetEvent(&g_svmShutdownEvent, IO_NO_INCREMENT, FALSE);
	for (ULONG i = 0; i < n; i++)
	{
		PGNPT_VCPU_SVM v = &g_svmVcpu[i];
		if (v->ThreadObj == NULL)
		{
			continue;
		}
		LARGE_INTEGER to;
		to.QuadPart = -50000000LL;    //5秒
		if (KeWaitForSingleObject(v->ThreadObj, Executive, KernelMode, FALSE, &to)
			== STATUS_TIMEOUT)
		{
			leaked |= 1UL << i;
			FlLog("%s: 核%u发起线程5秒未退出(该核资源泄漏保留)", why, i);
			ObDereferenceObject(v->ThreadObj);
			v->ThreadObj = NULL;
			continue;
		}
	}
	KeClearEvent(&g_svmShutdownEvent);
	for (ULONG i = 0; i < n; i++)
	{
		if (leaked & (1UL << i))
		{
			continue;    //超时核资源保留
		}
		PGNPT_VCPU_SVM v = &g_svmVcpu[i];
		if (v->ThreadObj == NULL && v->VmcbVa == NULL)
		{
			continue;    //未启动核(资源由调用方处理或从未分配)
		}
		if (v->ThreadObj != NULL)
		{
			if (v->ThreadHandle != NULL)
			{
				ZwClose(v->ThreadHandle);
				v->ThreadHandle = NULL;
			}
			ObDereferenceObject(v->ThreadObj);
			v->ThreadObj = NULL;
		}
		SvmFreeContig(v->VmcbVa);
		SvmFreeContig(v->HsaveVa);
		SvmFreeContig(v->IopmVa);
		SvmFreeContig(v->MsrpmVa);
		SvmFreeContig(v->VmmStack);
		RtlZeroMemory(v, sizeof(GNPT_VCPU_SVM));    //资源清零: 观测残留不跨加载
	}
	FlLog("%s: 完成(泄漏核掩码=%X)", why, leaked);
}

//==================== 生命周期 ====================
NTSTATUS SvmStartAllCpus(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	if (cpuCount > 64)
	{
		FlLog("GNPT: 拒绝启动: %u核超64(单组上限)", cpuCount);
		return STATUS_NOT_SUPPORTED;
	}
	//SVM可用性三态+特性探测(横幅)
	ULONG svmState = CommCheckSvm();
	const char* stateText =
		(svmState == 0) ? "可用" :
		(svmState == 1) ? "CPU无SVM(Fn8000_0001_ECX.bit2=0)" :
		(svmState == 2) ? "BIOS禁用且不可解锁(VM_CR.SVMDIS=1, 无SVML)" :
		"BIOS禁用但有钥匙可能(VM_CR.SVMDIS=1, 有SVML)";
	int feat[4] = { 0 };
	__cpuidex(feat, CPUID_FN_SVM, 0);
	ULONG svmRev = (ULONG)feat[0] & 0xFF;
	ULONG nasid = (ULONG)feat[1];
	ULONG featBits = (ULONG)feat[3];
	g_svmFeatBits = (ULONG64)featBits;
	FlLog("%s AMD SVM引擎 %s | %u核 | SVM=%s rev=%u ASID=%u",
		"GNPT", GNPT_BUILD_TAG, cpuCount, stateText, svmRev, nasid);
	FlLog("特性: NP=%d NRIPS=%d VmcbClean=%d FlushByAsid=%d DecodeAssists=%d VGIF=%d",
		(featBits >> 0) & 1, (featBits >> 3) & 1, (featBits >> 5) & 1,
		(featBits >> 6) & 1, (featBits >> 7) & 1, (featBits >> 16) & 1);
	if (svmState != 0)
	{
		FlLog("[Entry] SVM不可用(状态%u), 拒绝接管", svmState);
		return STATUS_UNSUCCESSFUL;
	}
	if ((g_svmFeatBits & SVM_FEAT_NRIPS) == 0)
	{
		//探针RIP推进依赖NRIPS(指令拦截类exit才回写nRIP, §15.7); =0时
		//每次exit原地重执行=挂死。LDE兜底未实现, 直接拒绝
		FlLog("[Entry] NRIPS=0(RIP推进无硬件支持), 拒绝接管");
		return STATUS_NOT_SUPPORTED;
	}
	if ((g_svmFeatBits & SVM_FEAT_NP) == 0)
	{
		FlLog("[Entry] NP=0(处理器无嵌套分页), 拒绝接管");
		return STATUS_NOT_SUPPORTED;
	}
	//NPT双视图构建(全核共享单实例, 先于每核资源分配):
	//Primary=常态(取指NPF切换), Secondary=hook(CodePage可执行)
	{
		ULONG64 ncr3[2] = { 0, 0 };
		ULONG nptPages = 0;
		ULONG64 nptCover = 0;
		if (!SvmBuildDualNpt(ncr3, &nptCover, &nptPages))
		{
			FlLog("[Entry] NPT双视图构建失败(内存不足?), 拒绝接管");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		g_svmNcr3 = ncr3[GNPT_VIEW_PRIMARY];
		FlLog("NPT: 双视图就绪(%u页, 覆盖%lluGB, Primary=%llX Secondary=%llX)",
			nptPages, nptCover >> 30, ncr3[0], ncr3[1]);
	}
	//每核资源预分配(VMCB/HSAVE 4KB, IOPM 12KB, MSRPM 8KB, VMM栈16KB)
	for (ULONG i = 0; i < cpuCount; i++)
	{
		PGNPT_VCPU_SVM v = &g_svmVcpu[i];
		v->CpuIndex = (CHAR)i;
		v->VmcbVa = SvmAllocContig(PAGE_SIZE, &v->VmcbPa);
		v->HsaveVa = SvmAllocContig(PAGE_SIZE, &v->HsavePa);
		v->IopmVa = SvmAllocContig(0x3000, &v->IopmPa);
		v->MsrpmVa = SvmAllocContig(0x2000, &v->MsrpmPa);
		v->VmmStack = SvmAllocContig(0x4000, NULL);
		if (v->VmmStack != NULL)
		{
			v->VmmStackTop = (PVOID)((PUCHAR)v->VmmStack + 0x4000);
		}
		if (v->VmcbVa == NULL || v->HsaveVa == NULL || v->IopmVa == NULL ||
			v->MsrpmVa == NULL || v->VmmStack == NULL)
		{
			FlLog("[Entry] 核%u资源分配失败, 回滚", i);
			for (ULONG j = 0; j <= i; j++)    //含本核半分配
			{
				SvmFreeContig(g_svmVcpu[j].VmcbVa);
				SvmFreeContig(g_svmVcpu[j].HsaveVa);
				SvmFreeContig(g_svmVcpu[j].IopmVa);
				SvmFreeContig(g_svmVcpu[j].MsrpmVa);
				SvmFreeContig(g_svmVcpu[j].VmmStack);
				RtlZeroMemory(&g_svmVcpu[j], sizeof(GNPT_VCPU_SVM));
			}
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	KeInitializeEvent(&g_svmShutdownEvent, NotificationEvent, FALSE);
	//每核发起线程
	ULONG created = 0;
	for (ULONG i = 0; i < cpuCount; i++)
	{
		HANDLE h = NULL;
		NTSTATUS st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL,
			NULL, SvmVcpuThread, (PVOID)&g_svmVcpu[i]);
		if (!NT_SUCCESS(st))
		{
			FlLog("[Entry] 核%u发起线程创建失败=0x%X, 回滚", i, (ULONG)st);
			break;
		}
		ObReferenceObjectByHandle(h, THREAD_ALL_ACCESS, *PsThreadType,
			KernelMode, &g_svmVcpu[i].ThreadObj, NULL);
		g_svmVcpu[i].ThreadHandle = h;
		created++;
	}
	if (created != cpuCount)
	{
		SvmStopAndFree(created, "[Start回滚]");
		for (ULONG j = created; j < cpuCount; j++)    //未建线程核: 纯资源回滚
		{
			PGNPT_VCPU_SVM v = &g_svmVcpu[j];
			SvmFreeContig(v->VmcbVa);
			SvmFreeContig(v->HsaveVa);
			SvmFreeContig(v->IopmVa);
			SvmFreeContig(v->MsrpmVa);
			SvmFreeContig(v->VmmStack);
			RtlZeroMemory(v, sizeof(GNPT_VCPU_SVM));
		}
		return STATUS_UNSUCCESSFUL;
	}
	//等待全核in-guest确认(10秒界; 失败/超时=回滚)
	LARGE_INTEGER tick;
	tick.QuadPart = -100000LL;    //10ms
	ULONG inGuest = 0, failed = 0;
	for (int w = 0; w < 1000; w++)
	{
		inGuest = 0;
		failed = 0;
		for (ULONG i = 0; i < cpuCount; i++)
		{
			if (g_svmVcpu[i].base.bInGuest)
			{
				inGuest++;
			}
			else if (g_svmVcpu[i].base.bLaunchFailed)
			{
				failed++;
			}
		}
		if (inGuest == cpuCount || failed != 0)
		{
			break;
		}
		KeDelayExecutionThread(KernelMode, FALSE, &tick);
	}
	if (inGuest != cpuCount)
	{
		FlLog("[Entry] 接管未完成(in-guest=%u/%u failed=%u), 回滚", inGuest, cpuCount, failed);
		SvmStopAndFree(cpuCount, "[Start回滚]");
		return STATUS_UNSUCCESSFUL;
	}
	g_gnptVcpuCpu = 0;    //观测锚点核(HB行vcpu字段)
	FlLog("SVM: 全核接管完成(%u核in-guest)", cpuCount);
	return STATUS_SUCCESS;
}

//返回TRUE=全核已裸机(引擎真正关停); FALSE=拒绝/未在位(引擎仍在位)
BOOLEAN SvmShutdownAllCpus(VOID)
{
	ULONG n = KeQueryActiveProcessorCount(NULL);
	if (n > 64)
	{
		n = 64;
	}
	//park守卫: park核的VMM栈/代码页被占用, 释放=蓝屏; 拒绝并泄漏
	if (g_gnptParkedMask != 0)
	{
		FlLog("[Unload] 拒绝去虚拟化: park掩码=%X非零(资源泄漏保留)", g_gnptParkedMask);
		return FALSE;
	}
	//从未启动(或已回滚): 无状态可退
	if (g_svmVcpu[0].ThreadObj == NULL)
	{
		FlLog("[Unload] 引擎未在位, 空卸载");
		return TRUE;
	}
	SvmStopAndFree(n, "[Unload]");
	//NPT页表释放(全核已裸机, 页表无人引用)
	FlLog("NPT: 释放(%u页, 曾覆盖%lluGB)",
		SvmNptPageCount(), SvmNptCoverageBytes() >> 30);
	SvmFreeNpt();
	g_svmNcr3 = 0;
	g_gnptVcpuCpu = -1;
	return TRUE;
}

//==================== exit handler(asm调用, GIF=0上下文) ====================
//纪律: 全程GIF=0——只FlRingPush/FlRingExit/VMCB写/静态计数, 勿FlLog/睡眠。
//返回0=vmrun重入guest; 非0=STOP(asm CmSvmStop: 桥经易失r10/r11槽, 非易失全保真)
ULONG SvmExitHandler(PGNPT_VCPU_SVM Vcpu, PGUEST_REGS Regs)
{
	PVMCB vmcb = (PVMCB)Vcpu->VmcbVa;
	ULONG cpu = (ULONG)(UCHAR)Vcpu->CpuIndex;
	//exit帧槽位修正: #VMEXIT把guest状态回写VMCB(§15.6); exit帧的rax/rsp槽
	//是host值(vmsave不碰RIP/RSP/RAX, §15.5.2)——真值以VMCB为准
	Regs->rax = vmcb->State.Rax;
	Regs->rsp = vmcb->State.Rsp;
	//上轮注入清场: 不依赖硬件对EVENTINJ.V自动清(每exit一条u64写)
	vmcb->Control.EventInj = 0;
	ULONG64 exitCode = vmcb->Control.ExitCode;
	//负值族(VMEXIT_INVALID等): vmrun一致性失败——'R'环留痕+手动return桥
	//(探针帧: [RSP+0xA8]=CmSvmEnter返回地址, +0xB0=返回后调用者栈基)
	if ((LONG64)exitCode < 0)
	{
		FlRingPush('R', cpu, (ULONG)exitCode, vmcb->State.Rip,
			vmcb->Control.ExitInfo1, vmcb->Control.ExitInfo2);
		Vcpu->base.bLaunchFailed = 1;
		ULONG64 probeRsp = vmcb->State.Rsp;
		Regs->r10 = probeRsp + 0xB0;
		Regs->r11 = *(ULONG64*)(probeRsp + 0xA8);
		Regs->rax = 0;
		return 1;
	}
	FlRingExit(cpu, (ULONG)exitCode, vmcb->State.Rip, vmcb->Control.ExitInfo1);
	switch ((ULONG)exitCode)
	{
		case SVM_EXIT_VMMCALL:    //0x81: 探针/KEEP/STOP桥+签名门
		{
			ULONG func = (ULONG)Regs->rcx;
			//签名门+CPL门+功能码白名单: 不符='u'采样+#UD注入(裸机vmmcall
			//等价语义), RIP不推进(fault指向引发指令; §15.20注入不经拦截
			//检查)。CPL取VMCB.Cpl(§15.6回写恒真); 用户态vmmcall=外来者
			//(§15.18"no CPL checks"故裸机用户态可达, 须门禁)
			if (vmcb->State.Cpl != 0 ||
				Regs->r10 != GNPT_VMMCALL_SIG0 ||
				Regs->r11 != GNPT_VMMCALL_SIG1 ||
				(func != GNPT_PROBE_MAGIC && func != GNPT_VMCALL_KEEP &&
					func != GNPT_VMCALL_STOP && func != GNPT_VMCALL_NPTSYNC))
			{
				static volatile LONG s_sigCnt[64] = { 0 };    //每核计数
				LONG sn = InterlockedIncrement(&s_sigCnt[cpu & 63]);
				if (sn == 1 || (sn & 0xFFF) == 0)    //首条+每4096条采样(防刷爆环)
				{
					FlRingPush('u', cpu, SVM_EXIT_VMMCALL, func,
						vmcb->State.Cs.Selector, 0);
				}
				//EVENTINJ注入#UD: TYPE=3(异常) vector=6 无错误码
				vmcb->Control.EventInj = EVENTINJ_MAKE(6, EVENTINJ_TYPE_EXCP, 0, 0);
				static volatile LONG s_udCnt[64] = { 0 };
				LONG un = InterlockedIncrement(&s_udCnt[cpu & 63]);
				if (un == 1 || (un & 0xFFF) == 0)
				{
					FlRingPush('B', cpu, SVM_EXIT_VMMCALL, vmcb->State.Rip, 0, 0);
				}
				return 0;    //不推RIP(fault语义)
			}
			switch (func)
			{
				case GNPT_PROBE_MAGIC:    //'W'落地探针自证(每核恰一条)
					FlRingPush('W', cpu, SVM_EXIT_VMMCALL, GNPT_PROBE_MAGIC, 0, 0);
					SvmAdvanceRip(vmcb);
					return 0;
				case GNPT_VMCALL_KEEP:    //接管确认(HB g掩码数据源)
					Vcpu->base.bInGuest = 1;
					FlRingPush('Q', cpu, SVM_EXIT_VMMCALL, func, 0, 0);
					SvmAdvanceRip(vmcb);
					return 0;
				case GNPT_VMCALL_STOP:    //卸载STOP桥('[S]'留痕)
					Vcpu->base.bInGuest = 0;
					FlRingPush('S', cpu, SVM_EXIT_VMMCALL, func, 0, 0);
					SvmAdvanceRip(vmcb);
					//桥值填帧的易失r10/r11槽(ABI零牺牲: 非易失全保真):
					//r10=VMCB.RSP(guest栈), r11=推进后RIP, rax=VMCB.RAX
					//(=CmVmmCall返回值); asm CmSvmStop: mov rsp,r10; stgi; jmp r11
					Regs->r10 = vmcb->State.Rsp;
					Regs->r11 = vmcb->State.Rip;
					Regs->rax = vmcb->State.Rax;
					return 1;
				case GNPT_VMCALL_NPTSYNC:    //NPT改动TLB同步: 下轮vmrun冲净本guest全部翻译
					vmcb->Control.TlbControl = 3;
					FlRingPush('i', cpu, GNPT_VMCALL_NPTSYNC, 0, 0, 0);    //每核同步确认(触发链面包屑)
					SvmAdvanceRip(vmcb);
					return 0;
				default:
					break;    //白名单已收窄, 不可达
			}
			break;
		}
		case SVM_EXIT_CPUID:    //0x72直透传(全真值; 伪装待后续版本)
		{
			int info[4] = { 0 };
			__cpuidex(info, (int)Regs->rax, (int)Regs->rcx);
			Regs->rax = (ULONG64)(ULONG)info[0];
			Regs->rbx = (ULONG64)(ULONG)info[1];
			Regs->rcx = (ULONG64)(ULONG)info[2];
			Regs->rdx = (ULONG64)(ULONG)info[3];
			SvmAdvanceRip(vmcb);
			return 0;
		}
		case SVM_EXIT_NPF:    //0x400嵌套页故障: 双NPT视图切换引擎(hook布防产物)
		{
			//引擎处理hook布防引发的NPF(取指进Secondary/写回Primary);
			//未处理=异常信号(fault语义不推RIP, 'N'环留痕)
			if (GnptHookNpfEngine(vmcb, cpu,
				vmcb->Control.ExitInfo1, vmcb->Control.ExitInfo2))
			{
				return 0;
			}
			//'N'环: a=faulting gpa(EXITINFO2) b=错误码(EXITINFO1);
			//错误码位域: bit0 P/bit1 RW/bit2 US/bit3 RSV/bit4 ID(取指)/
			//bit6 SS/bit32 终译fault/bit33 guest页表fault(§15.25.6)
			FlRingPush('N', cpu, SVM_EXIT_NPF,
				vmcb->Control.ExitInfo2, vmcb->Control.ExitInfo1, 0);
			return 0;    //fault语义: 不推RIP(FlRingExit计数+限流兜底)
		}
		case SVM_EXIT_EXCP_DB:    //0x41: 单步窗口#DB认领(IDLE残余=吞)
		{
			if (GnptHookStepDbExit(vmcb, cpu))
			{
				return 0;
			}
			//IDLE残余#DB: 一律吞掉不注入。注入回guest无调试接手
			//=0x1E(M4.8/M4.9两判例实证, RIP=注入点fault语义)。
			//引擎设计上guest不合法持有TF(注入TF只在armed窗口内),
			//此形态=多核窗口撕裂竞态残余, 'D'采样留痕观察
			static volatile LONG s_dbIdleCnt[64] = { 0 };
			LONG dbn = InterlockedIncrement(&s_dbIdleCnt[cpu & 63]);
			if (dbn == 1 || (dbn & 0xFF) == 0)
			{
				FlRingPush('D', cpu, SVM_EXIT_EXCP_DB,
					vmcb->State.Rip, vmcb->State.Dr6, 0);
			}
			return 0;    //不推RIP(trap语义RIP已下一条)
		}
		case SVM_EXIT_PUSHF:    //0x70: 单步窗口PUSHF仿真(EFLAGS影子)
		{
			if (GnptHookStepEmuPushf(vmcb, cpu))
			{
				return 0;
			}
			SvmAdvanceRip(vmcb);    //非窗口(理论不可达): 推进防原地死循环
			return 0;
		}
		case SVM_EXIT_POPF:    //0x71: 单步窗口POPF仿真(保注入TF)
		{
			if (GnptHookStepEmuPopf(vmcb, cpu))
			{
				return 0;
			}
			SvmAdvanceRip(vmcb);    //非窗口(理论不可达): 推进防原地死循环
			return 0;
		}
		default:    //未知exit: 计数留痕(FlRingExit兜底限流)+推进(观察语义)
			SvmAdvanceRip(vmcb);
			return 0;
	}
	//内层白名单收窄后不可达; 兜底=推进(保守)
	SvmAdvanceRip(vmcb);
	return 0;
}
