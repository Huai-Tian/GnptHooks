#include"svm.h"
#include"vmcb.h"
#include"npt.h"
#include"hook.h"
#include"msr.h"

//==================== 常驻全局 ====================
volatile LONG g_gnptVcpuCpu = -1;      //观测锚点核(-1=未启动)
volatile LONG g_gnptParkedMask = 0;    //shutdown park核位掩码(bit i=cpu i)
GNPT_VCPU_SVM g_svmVcpu[64];           //每核SVM引擎态(BSS清零)
ULONG64 g_svmFeatBits = 0;             //Fn8000_000A_EDX特性快照(降级决策)
KEVENT g_svmShutdownEvent;             //卸载广播(通知事件: 一次唤醒全部发起线程)
static ULONG64 g_svmNcr3 = 0;          //P视图NCR3(SvmBuildNptViews返回; 其余视图经SvmNptViewNcr3)

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
	//v0.9r=CPUID观测采样移除: v0.9p/q判读=CPUID拦截面在场5/5渐进死
	//(DWM/GPU崩溃循环, 内核活), 不在(v0.9o)全活——无论真因是exit
	//频率本身(硬件怪癖)还是它驱动的TSC全局水位补偿壳高频运作
	//(参照系无对应物; NOIRVisor同类时间操纵因"Timer/GPU/NIC全乱"
	//被整体移除=同签名先例), CPUID拦截仅观测采样非功能必需→移除。
	//MSRPM(demo的LSTAR hook面)+复位类观测(SHUTDOWN/INIT)保留
	//M10.2(变体9): 该定罪被M9.6三体竞态混杂污染(5死轮均含隐蔽
	//或MSRPM; M8.28 caveat)——CPUID位条件回归重测, 单变量裁决
	//M10.5(变体10): 毒位细分——同9但CPUID exit绕过TSC壳
	//v0.9z(M10.6定罪转正): CPUID位回归正式版——毒源已定罪为
	//TSC壳的水位/钳制与高频exit的交互(非CPUID本身; x9进壳拖动
	//崩 vs xa绕壳更强拖动绿, 单变量翻转), exit handler顶部短路
	//路径(见SvmExitHandler)消除交互→拦截位安全回归。
	//M10.7-10.9终裁反转: 短路修复不完全——v0.9z视频级实测仍崩
	//(0x8898009b=DXGI设备移除=GPU驱动时序敏感路径), 毒=CPUID风暴×
	//切换器级C-state高频转换×GPU渲染三因子同场; 真实使用形态安全但
	//accel Full+视频门槛不过→正式版拦截位退回移除(v0.9r形态), 短路
	//快路径保留为遗产。回归验收=accel Full+视频叠加双绿(leaf伪装/
	//Hyper-V签名铺路届时重开)
#if GNPT_M92_VARIANT == 9 || GNPT_M92_VARIANT == 10
	vmcb->Control.InterceptMisc1 = INTERCEPT_CPUID | INTERCEPT_MSR_PROT |
		INTERCEPT_SHUTDOWN | INTERCEPT_INIT;
#else
	vmcb->Control.InterceptMisc1 = INTERCEPT_MSR_PROT |
		INTERCEPT_SHUTDOWN | INTERCEPT_INIT;
#endif
	//#DB拦截常驻: 单步窗口外的任何#DB=残余TF泄漏→
	//guest可见=0x3B/0x1E致命; 常驻+IDLE吞+清TF=最后一道网
	//#MC观测(EXCP_INTERCEPT_MC, 同上: 静默复位转化器)
	vmcb->Control.InterceptException = EXCP_INTERCEPT_DB | EXCP_INTERCEPT_MC;
	//v0.9w: V_INTR_MASKING回退为0(v0.9v教训, M8.26): kov.dev修法
	//的前提是**拦截INTR**(物理中断→#VMEXIT→host ISR); 我们type-2
	//in-place=INTR直通, 置位+host IF=1=物理中断无视guest cli直接
	//投递=中断插入临界区=数据腐败=瞬间bugcheck(v0.9v实测30s全核
	//崩溃路径爬行在被hook的KeBugCheckEx页=整机冻结)。
	//V_INTR_MASKING=0+INTR直通=中断流与裸机一致(guest IF门控)
	//=v0.9b以来正确形态; 0x101悬案(v0.9u 30s)另有其因, 哨兵在位
	vmcb->Control.InterceptMisc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL;  //VMRUN位强制(一致性检查)+VMMCALL拦截
	vmcb->Control.IopmBasePa = Vcpu->IopmPa;     //位图全0=不拦任何端口
	vmcb->Control.MsrpmBasePa = Vcpu->MsrpmPa;   //位图全0=不拦任何MSR
	vmcb->Control.GuestAsid = 1;                 //0非法(一致性检查要求)
	//---- 嵌套分页布线: NP启用+NCR3(§15.25.3) ----
	vmcb->Control.NpEnable |= NP_ENABLE_NP;
	vmcb->Control.NCr3 = g_svmNcr3;
	//TlbControl/EventInj/VmcbClean=0(分配时已清零; clean bits全0
	//=vmrun全字段从VMCB加载, 正确性优先)。
	//TscOffset=0起步=时间轴补偿基线(SvmExitHandler壳每exit负向
	//累计; clean bit0覆盖TSC offset, 全dirty形态保证每轮vmrun重载)
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
	//时间轴补偿留痕: offset终值(负值, 绝对值=本核会话root驻留
	//累计扣除量)。't'环事件(offset lo32/hi32)=补偿循环全程在跑的铁证
	PVMCB vmcbFinal = (PVMCB)Vcpu->VmcbVa;
	FlRingPush('t', idx, (ULONG)vmcbFinal->Control.TscOffset,
		vmcbFinal->Control.TscOffset >> 32, 0, 0);
	FlLog("SVM: 核%u已去虚拟化(STOP桥返回, SVME回读=%u, TSC补偿累计%llu ticks)",
		idx, svmeBack, 0ULL - vmcbFinal->Control.TscOffset);
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
	g_svmVcpuCount = 0;    //引擎已关: root原语钉核失效(v0.9t)
	FlLog("%s: 完成(泄漏核掩码=%X)", why, leaked);
}

//==================== 生命周期 ====================
//虚拟化核数(0=引擎未起; v0.9u起恒=全部核, SMT隔离路线已废弃)
volatile ULONG g_svmVcpuCount = 0;
//v0.9v哨兵: 各核最后#VMEXIT的TSC——HB心跳检查"核在VMRUN里停泊
//过久"(idle停泊正常=guest真实hlt; >2s且系统活动=IPI丢失嫌疑现场)
volatile LONG64 g_svmLastExitTsc[64] = { 0 };

KAFFINITY SvmPinVirtualizedCpus(VOID)
{
	ULONG n = g_svmVcpuCount;
	if (n == 0)
	{
		return 0;
	}
	KAFFINITY mask = (n >= 64) ? ~(KAFFINITY)0
		: (((KAFFINITY)1 << n) - 1);
	//KeSetSystemAffinityThread返回VOID(WDK)——旧亲和自存自还:
	//取当前线程亲和(新掩码写入前的值), 由调用方经
	//KeSetSystemAffinityThread(oldAff)还原
	KAFFINITY oldAff = KeQueryActiveProcessors();
	KeSetSystemAffinityThread(mask);
	return oldAff;
}

NTSTATUS SvmStartAllCpus(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
	//v0.9u=全核接管回退(SMT隔离终裁放弃, M8.24): 部分虚拟化=
	//不一致性根源(蓝pill公理"every core has to go under";
	//v0.9s/t两轮实测: vmmcall#UD+#DB逃逸均因裸机兄弟核)。
	//SvmPinVirtualizedCpus/g_svmVcpuCount保留为API(全核时
	//掩码=全核集, 调用无害), 未来若重启部分虚拟化需先解决
	//TF窗口迁移/hook布防一致性问题
	g_svmVcpuCount = cpuCount;    //root原语钉核依据(v0.9t, 全核值)
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
	//NPT四视图构建(静态共享树, 先于每核资源分配):
	//P=常态 / HOOKS=常规驻留 / HIDE=TRANSPARENT潜伏 / EXEC=执行窗口
	{
		ULONG64 ncr3[GNPT_VIEW_COUNT] = { 0, 0, 0, 0 };
		ULONG nptPages = 0;
		ULONG64 nptCover = 0;
		if (!SvmBuildNptViews(ncr3, &nptCover, &nptPages))
		{
			FlLog("[Entry] NPT四视图构建失败(内存不足?), 拒绝接管");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		g_svmNcr3 = ncr3[GNPT_VIEW_PRIMARY];
		FlLog("NPT: 四视图就绪(%u页, 覆盖%lluGB, P=%llX HOOKS=%llX HIDE=%llX EXEC=%llX)",
			nptPages, nptCover >> 30,
			ncr3[GNPT_VIEW_PRIMARY], ncr3[GNPT_VIEW_SECONDARY],
			ncr3[GNPT_VIEW_HIDE], ncr3[GNPT_VIEW_EXEC]);
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
	//NPT自我隐蔽: 全部核资源已分配+零核launch(此刻本线程纯裸机
	//root态=写NPT页直访物理自免疫); 首核launch后guest态动态写须走
	//vmmcall root原语(见svm.h功能码注释)。失败=无隐蔽(非致命, 记日志)
	//v0.9r=隐蔽回归(v0.9q判读: 无隐蔽仍死→隐蔽无罪; 全功能恢复)
	//M9.2变体: 隐蔽开启=全功能(0)/裸隐蔽(2)/隐蔽+MSR(5)/隐蔽+hook(6)/x8机制轮(8)/M10.2决策轮(9)/M10.5细分轮(10)
#if GNPT_M92_VARIANT == 0 || GNPT_M92_VARIANT == 2 || GNPT_M92_VARIANT == 5 || GNPT_M92_VARIANT == 6 || GNPT_M92_VARIANT == 8 || GNPT_M92_VARIANT == 9 || GNPT_M92_VARIANT == 10 || GNPT_M92_VARIANT == 11
	if (!SvmNptConcealAll())
	{
		FlLog("[Entry] 自我隐蔽失败(内存不足?), 无隐蔽继续(功能不受影响)");
	}
#else
	FlLog("[Entry] M9.2鉴别: 自我隐蔽停用(本轮无零页改译)");
#endif
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

//==================== exit分派(SvmExitHandler壳内调用, GIF=0上下文) ====================
//纪律: 全程GIF=0——只FlRingPush/FlRingExit/VMCB写/静态计数, 勿FlLog/睡眠。
//返回0=vmrun重入guest; 非0=STOP(asm CmSvmStop: 桥经易失r10/r11槽, 非易失全保真)
static ULONG SvmExitDispatch(PGNPT_VCPU_SVM Vcpu, PGUEST_REGS Regs)
{
	PVMCB vmcb = (PVMCB)Vcpu->VmcbVa;
	ULONG cpu = (ULONG)(UCHAR)Vcpu->CpuIndex;
	//exit帧槽位修正: #VMEXIT把guest状态回写VMCB(§15.6); exit帧的rax/rsp槽
	//是host值(vmsave不碰RIP/RSP/RAX, §15.5.2)——真值以VMCB为准
	Regs->rax = vmcb->State.Rax;
	Regs->rsp = vmcb->State.Rsp;
	//上轮注入清场: 不依赖硬件对EVENTINJ.V自动清(每exit一条u64写)
	vmcb->Control.EventInj = 0;
	//上轮TLB action清场: VMRUN只读不清TLB_CONTROL(§15.16原文), 置3
	//不清零=此后每轮vmrun都flush(必须每exit清零)。
	//免flush切换由ASID配对承载, 置3仅限NPT内容变化路径(Install/Remove/
	//临时RW), 见hook.c HookSwitchView
	vmcb->Control.TlbControl = 0;
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
	//单步窗口泄漏防御: armed而guest TF已失=窗口死亡
	//(步进指令为syscall/sysret/iret类清TF指令, #DB永不到达)→
	//拦截位+EXEC视图永久泄漏=全系统pushf/popf风暴+guest破坏
	GnptHookStepLeakCheck(vmcb, cpu);
	switch ((ULONG)exitCode)
	{
		case SVM_EXIT_VMMCALL:    //0x81: 探针/KEEP/STOP桥+签名门+root写原语族
		{
			ULONG func = (ULONG)Regs->rcx;
			ULONG64 arg1 = Regs->rdx, arg2 = Regs->r8, arg3 = Regs->r9;
			//签名门+CPL门+功能码白名单: 不符='u'采样+#UD注入(裸机vmmcall
			//等价语义), RIP不推进(fault指向引发指令; §15.20注入不经拦截
			//检查)。CPL取VMCB.Cpl(§15.6回写恒真); 用户态vmmcall=外来者
			//(§15.18"no CPL checks"故裸机用户态可达, 须门禁)
			if (vmcb->State.Cpl != 0 ||
				Regs->r10 != GNPT_VMMCALL_SIG0 ||
				Regs->r11 != GNPT_VMMCALL_SIG1 ||
				(func != GNPT_PROBE_MAGIC && func != GNPT_VMCALL_KEEP &&
					func != GNPT_VMCALL_STOP && func != GNPT_VMCALL_NPTSYNC &&
					func != GNPT_VMCALL_NPTSET && func != GNPT_VMCALL_NPTRES &&
					func != GNPT_VMCALL_MSRBIT))
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
				case GNPT_VMCALL_NPTSET:    //root写原语: 视图PTE(隐蔽后动态写唯一正道)
					SvmNptSetPte((ULONG)(arg2 >> 48) & 0xF, arg1,
						arg2 & 0x0000FFFFFFFFFFFFULL, arg3);
					FlRingPush('n', cpu, GNPT_VMCALL_NPTSET, arg1, arg2, arg3);
					SvmAdvanceRip(vmcb);
					return 0;
				case GNPT_VMCALL_NPTRES:    //root恢复原语: 单树(0-3)/四树(0xF)恒等
				{
					ULONG vw = (ULONG)arg2 & 0xF;
					if (vw == 0xF)
					{
						for (ULONG v = 0; v < GNPT_VIEW_COUNT; v++)
						{
							SvmNptRestoreIdentity(v, arg1);
						}
					}
					else
					{
						SvmNptRestoreIdentity(vw, arg1);
					}
					FlRingPush('n', cpu, GNPT_VMCALL_NPTRES, arg1, arg2, 0);
					SvmAdvanceRip(vmcb);
					return 0;
				}
				case GNPT_VMCALL_MSRBIT:    //root位图原语: 全核MSRPM位操作
				{
					ULONG32 msr = (ULONG32)arg1;
					BOOLEAN isWrite = ((arg2 & 2) != 0);
					BOOLEAN set = ((arg2 & 1) != 0);
					GnptMsrBitmapRootAllCpus(msr, isWrite, set);
					FlRingPush('b', cpu, GNPT_VMCALL_MSRBIT, arg1, arg2, 0);
					SvmAdvanceRip(vmcb);
					return 0;
				}
				default:
					break;    //白名单已收窄, 不可达
			}
			break;
		}
		case SVM_EXIT_CPUID:    //0x72直透传(全真值; 伪装待后续版本)
		{
			int info[4] = { 0 };
			__cpuidex(info, (int)Regs->rax, (int)Regs->rcx);
			//RAX走VMCB(asm契约: 帧rax槽恢复时跳过, vmrun从VMCB
			//加载——写Regs->rax无效)
			vmcb->State.Rax = (ULONG64)(ULONG)info[0];
			Regs->rax = (ULONG64)(ULONG)info[0];
			Regs->rbx = (ULONG64)(ULONG)info[1];
			Regs->rcx = (ULONG64)(ULONG)info[2];
			Regs->rdx = (ULONG64)(ULONG)info[3];
			SvmAdvanceRip(vmcb);
			return 0;
		}
		case SVM_EXIT_MSR:    //0x7C: MSR拦截API面
		{
			//EXITINFO1 bit0=0读/1写(位义见msr.h); MSR号在ECX。
			//hook命中→回调(读=伪造值/写=放行或静默丢弃); 未hook
			//(位图竞态/范围外MSR自动exit)→真值回放=裸机等价
			ULONG32 msr = (ULONG32)Regs->rcx;
			BOOLEAN isWrite = ((vmcb->Control.ExitInfo1 & 1) != 0);
			{
				static volatile LONG s_msrCnt[64] = { 0 };
				LONG mn = InterlockedIncrement(&s_msrCnt[cpu & 63]);
				if (mn == 1 || (mn & 0xFFF) == 0)
				{
					FlRingPush('m', cpu, SVM_EXIT_MSR,
						msr, (ULONG64)(ULONG)isWrite, (ULONG64)mn);
				}
			}
			if (isWrite)
			{
				ULONG64 val = (ULONG64)(ULONG)Regs->rax |
					((ULONG64)(ULONG)Regs->rdx << 32);
				if (!GnptMsrDispatchWrite(msr, val))
				{
					SvmAdvanceRip(vmcb);
					return 0;    //回调拒绝: 静默丢弃(guest认为写成功)
				}
				__writemsr(msr, val);    //放行代写(root真写)
			}
			else
			{
				ULONG64 val = 0;
				if (!GnptMsrDispatchRead(msr, &val))
				{
					val = __readmsr(msr);    //未hook真值回放
				}
				//RAX=低32走VMCB(asm契约: 帧rax槽vmrun时被VMCB.RAX
				//覆盖——不写VMCB则低32停留在rdmsr时刻线程EAX);
				//RDX=高32是帧GPR正常路径
				vmcb->State.Rax = val & 0xFFFFFFFFULL;
				Regs->rax = val & 0xFFFFFFFFULL;
				Regs->rdx = val >> 32;
			}
			SvmAdvanceRip(vmcb);
			return 0;
		}
		case SVM_EXIT_NPF:    //0x400嵌套页故障: 双NPT视图切换引擎(hook布防产物)
		{
			//隐蔽页写/执行fault兜底(须最前置: 先于hook引擎
			//——隐蔽页gpa非hook目标, 但泄漏态自愈分支会误切视图)
			if (SvmNptConcealFaultFix(vmcb->Control.ExitInfo2))
			{
				vmcb->Control.TlbControl = 3;    //恢复后冲净零页翻译
				return 0;    //重执行=访问自愈
			}
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
			//=0x1E; guest可见#DB=0x3B——
			//#DB拦截常驻: 此处=最后一道网, 吞+清TF自愈。
			//残留窗口位一并解除(LeakCheck已收口, 此为双保险)
			static volatile LONG s_dbIdleCnt[64] = { 0 };
			LONG dbn = InterlockedIncrement(&s_dbIdleCnt[cpu & 63]);
			if (dbn == 1 || (dbn & 0xFF) == 0)
			{
				FlRingPush('D', cpu, SVM_EXIT_EXCP_DB,
					vmcb->State.Rip, vmcb->State.Dr6, 0);
			}
			vmcb->Control.InterceptMisc1 &= ~(INTERCEPT_PUSHF | INTERCEPT_POPF);
			vmcb->State.Rflags &= ~(1ULL << 8);    //清残余TF(自愈终结churn)
			return 0;    //不推RIP(trap语义RIP已下一条)
		}
		case SVM_EXIT_PUSHF:    //0x70: 单步窗口PUSHF仿真(EFLAGS影子)
		{
			if (GnptHookStepEmuPushf(vmcb, cpu))
			{
				return 0;
			}
			//非窗口=拦截位泄漏: 解除窗口位+重执行原指令。
			//推进=跳过pushfq的压栈效应=guest标志/栈大面积
			//破坏(0x1E级)。fault语义不推RIP
			//#DB拦截常驻不动
			vmcb->Control.InterceptMisc1 &= ~(INTERCEPT_PUSHF | INTERCEPT_POPF);
			return 0;
		}
		case SVM_EXIT_POPF:    //0x71: 单步窗口POPF仿真(保注入TF)
		{
			if (GnptHookStepEmuPopf(vmcb, cpu))
			{
				return 0;
			}
			//非窗口=拦截位泄漏: 同0x70——解除窗口位+重执行,
			//绝不跳过popfq的弹栈/标志效应。#DB拦截常驻不动
			vmcb->Control.InterceptMisc1 &= ~(INTERCEPT_PUSHF | INTERCEPT_POPF);
			return 0;
		}
		case SVM_EXIT_SHUTDOWN:    //0x7F: guest triple fault(硬件复位级)
		case SVM_EXIT_INIT:        //0x63: 外部INIT(复位类IPI; 含带引擎重启)
		case SVM_EXIT_EXCP_MC:     //0x52: 机器检查(#MC)
			//观测轮(v0.9o): 静默硬复位转化器——命中即留痕+标记蓝屏
			//(0xDEADDEAD, P1=exit码 P2=cpu P3=RIP P4=Info1)。同OS
			//设计=exit handler即OS上下文, KeBugCheckEx任意IRQL合法;
			//dump含内核内存='Y'环条目与VMCB全量可析。注意: 带引擎
			//重启(INIT)也会触发——重启前sc stop本就是纪律
			FlRingPush('Y', cpu, (ULONG)exitCode, vmcb->State.Rip,
				vmcb->Control.ExitInfo1, vmcb->Control.ExitInfo2);
			KeBugCheckEx(0xDEADDEAD, (ULONG_PTR)(ULONG)exitCode, cpu,
				(ULONG_PTR)vmcb->State.Rip,
				(ULONG_PTR)vmcb->Control.ExitInfo1);
			return 0;    //不可达(bugcheck不归)
		default:    //未知exit: 计数留痕(FlRingExit兜底限流)+推进(观察语义)
			SvmAdvanceRip(vmcb);
			return 0;
	}
	//内层白名单收窄后不可达; 兜底=推进(保守)
	SvmAdvanceRip(vmcb);
	return 0;
}

//==================== exit handler外壳(asm调用, GIF=0上下文) ====================
//TSC时间轴补偿壳(全局水位形态): guest读TSC(RDTSC/RDTSCP直通
//零exit)=物理TSC+VMCB.TscOffset(硬件加, §15.10控制区语义+App.B
//"to be added in RDTSC and RDTSCP")。本壳把每次#VMEXIT的root驻留
//时长从guest时间线扣除——guest时间线上"exit从未发生"。
//
//设计约束: 每核独立负向累计=跨核偏差无界增长, 线程迁移即遭遇
//RDTSC倒退(Windows裸rdtsc使用者依赖跨核同步契约)——故用全局
//虚拟时间线水位g_svmTscWm(单调只升, cmpxchg免锁max)。
//每exit三步: ①扣驻留(本核单调性保持: 扣除窗[T0,T1]含于真实不可
//见窗, 相邻guest读间扣除总和≤物理差→本核永不倒退) ②virt对水位
//做max提升 ③落后水位>ε则前跳重挂共享时间线。效果: 热核不再自己
//累积滞后, 而是从全局(实际=最冷核)时间线借时——跨核发散从
//"无界永久"变为"有界瞬态"(≈水位两次推进间他核扣除量+ε,
//活跃集内≈ε)。前跳=单调安全方向。
//残余(接受并记录): 共享时间线整体滞后物理=最冷核累计驻留(均匀
//不可分核); 钳制成本按欠补偿方向泄漏(亚μs/s级)。
//STOP路径不补偿(无vmrun, offset此后不再作用于本核)。
#define GNPT_TSC_CC_EPS  1024    //跨核钳制余量(ticks, ≈320ns@3.2GHz P0)
static volatile LONG64 g_svmTscWm = 0;   //全局虚拟TSC水位(单调只升)
ULONG SvmExitHandler(PGNPT_VCPU_SVM Vcpu, PGUEST_REGS Regs)
{
	//v0.9z(M10.6定罪修复转正): CPUID exit短路于TSC壳——
	//不进T0/T1/扣除/水位/钳制(哨兵照常刷新, dispatch/观测/计数
	//照常走)。毒源=壳的水位/钳制与CPUID高频exit的交互(x9进壳
	//拖动崩vs xa绕壳更强拖动绿, 单变量翻转); CPUID exit本身
	//无罪(kov.dev反例吻合)。exit成本(~1500周期)guest可见=
	//CPUID自然延迟范围(100-3000)内, kov.dev同款tradeoff;
	//CPUID核滞后累计无界但下一非CPUID exit钳制前跳=单调安全
	//(M6判例), 拖动风暴期滞后率~200K周期/s有界瞬态。
	{
		PVMCB vmcbFast = (PVMCB)Vcpu->VmcbVa;
		if (vmcbFast->Control.ExitCode == SVM_EXIT_CPUID)
		{
			g_svmLastExitTsc[(ULONG)(UCHAR)Vcpu->CpuIndex & 63] = __rdtsc();
			return SvmExitDispatch(Vcpu, Regs);
		}
	}
	Vcpu->ExitTsc = __rdtsc();              //T0: root驻留起点
	g_svmLastExitTsc[(ULONG)(UCHAR)Vcpu->CpuIndex & 63] =
		Vcpu->ExitTsc;                      //v0.9v哨兵刷新(核号取VCPU)
	ULONG stop = SvmExitDispatch(Vcpu, Regs);
	if (stop == 0)
	{
		PVMCB vmcb = (PVMCB)Vcpu->VmcbVa;
		ULONG64 t1 = __rdtsc();             //T1: root驻留终点
		vmcb->Control.TscOffset -= t1 - Vcpu->ExitTsc;
		//本核此刻虚拟读数(mod 2^64; 负offset自然回绕)
		ULONG64 virt = t1 + vmcb->Control.TscOffset;
		//水位提升(cmpxchg自旋max; 败者以最新值重判)
		if (virt > (ULONG64)g_svmTscWm)
		{
			ULONG64 cmp = (ULONG64)g_svmTscWm;
			while (virt > cmp)
			{
				ULONG64 prev = (ULONG64)_InterlockedCompareExchange64(
					&g_svmTscWm, (LONG64)virt, (LONG64)cmp);
				if (prev == cmp)
				{
					break;    //提升成功
				}
				cmp = prev;
			}
		}
		//跨核钳制: 落后共享时间线>ε→前跳重挂(单调安全, 仅写本核VMCB)
		ULONG64 w = (ULONG64)g_svmTscWm;    //提升后新鲜读(单调量免锁)
		if (w - virt > GNPT_TSC_CC_EPS)
		{
			vmcb->Control.TscOffset += (w - virt) - GNPT_TSC_CC_EPS;
		}
	}
	return stop;
}

