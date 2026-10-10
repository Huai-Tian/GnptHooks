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
volatile ULONG g_svmStgiPass = 0;      //STGI直通门控(启动时按CPUID定, 见SvmStartAllCpus)
volatile ULONG g_svmTscDlMode = 0;     //0x6E0轴换算门控(启动时裸机探测LAPIC模式定, 见SvmStartAllCpus)
KEVENT g_svmShutdownEvent;             //卸载广播(通知事件: 一次唤醒全部发起线程)
static ULONG64 g_svmNcr3 = 0;          //P视图NCR3(SvmBuildNptViews返回; 其余视图经SvmNptViewNcr3)
//NPF风暴探针(仅Debug构建读写): 引擎不可恢复NPF的取证面
//(单发全档转储后静音)
static volatile ULONG64 g_nStormGpa[64];  //各核最后不可恢复NPF的gpa
static volatile LONG g_nStormCnt[64];    //同gpa连续计数(阈值=单发触发)
static volatile LONG g_nStormDone[64];   //已转储(此后'N'静音防环溢出)
//故事面状态(语义/处置见exit分派前的"SVM未激活自洽故事面"节):
//三MSR读写exit计数(0=EFER 1=VM_CR 2=HSAVE; Debug构建累加,
//停机总结对账)+HSAVE影子寄存器(per-core, 仅exit handler写=
//功能件)
static volatile LONG64 g_svmStoryRd[3] = { 0, 0, 0 };
static volatile LONG64 g_svmStoryWr[3] = { 0, 0, 0 };
static ULONG64 g_svmHsaveShadow[64] = { 0 };
//#GP处置计数: 族转换#UD / 忠实回注(自然#GP应≈0; Debug构建
//累加, 停机对账)
static volatile LONG64 g_svmGpUdConv = 0;
static volatile LONG64 g_svmGpReinj = 0;

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
	//DR-TRANSPARENT卫生: 历史硬件DR残留清零(引擎重启/
	//park边角的陈旧断点=幽灵hook: DR0-3不在VMCB跨世界持续,
	//陈旧地址+新会话误武装=改道到已释放槽)。裸机Windows运行期
	//DR0-3恒0/DR7恒0x400(保留位)——清零=裸机等价; DR6状态位
	//无副作用保留裸读。DR6/DR7=VMCB guest state(§15.5), 接管后
	//MOV DR全拦=guest视角由影子承载, 硬件/VMCB位全归引擎
	__writedr(0, 0);
	__writedr(1, 0);
	__writedr(2, 0);
	__writedr(3, 0);
	__writedr(7, 0x400);
	//影子侧对偶初始化(DR7=0x400): guest首个读DR7零差异
	GnptHookDrShadowInit((ULONG)(UCHAR)Vcpu->CpuIndex);
	vmcb->State.Dr6 = __readdr(6);
	vmcb->State.Dr7 = 0x400;
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
	//---- 拦截配置 ----
#if GNPT_L3_G2
	//L3+G2探针: L3底座+MSR_PROT单bit加回(其余组全剥)——故事三MSR
	//(EFER/VM_CR/HSAVE)与0x6E0(TSC_DEADLINE, g_svmTscDlMode在位
	//时)exit进handler(MSRPM位图填充本无条件在跑)。0x6E0=热键
	//风暴最可能载体(定时器编程exit)。TscOffset恒0=0x6E0换算
	//退化为恒等(TSC壳属G4组, 不在本形态)
	vmcb->Control.InterceptMisc1 = INTERCEPT_CPUID | INTERCEPT_MSR_PROT;
	vmcb->Control.InterceptMisc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL;
	vmcb->Control.LbrVirtEnable = 0;
#elif GNPT_L3_MINIMAL
	//L3探针极简底座: CPUID(骨架原样)+VMMCALL(STOP桥生命线)仅存,
	//其余全剥=SimpleSvm同构形态。guest内SVM指令族(SVME=1下硬件
	//真实执行)不拦=探针协议下无人自发执行(Windows不用SVM指令);
	//#MC直达=硬件reset(裸机等价, 死=真硬件事件)
	vmcb->Control.InterceptMisc1 = INTERCEPT_CPUID;
	vmcb->Control.InterceptMisc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL;
	vmcb->Control.LbrVirtEnable = 0;
#elif GNPT_L3_NOG1
	//L系列NOG1探针: NOLBR形态剥G1——异常拦截全0(#DB/#GP/#MC)
	//+DR读写位全0。零hook形态: STEP/DR-TRANSPARENT机件不触发,
	//guest自身DR/TF活动=纯裸跑(硬件DR未被引擎触碰, 裸机行为)。
	//G2/G3/G4/CPUID/VMMCALL保持(MSR_PROT/SHUTDOWN/INIT/INVLPGA/
	//SVM族在场, SMI按开关)
	vmcb->Control.InterceptMisc1 = INTERCEPT_CPUID | INTERCEPT_MSR_PROT |
		INTERCEPT_SHUTDOWN | INTERCEPT_INIT | INTERCEPT_INVLPGA;
#if GNPT_SMI_INTERCEPT
	vmcb->Control.InterceptMisc1 |= INTERCEPT_SMI;
#endif
	vmcb->Control.InterceptDrRead = 0;
	vmcb->Control.InterceptDrWrite = 0;
	vmcb->Control.InterceptException = 0;
	vmcb->Control.InterceptMisc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL |
		INTERCEPT_VMLOAD | INTERCEPT_VMSAVE |
		INTERCEPT_CLGI | INTERCEPT_SKINIT;
	if (!g_svmStgiPass)
	{
		vmcb->Control.InterceptMisc2 |= INTERCEPT_STGI;
	}
	vmcb->Control.LbrVirtEnable = 0;   //NOLBR保持(0xB8=0)
#elif GNPT_L3_G1DR
	//L系列G1DR探针: G1内部二分轮1——NOG1形态仅加回DR读写位
	//(0x20-0x3F全拦, Mov DR进影子仿真; 流量=第三方驱动看门狗)。
	//异常拦截保持全0(guest自身#DB/#GP/#MC=裸机直通IDT, 硬件DR
	//未被引擎触碰)。NODEMO/NOLBR保持
	vmcb->Control.InterceptMisc1 = INTERCEPT_CPUID | INTERCEPT_MSR_PROT |
		INTERCEPT_SHUTDOWN | INTERCEPT_INIT | INTERCEPT_INVLPGA;
#if GNPT_SMI_INTERCEPT
	vmcb->Control.InterceptMisc1 |= INTERCEPT_SMI;
#endif
	vmcb->Control.InterceptDrRead = 0xFF;
	vmcb->Control.InterceptDrWrite = 0xFF;
	vmcb->Control.InterceptException = 0;
	vmcb->Control.InterceptMisc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL |
		INTERCEPT_VMLOAD | INTERCEPT_VMSAVE |
		INTERCEPT_CLGI | INTERCEPT_SKINIT;
	if (!g_svmStgiPass)
	{
		vmcb->Control.InterceptMisc2 |= INTERCEPT_STGI;
	}
	vmcb->Control.LbrVirtEnable = 0;   //NOLBR保持(0xB8=0)
#elif GNPT_L3_G1EXC
	//L系列G1EXC探针: NOG1形态仅加回异常拦截位(#DB/#GP/#MC三
	//bit, 甄别投递路径在场)。DR读写位保持全0, NODEMO/NOLBR保持
	vmcb->Control.InterceptMisc1 = INTERCEPT_CPUID | INTERCEPT_MSR_PROT |
		INTERCEPT_SHUTDOWN | INTERCEPT_INIT | INTERCEPT_INVLPGA;
#if GNPT_SMI_INTERCEPT
	vmcb->Control.InterceptMisc1 |= INTERCEPT_SMI;
#endif
	vmcb->Control.InterceptDrRead = 0;
	vmcb->Control.InterceptDrWrite = 0;
	vmcb->Control.InterceptException = EXCP_INTERCEPT_DB |
		EXCP_INTERCEPT_MC | EXCP_INTERCEPT_GP;
	vmcb->Control.InterceptMisc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL |
		INTERCEPT_VMLOAD | INTERCEPT_VMSAVE |
		INTERCEPT_CLGI | INTERCEPT_SKINIT;
	if (!g_svmStgiPass)
	{
		vmcb->Control.InterceptMisc2 |= INTERCEPT_STGI;
	}
	vmcb->Control.LbrVirtEnable = 0;   //NOLBR保持(0xB8=0)
#elif GNPT_L3_G1DDB
	//L系列G1DDB探针: NOG1形态加回DR读写位(0xFF/0xFF)+仅#DB异常
	//位(bit1), #GP/#MC缺席。DR×#DB=TRANSPARENT生产关键对(MOV
	//DR影子与#DB入口陷阱必须同场)
	vmcb->Control.InterceptMisc1 = INTERCEPT_CPUID | INTERCEPT_MSR_PROT |
		INTERCEPT_SHUTDOWN | INTERCEPT_INIT | INTERCEPT_INVLPGA;
#if GNPT_SMI_INTERCEPT
	vmcb->Control.InterceptMisc1 |= INTERCEPT_SMI;
#endif
	vmcb->Control.InterceptDrRead = 0xFF;
	vmcb->Control.InterceptDrWrite = 0xFF;
	vmcb->Control.InterceptException = EXCP_INTERCEPT_DB;
	vmcb->Control.InterceptMisc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL |
		INTERCEPT_VMLOAD | INTERCEPT_VMSAVE |
		INTERCEPT_CLGI | INTERCEPT_SKINIT;
	if (!g_svmStgiPass)
	{
		vmcb->Control.InterceptMisc2 |= INTERCEPT_STGI;
	}
	vmcb->Control.LbrVirtEnable = 0;   //NOLBR保持(0xB8=0)
#elif GNPT_L3_G1DGP
	//L系列G1DGP探针: NOG1形态加回DR读写位(0xFF/0xFF)+仅#GP位
	//(bit13), #DB/#MC缺席
	vmcb->Control.InterceptMisc1 = INTERCEPT_CPUID | INTERCEPT_MSR_PROT |
		INTERCEPT_SHUTDOWN | INTERCEPT_INIT | INTERCEPT_INVLPGA;
#if GNPT_SMI_INTERCEPT
	vmcb->Control.InterceptMisc1 |= INTERCEPT_SMI;
#endif
	vmcb->Control.InterceptDrRead = 0xFF;
	vmcb->Control.InterceptDrWrite = 0xFF;
	vmcb->Control.InterceptException = EXCP_INTERCEPT_GP;
	vmcb->Control.InterceptMisc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL |
		INTERCEPT_VMLOAD | INTERCEPT_VMSAVE |
		INTERCEPT_CLGI | INTERCEPT_SKINIT;
	if (!g_svmStgiPass)
	{
		vmcb->Control.InterceptMisc2 |= INTERCEPT_STGI;
	}
	vmcb->Control.LbrVirtEnable = 0;   //NOLBR保持(0xB8=0)
#elif GNPT_L3_G1DMC
	//L系列G1DMC探针: 交互项分解轮3——NOG1形态加回DR读写位
	//(0xFF/0xFF)+仅#MC位(bit18)。#DB/#GP缺席。G1DDB(DR+#DB)/
	//G1DGP(DR+#GP: r37=132+r4D=3注入零泄漏)均活=两两组合仅剩
	//DR×#MC; 本轮闭合后若活=凶手为DR+≥2个EXC位组合
	vmcb->Control.InterceptMisc1 = INTERCEPT_CPUID | INTERCEPT_MSR_PROT |
		INTERCEPT_SHUTDOWN | INTERCEPT_INIT | INTERCEPT_INVLPGA;
#if GNPT_SMI_INTERCEPT
	vmcb->Control.InterceptMisc1 |= INTERCEPT_SMI;
#endif
	vmcb->Control.InterceptDrRead = 0xFF;
	vmcb->Control.InterceptDrWrite = 0xFF;
	vmcb->Control.InterceptException = EXCP_INTERCEPT_MC;
	vmcb->Control.InterceptMisc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL |
		INTERCEPT_VMLOAD | INTERCEPT_VMSAVE |
		INTERCEPT_CLGI | INTERCEPT_SKINIT;
	if (!g_svmStgiPass)
	{
		vmcb->Control.InterceptMisc2 |= INTERCEPT_STGI;
	}
	vmcb->Control.LbrVirtEnable = 0;   //NOLBR保持(0xB8=0)
#elif GNPT_L3_G1DDBGP
	//L系列G1DDBGP探针: 交互项分解轮4——NOG1形态加回DR读写位
	//(0xFF/0xFF)+#DB+#GP两位(bit1|bit13)。#MC缺席。两两组合全
	//无辜(G1DDB/G1DGP/G1DMC均活)=凶手=DR+≥2个EXC位; 本轮与
	//NOLBR(死×2)差分仅#MC。死=生产剥#GP即活(#MC待定位);
	//活=凶手含#MC(→G1DBMC/G1GPMC轮)
	vmcb->Control.InterceptMisc1 = INTERCEPT_CPUID | INTERCEPT_MSR_PROT |
		INTERCEPT_SHUTDOWN | INTERCEPT_INIT | INTERCEPT_INVLPGA;
#if GNPT_SMI_INTERCEPT
	vmcb->Control.InterceptMisc1 |= INTERCEPT_SMI;
#endif
	vmcb->Control.InterceptDrRead = 0xFF;
	vmcb->Control.InterceptDrWrite = 0xFF;
	vmcb->Control.InterceptException = EXCP_INTERCEPT_DB |
		EXCP_INTERCEPT_GP;
	vmcb->Control.InterceptMisc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL |
		INTERCEPT_VMLOAD | INTERCEPT_VMSAVE |
		INTERCEPT_CLGI | INTERCEPT_SKINIT;
	if (!g_svmStgiPass)
	{
		vmcb->Control.InterceptMisc2 |= INTERCEPT_STGI;
	}
	vmcb->Control.LbrVirtEnable = 0;   //NOLBR保持(0xB8=0)
#else
	//Misc1: CPUID(伪装面载体; 快路径短路于TSC壳——高频风暴不进
	//补偿壳)+MSR_PROT(MSR hook面载体)+SHUTDOWN/INIT/INVLPGA(观测/
	//自愈位)+SMI(观测位, SMMLOCK=1平台硬件忽略)
	vmcb->Control.InterceptMisc1 = INTERCEPT_CPUID | INTERCEPT_MSR_PROT |
		INTERCEPT_SHUTDOWN | INTERCEPT_INIT | INTERCEPT_INVLPGA;
#if GNPT_SMI_INTERCEPT
	vmcb->Control.InterceptMisc1 |= INTERCEPT_SMI;
#endif
	//NMI virt(IBS/PMC virt的中断投递配套, §15.21.10): INTERCEPT_NMI+
	//V_NMI_ENABLE为硬依赖对(APM原文: 无NMI拦截位而置V_NMI_ENABLE=
	//VMRUN一致性拒)。门控=VNMI特性在场且IBS或PMC特性在场(两者皆无
	//时无投递需求, 不增NMI拦截面)。物理NMI→exit(0x61)→EVENTINJ注入
	//vNMI(dispatch), NMI交付延迟+1世界开关(罕见事件: WHEA/硬件看门
	//狗类)。IBS virt伴生should条款: host侧IbsFetchEn/IbsOpEn应保持0
	//(§15.38; 本框架与Windows默认均不做IBS采样)。未知微架构合置
	//硬门由launch阶梯回退兜底(SvmLaunchThread)
	if ((g_svmFeatBits & SVM_FEAT_VNMI) != 0 &&
	    (g_svmFeatBits & (SVM_FEAT_IBSVIRT | SVM_FEAT_PMCVIRT)) != 0)
	{
		vmcb->Control.InterceptMisc1 |= INTERCEPT_NMI;
		vmcb->Control.VIntr |= VINTR_V_NMI_ENABLE;
	}
	//DR0-7读写全拦(DR-TRANSPARENT机件): guest的MOV DR经exit对
	//影子仿真——硬件DR0-3(跨VMRUN持续)与VMCB.Dr6/7(guest state)
	//永不受guest触碰; 空闲态零额外exit(Windows运行期几乎无MOV DR
	//流量, 仅启动/调试器路径)
	vmcb->Control.InterceptDrRead = 0xFF;
	vmcb->Control.InterceptDrWrite = 0xFF;
	//异常拦截: 仅#DB(单步窗口认领+DR断点入口陷阱+窗口外残余TF泄漏
	//的最后防线——guest可见#DB=致命, 一律拦截)。#GP/#MC让位——
	//平台约束: DR位+#DB+#GP三位组合=本机类冻结杀手(深空闲停泊态
	//零exit冻结, 死亡不经handler; 任两两组合存活), 故生产形态
	//#GP/#MC不设拦截位。让位语义复核: #GP手术仅兜"硬件先于拦截
	//位产生#GP"的边界(非法VMCB对齐类), SVM指令族主路径全由
	//Misc1/Misc2拦截位承载(INVLPGA/VMRUN/VMMCALL/VMLOAD/VMSAVE/
	//CLGI/SKINIT/STGI), guest内硬件#GP直通IDT=与第二实例SVME=1
	//故事自洽; #MC=复位转化器(观测留痕), 让位后真#MC=裸机等价
	//硬件reset。dispatch的#GP/#MC甄别代码保留(位不设不可达,
	//Debug/未来硬件迭代可再启用)
	vmcb->Control.InterceptException = EXCP_INTERCEPT_DB;
	//V_INTR_MASKING必须为0: 该位仅当"拦截INTR+host ISR"形态才有
	//意义; 本框架type-2 in-place=INTR直通(物理中断由guest原生IF
	//门控), 置位+host IF=1=物理中断无视guest cli直接投递=中断
	//插入临界期=数据腐败=瞬间bugcheck。V_INTR_MASKING=0+INTR
	//直通=中断流与裸机一致
	//Misc2: VMRUN位(一致性检查强制)+VMMCALL(STOP桥生命线; APM
	//§15.9未拦截的VMMCALL在guest内#UD)+SVM指令族显式拦截——
	//裸机Windows(EFER.SVME=0)上全族#UD(APM §15.4: #UD条件=
	//SVME=0, 与是否在guest无关); 不拦则guest内SVME=1下硬件照常
	//执行(VMLOAD/VMSAVE可直访VMCB段/MSR态, CLGI可翻转GIF)=自洽
	//故事差+安全洞双开。工程处置=显式拦截+#UD注入(不依赖硬件
	//默认), dispatch的'v' case族。STGI例外=按SKINIT特性门控:
	//在场裸机STGI本就静默执行, 注入#UD反成可判别违反
	vmcb->Control.InterceptMisc2 = INTERCEPT_VMRUN | INTERCEPT_VMMCALL |
		INTERCEPT_VMLOAD | INTERCEPT_VMSAVE |
		INTERCEPT_CLGI | INTERCEPT_SKINIT;
	//STGI门控(Fn8000_0001_ECX bit12=SKINIT): 在场→拦截位不设=
	//直通忠实(裸机同款CPU的STGI静默执行不#UD); 缺席→拦截+#UD
	//注入(保守维持)。GIF方向安全: guest态GIF本为1, STGI直通
	//为幂等(1→1); root窗GIF=0纪律不受guest指令影响(#VMEXIT
	//硬件自动清GIF)
	if (!g_svmStgiPass)
	{
		vmcb->Control.InterceptMisc2 |= INTERCEPT_STGI;
	}

	//VMCB 0xB8指令虚拟化使能族(§15.33/§15.23/§15.38/§15.39): 世界
	//开关硬件交换guest/host寄存器组=root驻留分支不泄漏进guest计数
	//器。LBR(b0): DebugCtl+控制转移组(探测面=读LBR栈找非模块分支
	//地址); IBS(b2)/PMC(b3): 指令/分支计数(检测方基线对比的root
	//增量)。VMCB位零exit成本, 代价=世界开关多组寄存器保存/恢复。
	//置位门控: LBR按特性独立; IBS/PMC须特性在场且NMI virt投递配套
	//在位(上方组合)——配套缺席=平台边界(DemoPmuProbe状态报告)。
	//S1横幅的0xB8值=特性叙事面(第二实例故事), 与实际使能解耦。
	//bit1=VMSAVEvirt不使能(该路径要#UD注入非guest执行)。首试被
	//未知微架构合置硬门拒(全核VMEXIT_INVALID形态在档)时, launch
	//阶梯回退兜底(SvmLaunchThread)
#if GNPT_L3_NOLBR
	//L系列NOLBR探针(已完成使命): 0xB8强制0+NMI virt配套剥离——
	//位组嫌疑隔离形态(见common.h L系列注释)
	vmcb->Control.LbrVirtEnable = 0;
	vmcb->Control.InterceptMisc1 &= ~INTERCEPT_NMI;
	vmcb->Control.VIntr &=
		~(VINTR_V_NMI_ENABLE | VINTR_V_NMI | VINTR_V_NMI_MASK);
#else
	{
		ULONG64 b8v = (g_svmFeatBits & SVM_FEAT_LBRVIRT) ? 1ULL : 0ULL;
		if ((vmcb->Control.VIntr & VINTR_V_NMI_ENABLE) != 0)
		{
			b8v |= (g_svmFeatBits & SVM_FEAT_IBSVIRT) ? (1ULL << 2) : 0ULL;
			b8v |= (g_svmFeatBits & SVM_FEAT_PMCVIRT) ? (1ULL << 3) : 0ULL;
		}
		vmcb->Control.LbrVirtEnable = b8v;
	}
#endif
#endif
	//launch定格形态登记(裸机root上下文=真实读写; 阶梯回退时在
	//SvmLaunchThread裸机侧按级更新)
	g_svmB8Landed[(ULONG)(UCHAR)Vcpu->CpuIndex & 63] =
		(LONG64)vmcb->Control.LbrVirtEnable;
	//MSRPM布防(自我隐蔽生效前=本核发起线程裸机root态, 直写位图
	//合法, 无需vmmcall root原语):
	//  三故事MSR(EFER/VM_CR/HSAVE_PA)读写双拦位="SVM未激活"自洽
	//  故事面的载体(0x7C特判先于公共MSR API表; 读写成对置位
	//  =拦读伪造的MSR禁止写直通, msr.h使用纪律5——伪造值RMW回写
	//  真实MSR=状态毁);
	//  0x6E0(TSC_DEADLINE)仅LAPIC实处TSC-deadline模式时置双拦位
	//  (g_svmTscDlMode启动探测; 缺席时0x6E0硬件访问即#GP, root真
	//  访问=物理#GP无SEH防护=蓝屏级, 故缺席=不置位, guest直通#GP
	//  走原生路径=裸机等价)
	{
		ULONG byteOff;
		UCHAR bit;
		const ULONG32 storyMsrs[3] = {
			MSR_EFER, MSR_VM_CR, MSR_VM_HSAVE_PA
		};
		PUCHAR map = (PUCHAR)Vcpu->MsrpmVa;
		for (ULONG i = 0; i < 3; i++)
		{
			if (GnptMsrLocate(storyMsrs[i], &byteOff, &bit))
			{
				map[byteOff] |= (UCHAR)(3 << bit);    //读+写双拦位
			}
		}
		if (g_svmTscDlMode != 0 &&
			GnptMsrLocate(MSR_IA32_TSC_DEADLINE, &byteOff, &bit))
		{
			map[byteOff] |= (UCHAR)(3 << bit);
		}
	}
	vmcb->Control.IopmBasePa = Vcpu->IopmPa;     //位图全0=不拦任何端口
	vmcb->Control.MsrpmBasePa = Vcpu->MsrpmPa;   //位图: 故事面+0x6E0置位外全0
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
	#if DBG
	if (idx == 0)
	{
		//发射前一致性域直读(仅核0; 裸intrinsics, 不经故事面)
		PVMCB vmcbP = (PVMCB)Vcpu->VmcbVa;
		ULONG64 eferP = __readmsr(MSR_EFER);
		FlLog("PROBE[A] efer=%llX svme=%u vmcr=%llX hsave=%llX vmcb_pa=%llX",
			eferP, (ULONG)((eferP >> 12) & 1), __readmsr(MSR_VM_CR),
			__readmsr(MSR_VM_HSAVE_PA), Vcpu->VmcbPa);
		FlLog("PROBE[B] 0xB8=%llX asid=%u np=%u ncr3=%llX efer_v=%llX",
			vmcbP->Control.LbrVirtEnable, vmcbP->Control.GuestAsid,
			(ULONG)(vmcbP->Control.NpEnable & 1ULL), vmcbP->Control.NCr3,
			vmcbP->State.Efer);
		FlLog("PROBE[C] m1=%lX m2=%lX exc=%lX iopm=%llX msrpm=%llX",
			vmcbP->Control.InterceptMisc1, vmcbP->Control.InterceptMisc2,
			vmcbP->Control.InterceptException, vmcbP->Control.IopmBasePa,
			vmcbP->Control.MsrpmBasePa);
		FlLog("PROBE[D] cr0=%llX cr4=%llX rflags=%llX",
			vmcbP->State.Cr0, vmcbP->State.Cr4, vmcbP->State.Rflags);
	}
	#endif
	FlLog("SVM: 核%u接管(vmrun循环就绪)", idx);
	FlArmLaunchWatch();      //vmrun观测预热(仅Debug构建有实体; Release空宏)
	CmSvmEnter(Vcpu);         //世界开关; "返回"=本核已guest化(launch失败除外)
	g_flLaunchHot = 0;
	//NMI virt+0xB8位组阶梯回退(产品级): 首试VMRUN一致性被拒时逐级
	//降形态重试——未知微架构合置硬门类(全核VMEXIT_INVALID形态在档)
	//下, 框架自动定格到本机可运行的最强形态而非拒绝虚拟化。
	//阶梯1: 剥IBS/PMC(b2/b3)与配套NMI virt→LBR独留;
	//阶梯2: 再剥LBR→位组全零; 仍败=拒绝源在位组外→裸机收尾(回滚)
	if (!Vcpu->base.bInGuest && Vcpu->base.bLaunchFailed)
	{
		PVMCB vmcbP = (PVMCB)Vcpu->VmcbVa;
		if (((vmcbP->Control.LbrVirtEnable & ~1ULL) != 0) ||
		    ((vmcbP->Control.VIntr & VINTR_V_NMI_ENABLE) != 0))
		{
			vmcbP->Control.LbrVirtEnable &= 1ULL;
			vmcbP->Control.InterceptMisc1 &= ~INTERCEPT_NMI;
			vmcbP->Control.VIntr &=
				~(VINTR_V_NMI_ENABLE | VINTR_V_NMI | VINTR_V_NMI_MASK);
			g_svmB8Landed[idx & 63] = (LONG64)vmcbP->Control.LbrVirtEnable;
			Vcpu->base.bLaunchFailed = 0;
			FlLog("SVM: 核%u首试被拒→阶梯1(LBR独留, 剥IBS/PMC+NMI virt)重试", idx);
			FlArmLaunchWatch();
			CmSvmEnter(Vcpu);
			g_flLaunchHot = 0;
			FlLog("SVM: 核%u阶梯1: %s", idx,
				Vcpu->base.bInGuest ? "接管成功" :
				Vcpu->base.bLaunchFailed ? "仍拒→进阶梯2" : "探针未确认");
			if (!Vcpu->base.bInGuest && Vcpu->base.bLaunchFailed &&
				((vmcbP->Control.LbrVirtEnable & 1ULL) != 0))
			{
				vmcbP->Control.LbrVirtEnable = 0;
				g_svmB8Landed[idx & 63] = 0;
				Vcpu->base.bLaunchFailed = 0;
				FlLog("SVM: 核%u→阶梯2(0xB8全零)重试", idx);
				FlArmLaunchWatch();
				CmSvmEnter(Vcpu);
				g_flLaunchHot = 0;
				FlLog("SVM: 核%u阶梯2: %s", idx,
					Vcpu->base.bInGuest ? "接管成功(拒绝源含LBR virt)" :
					"仍拒(拒绝源在位组外)");
			}
		}
	}
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
	g_svmVcpuCount = 0;    //引擎已关: root原语钉核失效
	//故事面计数总结——自然流量应近零, 超出=demo探针量或探测者在场
	//('m'环含msr明细)
	FlLog("%s: S1故事面计数: EFER读%lld/写%lld VM_CR读%lld/写%lld HSAVE读%lld/写%lld",
		why, g_svmStoryRd[0], g_svmStoryWr[0],
		g_svmStoryRd[1], g_svmStoryWr[1],
		g_svmStoryRd[2], g_svmStoryWr[2]);
	//#GP处置账: 族转换数应=探针量; 忠实回注=自然#GP(静置应≈0)
	FlLog("%s: S1#GP手术: 族转换#UD=%lld 忠实回注=%lld(0x4D exit总账见r4D)",
		why, g_svmGpUdConv, g_svmGpReinj);
	FlLog("%s: 完成(泄漏核掩码=%X)", why, leaked);
}

//==================== 生命周期 ====================
//虚拟化核数(0=引擎未起; =实际接管数)
volatile ULONG g_svmVcpuCount = 0;
//停泊哨兵: 各核最后#VMEXIT的TSC——HB心跳检查"核在VMRUN里停泊
//过久"(idle停泊正常=guest真实hlt; >2s且系统活动=IPI丢失嫌疑现场)
volatile LONG64 g_svmLastExitTsc[64] = { 0 };
//各核launch定格的0xB8形态: FillVmcb裸机root登记首试值, launch
//阶梯回退在裸机root更新终值——探针(DemoPmuProbe)只读此全局。
//勿从guest上下文读VMCB同名字段: 自我隐蔽已改译, guest读=零页
volatile LONG64 g_svmB8Landed[64] = { 0 };
//异常exit防御自愈登记: default防御路径(GIF=0上下文)剥位自愈时
//写exit码+1(0=无/探针已清)。自证探针只读此纯全局——自我隐蔽
//生效后guest读VMCB=零页, 框架状态回读必须走纯全局
volatile LONG64 g_svmDefHeal[64] = { 0 };

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

//部分接管安全门: 裸核上hook布防/root原语=蓝屏, 低剂量(TAKE_CORES<64)
//仅限纯引擎诊断形态(零hook零MSR面)放行; 纯引擎Debug诊断构建经
//显式临时宏豁免先例(改门时保留该豁免通道语义)
#if GNPT_TAKE_CORES < 64
#error "GNPT_TAKE_CORES<64 仅限纯引擎诊断形态(零hook零MSR面)"
#endif

NTSTATUS SvmStartAllCpus(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	ULONG totalCpu = KeQueryActiveProcessorCount(NULL);
	ULONG cpuCount = totalCpu;
	//全核接管=正式形态(部分接管=纯引擎诊断剂量轮, 见上方#error门)
#if GNPT_TAKE_CORES == 0
	cpuCount = 0;
#elif GNPT_TAKE_CORES < 64
	if (cpuCount > GNPT_TAKE_CORES)
	{
		cpuCount = GNPT_TAKE_CORES;
	}
#endif
	g_svmVcpuCount = cpuCount;    //root原语钉核依据(=实际接管数)
	if (totalCpu > 64)
	{
		FlLog("GNPT: 拒绝启动: %u核超64(单组上限)", totalCpu);
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
	//STGI直通门控: SKINIT特性在场=裸机STGI静默执行→拦截位不设=
	//直通忠实; 缺席=拦截+#UD注入(保守)
	__cpuidex(feat, 0x80000001, 0);
	g_svmStgiPass = ((feat[2] >> CPUID_SKINIT_ECX_BIT) & 1) != 0;
	FlLog("%s AMD SVM引擎 %s | %u核 | SVM=%s rev=%u ASID=%u",
		"GNPT", GNPT_BUILD_TAG, cpuCount, stateText, svmRev, nasid);
	FlLog("特性: NP=%d NRIPS=%d VmcbClean=%d FlushByAsid=%d DecodeAssists=%d VGIF=%d VMSAVEvirt=%d",
		(featBits >> 0) & 1, (featBits >> 3) & 1, (featBits >> 5) & 1,
		(featBits >> 6) & 1, (featBits >> 7) & 1, (featBits >> 16) & 1,
		(featBits >> 15) & 1);
	//指令虚拟化首试形态预告(NMI virt+0xB8按特性组合; launch首试被
	//拒时阶梯逐级回退, 定格形态以阶梯结果为准, 见SvmLaunchThread)
	{
		ULONG nmiVirtOn = ((featBits & SVM_FEAT_VNMI) != 0 &&
			(featBits & (SVM_FEAT_IBSVIRT | SVM_FEAT_PMCVIRT)) != 0) ? 1 : 0;
		FlLog("指令虚拟化: VNMI=%u IBSVIRT=%u PMCVIRT=%u → 首试形态=%s%s",
			(featBits >> 25) & 1, (featBits >> 26) & 1, (featBits >> 8) & 1,
			nmiVirtOn ? "NMI virt+LBR|IBS|PMC(按特性)" : "LBR-only(投递配套门未满足)",
			nmiVirtOn ? "; 被拒时launch阶梯回退" : "");
	}
	FlLog("STGI门控: SKINIT特性=%u → %s", g_svmStgiPass,
		g_svmStgiPass ? "直通(裸机等价: 硬件静默执行)"
		              : "拦截+#UD(无SKINIT特性, 保守忠实)");
	//0x6E0模式探测(裸机PASSIVE, SEH可用): LAPIC非TSC-deadline模式时
	//0x6E0访问硬件#GP——若置拦截, 处置的root真访问=物理#GP无防护
	//=蓝屏级。缺席=不置拦截位(guest直通#GP走原生路径=裸机等价)
	{
		ULONG code = 0;
		__try
		{
			(void)__readmsr(MSR_IA32_TSC_DEADLINE);
			g_svmTscDlMode = 1;
		}
		__except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
		{
			g_svmTscDlMode = 0;
		}
		FlLog("0x6E0轴换算门控: LAPIC %s(异常码%X)",
			g_svmTscDlMode ? "TSC-deadline模式→拦截+换算" : "非deadline模式→直通(裸机等价)",
			code);
	}
	//INIT重定向: VM_CR.R_INIT(bit1)置1=外部INIT经#SX异常可见化
	//(§15.21.8)——外部INIT的死法从静默复位变为可观察事件。
	//发起核一次性写(VM_CR为每核MSR, 其余核不写)。LOCK置位后
	//写被忽略(回读不符=如实报告, 不阻断启动——纯观测面)
	{
		ULONG64 vmCr = __readmsr(MSR_VM_CR);
		__writemsr(MSR_VM_CR, vmCr | VM_CR_R_INIT);
		ULONG64 vmCrBack = __readmsr(MSR_VM_CR);
		FlLog("INIT重定向: VM_CR=%llX R_INIT=%u%s",
			(unsigned long long)vmCrBack,
			(ULONG)((vmCrBack >> 1) & 1),
			((vmCrBack >> 1) & 1) ? "=已重定向(#SX可见化)" :
			"=写被忽略(观察仅, 不阻断)");
	}
#if GNPT_SMI_INTERCEPT
	{
		//go/no-go: HWCR bit0=SMMLOCK——1=固件锁死SMM, SMI拦截
		//被硬件忽略(死亡轴终局证据); 0=拦截可生效(修复+杀手首度可见)
		ULONG64 hwcr = __readmsr(MSR_HWCR);
		FlLog("SMI拦截: HWCR=%llX SMMLOCK(bit0)=%u%s",
			(unsigned long long)hwcr, (ULONG)(hwcr & 1ULL),
			(hwcr & 1ULL) ? "=固件锁死, 拦截将被硬件忽略!" : "=拦截可生效");
	}
#endif
#if GNPT_CPUID_STEALTH
	FlLog("CPUID伪装: 拦截位在位(Fn8000_0001 SVM位清零/无签名leaf归零)");
#else
	FlLog("CPUID伪装: 关闭(全真值直透传)");
#endif
	//CET平台取证(冷横幅一行): CR4.CET=1=shadow stack使能——本状态
	//下清CR0.WP=Mov CR0架构性#GP(APM Vol1 CR0.WP位规则)。宿主OS
	//运行期从不写CR0故该位平时无观测面; 引擎任何CR0写入路径的
	//平台适配判据在此行
	FlLog("CET: CR4=%llX CET(bit23)=%u%s",
		(unsigned long long)__readcr4(),
		(ULONG)((__readcr4() >> 23) & 1),
		((__readcr4() >> 23) & 1) ?
		"=shadow stack在位(CR0.WP不可清)" : "=WP瞬清可用");
	//故事面布防声明(位在各核SvmFillVmcb置; 含#GP处置——SVM指令族
	//#GP先于拦截位, Table 15-7)
	FlLog("S1故事: SVM未激活——EFER读伪SVME=0/VM_CR伪0x18(BIOS锁死=第二"
		"实例自拒)/HSAVE影子0; 指令族8条#UD+#GP手术; 0xB8 virt=0x%llX(%s%s%s)",
		((g_svmFeatBits & SVM_FEAT_LBRVIRT) ? 1ULL : 0ULL) |
		((g_svmFeatBits & SVM_FEAT_IBSVIRT) ? 4ULL : 0ULL) |
		((g_svmFeatBits & SVM_FEAT_PMCVIRT) ? 8ULL : 0ULL),
		(g_svmFeatBits & SVM_FEAT_LBRVIRT) ? "LBR " : "",
		(g_svmFeatBits & SVM_FEAT_IBSVIRT) ? "IBS " : "",
		(g_svmFeatBits & SVM_FEAT_PMCVIRT) ? "PMC" : "");
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
	//NPT两视图构建(静态共享树, 先于每核资源分配):
	//P=常态 / HOOKS=常规hook驻留
	{
		ULONG64 ncr3[GNPT_VIEW_COUNT] = { 0, 0 };
		ULONG nptPages = 0;
		ULONG64 nptCover = 0;
		if (!SvmBuildNptViews(ncr3, &nptCover, &nptPages))
		{
			FlLog("[Entry] NPT两视图构建失败(内存不足?), 拒绝接管");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		g_svmNcr3 = ncr3[GNPT_VIEW_PRIMARY];
		FlLog("NPT: PML4[0]全2MB叶覆盖%lluGB+高区1GB叶全空间; 共%u页; "
			"两视图就绪 P=%llX HOOKS=%llX",
			nptCover >> 30, nptPages,
			ncr3[GNPT_VIEW_PRIMARY], ncr3[GNPT_VIEW_SECONDARY]);
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
	if (!SvmNptConcealAll())
	{
		FlLog("[Entry] 自我隐蔽失败(内存不足?), 无隐蔽继续(功能不受影响)");
	}
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
	g_gnptVcpuCpu = (cpuCount != 0) ? 0 : -1;    //观测锚点核(HB行vcpu字段)
	FlLog("SVM: 接管完成(%u/%u核in-guest)", cpuCount, totalCpu);
	return STATUS_SUCCESS;
}

//返回TRUE=全核已裸机(引擎真正关停); FALSE=拒绝/未在位(引擎仍在位)
BOOLEAN SvmShutdownAllCpus(VOID)
{
	//实际接管数(TAKE_CORES诊断轮<全核; 从未启动=0同样成立)
	ULONG n = g_svmVcpuCount;
	//park守卫: park核的VMM栈/代码页被占用, 释放=蓝屏; 拒绝并泄漏
	if (g_gnptParkedMask != 0)
	{
		FlLog("[Unload] 拒绝去虚拟化: park掩码=%X非零(资源泄漏保留)", g_gnptParkedMask);
		return FALSE;
	}
	//从未启动(或已回滚): 无线程可退; 零接管对照轮(TAKE_CORES=0)
	//仍有NPT树在位, 单独释放(零核曾VMRUN, 无引用=安全)
	if (g_svmVcpu[0].ThreadObj == NULL)
	{
		if (g_svmNcr3 != 0)
		{
			ULONG nptPages = SvmNptPageCount();
			SvmFreeNpt();
			g_svmNcr3 = 0;
			FlLog("[Unload] 零接管对照: NPT释放(%u页)", nptPages);
		}
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

//==================== "SVM未激活"自洽故事面 ====================
//三MSR读写双拦处置器(0x7C特判, 先于公共MSR API表):
//  EFER读: 伪造SVME=0——取VMCB.State.Efer&~SVME。#VMEXIT时硬件已把
//          guest EFER回存VMCB(§15.6), 其SVME位恒1(vmrun一致性检查
//          要求+写路径强制), 按位清0=裸机Windows形态(SCE|LME|LMA|NXE)。
//          必须读VMCB而非真MSR: 真MSR此刻=host EFER(HSAVE回装), 两者
//          仅SVME同值是巧合, guest写EFER后即分叉——读VMCB=往返忠实
//  EFER写: 忠实代写但强制SVME=1——只写VMCB.State.Efer(guest EFER的
//          权威载体, vmrun从此装载; 写真MSR=污染host态且下轮vmrun被
//          VMCB覆盖=无效且有害)。强制SVME=1双保险: ①vmrun一致性检查
//          要求 ②防OS用伪造读值(SVME=0)RMW回写自锁死引擎
//  VM_CR读: 伪造LOCK|SVMDIS=0x18("BIOS锁死SVM禁用"故事)——第二实例
//          CommCheckSvm见SVMDIS=1判"BIOS禁用"秒级干净自拒=无痕互斥仲裁
//  VM_CR写: 静默丢弃——真硬件LOCK=1时LOCK/SVMDIS写本就被忽略(§15.30)
//          =忠实; guest认为写成功, 读回0x18不变=锁死故事自洽
//  HSAVE读: 影子值(初0=裸机无人写过的形态; 真值=引擎host保存区物理
//          地址=探测器天赐铁证, 必堵)。影子按核: 真MSR本就per-core
//  HSAVE写: 写影子不写真MSR(真写=下轮#VMEXIT把host状态写进垃圾地址
//          =致命)。写后读回=影子往返=与裸机SVME=0的RMW往返一致
//指令族(0x7A/0x80/0x82-0x86): 全部#UD注入(fault语义不推RIP)=裸机
//SVME=0等价; vmmcall(0x81)不在族内——签名门自持#UD路径('u'/'B'环)
//自然流量预期≈0: 三MSR读/写各留计数(状态变量在文件头
//全局区——SvmStopAndFree停机总结引用), 停机总结对账

//0x7C故事特判处置(GIF=0上下文): 调用方负责推RIP(写路径NRIP恒有效)
static VOID SvmStoryMsrHandle(PVMCB vmcb, ULONG cpu, ULONG32 msr, BOOLEAN isWrite,
	PGUEST_REGS Regs)
{
	ULONG idx = (msr == MSR_EFER) ? 0 : (msr == MSR_VM_CR) ? 1 : 2;
	if (isWrite)
	{
		ULONG64 val = (ULONG64)(ULONG)Regs->rax | ((ULONG64)(ULONG)Regs->rdx << 32);
#if DBG
		InterlockedIncrement64(&g_svmStoryWr[idx]);
#endif
		if (msr == MSR_EFER)
		{
			vmcb->State.Efer = val | EFER_SVME;    //强制SVME=1; 只写VMCB(guest权威态)
		}
		else if (msr == MSR_VM_CR)
		{
			;    //静默丢弃=真硬件LOCK=1忽略写(忠实)
		}
		else
		{
			g_svmHsaveShadow[cpu & 63] = val;    //影子往返(写真MSR=致命)
		}
	}
	else
	{
#if DBG
		InterlockedIncrement64(&g_svmStoryRd[idx]);
#endif
		ULONG64 val;
		if (msr == MSR_EFER)
		{
			val = vmcb->State.Efer & ~EFER_SVME;      //伪造SVME=0(裸机Windows形态)
		}
		else if (msr == MSR_VM_CR)
		{
			val = VM_CR_LOCK | VM_CR_SVMDIS;          //0x18: "BIOS锁死"故事
		}
		else
		{
			val = g_svmHsaveShadow[cpu & 63];         //影子(初0)
		}
		//RAX=低32走VMCB(asm契约: 帧rax槽vmrun时被VMCB.RAX覆盖),
		//RDX=高32=帧GPR正常路径(与通用读回放同型)
		vmcb->State.Rax = val & 0xFFFFFFFFULL;
		Regs->rax = val & 0xFFFFFFFFULL;
		Regs->rdx = val >> 32;
	}
	//'m'环已在0x7C入口统一采样(msr+读写位+计数), 此处不再推环
}

//0x6E0 TSC_DEADLINE轴换算(0x7C特判, GIF=0上下文; 调用方负责推RIP):
//LAPIC按物理TSC比较deadline, guest按虚拟轴编程(RDTSC=物理TSC+
//TscOffset)→不换算则触发时刻整体偏移|TscOffset|(补偿壳驻留扣减
//随累计增长)。读写双向换算, offset每exit实时读当前核VMCB(动态):
//  写: 真写 D_h = D_g - TscOffset(物理轴等效触发时刻;
//       0=关闭deadline, 换算恒等, 自然对)
//  读: 真读 D_h; !=0(在飞)返回 D_g = D_h + TscOffset(guest视角);
//       ==0(未设/已触发自清)返回0=裸机语义忠实。
//  残差=写读间offset变化(补偿壳逐exit扣减, 量级=单exit驻留ns级
//  =对deadline语义无影响)
static VOID SvmTscDeadlineHandle(PVMCB vmcb, BOOLEAN isWrite, PGUEST_REGS Regs)
{
	ULONG64 tscOffset = vmcb->Control.TscOffset;
	if (isWrite)
	{
		ULONG64 val = (ULONG64)(ULONG)Regs->rax | ((ULONG64)(ULONG)Regs->rdx << 32);
		__writemsr(MSR_IA32_TSC_DEADLINE, val - tscOffset);
	}
	else
	{
		ULONG64 val = __readmsr(MSR_IA32_TSC_DEADLINE);
		if (val != 0)
		{
			val += tscOffset;
		}
		//RAX=低32走VMCB(asm契约: 帧rax槽vmrun时被VMCB.RAX覆盖),
		//RDX=高32=帧GPR正常路径
		vmcb->State.Rax = val & 0xFFFFFFFFULL;
		Regs->rax = val & 0xFFFFFFFFULL;
		Regs->rdx = val >> 32;
	}
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
	//拦截位永久泄漏=全系统pushf/popf风暴+guest破坏
	GnptHookStepLeakCheck(vmcb, cpu);
	//MOV DR拦截(0x20-0x3F, Table C-1: [4]=方向0读/1写, [3:0]=DR号)
	//→hook.c影子仿真(guest读写只到影子, 硬件DR/VMCB.Dr6/7不受
	//guest触碰)。拦截位=VMCB静态置位, 到达即本case
	if (exitCode >= 0x20 && exitCode < 0x40)
	{
		GnptHookDrMovExit(vmcb, cpu, Regs, (ULONG)exitCode);
		return 0;
	}
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
					func != GNPT_VMCALL_MSRBIT && func != GNPT_VMCALL_MEMCPY &&
					func != GNPT_VMCALL_CONCEAL && func != GNPT_VMCALL_DRSET &&
					func != GNPT_VMCALL_NXREARM && func != GNPT_VMCALL_DEFTEST))
			{
				//签名门拒绝采样(防刷爆环; Release构建零开销)
				static volatile LONG s_sigCnt[64] = { 0 };
				GNPT_CRUMB(s_sigCnt, 0xFFF, cpu,
					FlRingPush('u', cpu, SVM_EXIT_VMMCALL, func,
						vmcb->State.Cs.Selector, 0));
				//EVENTINJ注入#UD: TYPE=3(异常) vector=6 无错误码
				vmcb->Control.EventInj = EVENTINJ_MAKE(6, EVENTINJ_TYPE_EXCP, 0, 0);
				static volatile LONG s_udCnt[64] = { 0 };
				GNPT_CRUMB(s_udCnt, 0xFFF, cpu,
					FlRingPush('B', cpu, SVM_EXIT_VMMCALL, vmcb->State.Rip, 0, 0));
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
				case GNPT_VMCALL_NPTSYNC:    //NPT改动TLB同步: 下轮vmrun冲净全部翻译
				{
					//同页"+0取原始字节(push rbx执行)+2取CodePage补丁
					//字节(add[rax],al写只读页→0x50)"的取指中途翻转已
					//收口: 根因=Zen op-cache(线性标记译码缓存)陈旧项跨arm
					//存活: ①CPUID序列化被证伪(序列化只保证指令流有序,
					//不无效化译码缓存条目; 全核'i'环确认执行仍复发);
					//②陈旧项来源=轮间卸载窗口的无hook期自然流量持续刷新
					//原始译码项, arm时的同步必须把它当作"必然存在"处置。
					//修复: ①TlbControl 3→1: 全TLB冲净(含他ASID/host条目);
					//②root态WBINVD: APM明文"invalidates internal caches"
					//=L1I/L1D/L2/op-cache全无效化(写回脏行零数据损失,
					//且自身序列化)——译码缓存唯一的文档化软件无效化
					//手段(NPT改译无内存写, SMC检测永不触发, 别无他途)。
					//op-cache命中绕过TLB行走=NX翻译拦不住, 故必须真冲。
					//成本=每核一次全缓存写回+无效化(~百μs级), install/
					//remove频度可接受; INVD(丢脏行)绝对禁止
					vmcb->Control.TlbControl = 1;
					__wbinvd();    //全缓存无效化: op-cache含
					FlRingPush('i', cpu, GNPT_VMCALL_NPTSYNC, 0, 0, 0);    //每核同步确认(触发链面包屑)
					SvmAdvanceRip(vmcb);
					return 0;
				}
				case GNPT_VMCALL_NPTSET:    //root写原语: 视图PTE(隐蔽后动态写唯一正道)
				{
					SvmNptRootCtxMark(TRUE);    //现场拆分只许arena槽切取
					SvmNptSetPte((ULONG)(arg2 >> 48) & 0xF, arg1,
						arg2 & 0x0000FFFFFFFFFFFFULL, arg3);
					SvmNptRootCtxMark(FALSE);
					FlRingPush('n', cpu, GNPT_VMCALL_NPTSET, arg1, arg2, arg3);
					SvmAdvanceRip(vmcb);
					return 0;
				}
				case GNPT_VMCALL_NPTRES:    //root恢复原语: 单树(0/1)/全树(0xF)恒等
				{
					ULONG vw = (ULONG)arg2 & 0xF;
					SvmNptRootCtxMark(TRUE);    //未拆分区恢复=现场拆分, 同上限
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
					SvmNptRootCtxMark(FALSE);
					FlRingPush('n', cpu, GNPT_VMCALL_NPTRES, arg1, arg2, 0);
					SvmAdvanceRip(vmcb);
					return 0;
				}
				case GNPT_VMCALL_MEMCPY:    //root拷贝原语: 已隐蔽页的guest态写=写fault, 须root代写(NPT不适用root)
				{
					BOOLEAN ok = (arg3 != 0 && arg3 <= PAGE_SIZE);
					if (ok)
					{
						RtlCopyMemory((PVOID)arg1, (PVOID)arg2, (SIZE_T)arg3);
					}
					FlRingPush('M', cpu, GNPT_VMCALL_MEMCPY, arg1, arg2, arg3);
					vmcb->State.Rax = ok ? 1 : 0;
					Regs->rax = vmcb->State.Rax;
					SvmAdvanceRip(vmcb);
					return 0;
				}
				case GNPT_VMCALL_CONCEAL:    //运行期工件隐蔽: 身份PTE两视图零页
				{
					SvmNptRootCtxMark(TRUE);
					BOOLEAN ok = SvmNptConcealPageRuntime(arg1);
					SvmNptRootCtxMark(FALSE);
					FlRingPush('c', cpu, GNPT_VMCALL_CONCEAL, arg1,
						ok ? 1 : 0, (ULONG64)SvmNptConcealCount());
					vmcb->State.Rax = ok ? 1 : 0;
					Regs->rax = vmcb->State.Rax;
					SvmAdvanceRip(vmcb);
					return 0;
				}
				case GNPT_VMCALL_DRSET:    //DR-TRANSPARENT武装/解除(每核root态)
				{
					//机件契约: arg1=slot(bit0-1)|on(bit8), arg2=入口
					//线性地址(on=1)。DR0-3不在VMCB=本核root态
					//__writedr直写(跨VMRUN持续); Dr7=VMCB guest state。
					//guest优先租用制: 被guest占用(影子DR7启用)的槽
					//让位(该核fail-open), guest释放时经MOV DR7合并
					//路径自动重武装(hook.c)
					GnptHookDrArmCore(vmcb, cpu, (ULONG)(arg1 & 3),
						(arg1 & 0x100) != 0, arg2);
					FlRingPush('g', cpu, (ULONG)arg1, arg2,
						vmcb->State.Dr7, 0);
					SvmAdvanceRip(vmcb);
					return 0;
				}
				case GNPT_VMCALL_NXREARM:    //NX-Fence detour收尾(stub尾自发):
				{
					//在途detour旗清+视图回P(fence重武装); 旗不在=
					//移除后补发等竞态形态(hook.c静默)。处置见GnptHookNxRearm
					GnptHookNxRearm(vmcb, cpu);
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
			case GNPT_VMCALL_DEFTEST:    //防御自证原语(demo探针): 制造拦截
				{                        //向量异常→default剥位自愈全链验证
					//置位本核RDTSC拦截位(生产形态此位不在位)+自愈登记清零;
					//guest随后首条rdtsc应exit(0x6E)→default剥位自愈+登记
					//→不推RIP重入→直通完成(全链语义见default注释)
					vmcb->Control.InterceptMisc1 |= INTERCEPT_RDTSC;
					g_svmDefHeal[cpu & 63] = 0;
					FlRingPush('x', cpu, GNPT_VMCALL_DEFTEST,
						vmcb->Control.InterceptMisc1, 0, 0);
					SvmAdvanceRip(vmcb);
					return 0;
				}
				default:
					break;    //白名单已收窄, 不可达
			}
			break;
		}
		case SVM_EXIT_INVLPGA:   //0x7A: 指令族(见下方case组注释)
		case SVM_EXIT_VMRUN:     //0x80: 拦截位must-1(硬件强制)——从default
		case SVM_EXIT_VMLOAD:    //0x82: 吞掉推进改为#UD注入(裸机等价)
		case SVM_EXIT_VMSAVE:    //0x83
		case SVM_EXIT_STGI:      //0x84: 仅SKINIT特性缺席配置可达(在场=直通不拦截, 见FillVmcb门控)
		case SVM_EXIT_CLGI:      //0x85
		case SVM_EXIT_SKINIT:    //0x86
			//SVM指令族#UD注入——裸机Windows(SVME=0)全族#UD(§15.4),
			//guest内SVME=1硬件照常执行=行为差; 显式拦截+注入=完整
			//裸机故事(与EFER读伪造SVME=0互证)。EVENTINJ注入不经
			//拦截检查(§15.20), #UD直达guest IDT=与裸机#UD同路; fault
			//语义不推RIP。'v'环采样(预期个位数; Release构建零开销)
		{
			static volatile LONG s_svmUdCnt[64] = { 0 };
			GNPT_CRUMB(s_svmUdCnt, 0xFFF, cpu,
				FlRingPush('v', cpu, (ULONG)exitCode, vmcb->State.Rip, 0, 0));
		}
			vmcb->Control.EventInj = EVENTINJ_MAKE(6, EVENTINJ_TYPE_EXCP, 0, 0);
			return 0;
		case SVM_EXIT_EXCP_GP:    //0x4D: #GP拦截处置(手术转换)
		{
			//Table 15-7(§15.9): SVM指令族"Checks exceptions(#GP) before
			//the intercept"→VMRUN/VMSAVE/VMLOAD非规范PA形态(超MAXPHYADDR/
			//未4KB对齐, 24594 Vol4页503异常表)硬件在guest内raise #GP,
			//拦截位不触发; 裸机SVME=0全族#UD(Vol4页500/503 Action伪代码:
			//SVME检查第一位)→#GP≠#UD=自洽故事差。
			//手术: fault指令字节∈SVM族(0F 01 D8-DF)→改注入#UD(裸机
			//等价); 否则忠实回注#GP(§15.12: 错误码载体=EXITINFO1, 向量=
			//EXITCODE)。§15.8.4: 指令字节仅#PF填充(GuestInstructionBytes
			//其余exit清零)→必直读RIP。字节读安全: #GP由指令执行raise→该
			//指令已fetch→RIP页驻留; 非规范RIP(理论不可达)守卫=不读回注。
			//前置事件链(EXITINTINFO.V=1双错级路径)不组合——该路径本就
			//致死, 回注本#GP=忠实方向(边界已文档化)
			ULONG64 rip = vmcb->State.Rip;
			BOOLEAN family = FALSE;
			//x64规范地址判据: bits63:47全0或全1
			if ((rip >> 47) == 0 || (rip >> 47) == 0x1FFFF)
			{
				PUCHAR p = (PUCHAR)rip;
				if (p[0] == 0x0F && p[1] == 0x01 && (p[2] & 0xF8) == 0xD8)
				{
					family = TRUE;    //0F 01 D8-DF全族(8条)
				}
			}
			static volatile LONG s_gpCnt[64] = { 0 };
			GNPT_CRUMB(s_gpCnt, 0xFFF, cpu,
				FlRingPush('G', cpu, SVM_EXIT_EXCP_GP, rip,
					(ULONG64)(ULONG)family, 0));
		if (family)
		{
#if DBG
			InterlockedIncrement64(&g_svmGpUdConv);
#endif
			vmcb->Control.EventInj = EVENTINJ_MAKE(6, EVENTINJ_TYPE_EXCP, 0, 0);
		}
		else
		{
#if DBG
			InterlockedIncrement64(&g_svmGpReinj);
#endif
			vmcb->Control.EventInj = EVENTINJ_MAKE(13, EVENTINJ_TYPE_EXCP,
				1, vmcb->Control.ExitInfo1);    //忠实回注(错误码=EXITINFO1)
		}
		return 0;    //fault语义不推RIP(#GP/#UD皆指向引发指令)
		}
		case SVM_EXIT_CPUID:    //0x72: 真值打底+伪装位修整(裸机等价校准)
		{
			int info[4] = { 0 };
			__cpuidex(info, (int)Regs->rax, (int)Regs->rcx);
#if GNPT_CPUID_STEALTH
			//伪装三则(固件级禁用形态, 与S1故事面VM_CR伪LOCK|SVMDIS
			//自洽——真实世界固件禁SVM正是CPUID位清+SVMDIS置组合):
			//①Fn8000_0001 ECX bit2(SVM位)清零; 绝不全零返回(特性
			//  位全丢=系统行为未定义)
			//②hypervisor专用leaf(0x40000000-0x4000000F)全零
			//  (无签名泄漏; 嵌套场景下层签名不穿透)
			//③maxleaf不收敛(比真值小=检测特征; 防嵌套抬高层新平台
			//  无场景, 保持真值)
			{
				ULONG leaf = (ULONG)Regs->rax;
				if (leaf == 0x80000001)
				{
					info[2] &= ~(1 << 2);
				}
				else if (leaf >= 0x40000000 && leaf <= 0x4000000F)
				{
					info[0] = 0;
					info[1] = 0;
					info[2] = 0;
					info[3] = 0;
				}
			}
#endif
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
			//'m'环采样(首条+每4096条; Release构建零开销)
			static volatile LONG s_msrCnt[64] = { 0 };
			GNPT_CRUMB(s_msrCnt, 0xFFF, cpu,
				FlRingPush('m', cpu, SVM_EXIT_MSR, msr,
					(ULONG64)(ULONG)isWrite, (ULONG64)gnCrumb));
			//故事三MSR特判(引擎保留, 先于公共MSR API表——公共表对这些
			//MSR的Install已被GnptMsrIsEngineReserved拒绝)
			if (msr == MSR_EFER || msr == MSR_VM_CR || msr == MSR_VM_HSAVE_PA)
			{
				SvmStoryMsrHandle(vmcb, cpu, msr, isWrite, Regs);
				SvmAdvanceRip(vmcb);
				return 0;
			}
			//0x6E0轴换算特判(引擎保留, Install拒绝同上)。仅在
			//g_svmTscDlMode=1时拦截位已置=本分支可达; mode=0时无拦截
			//位=本MSR直通零exit(root真访问缺席模式=#GP=不可入此处置)
			if (msr == MSR_IA32_TSC_DEADLINE)
			{
				SvmTscDeadlineHandle(vmcb, isWrite, Regs);
				SvmAdvanceRip(vmcb);
				return 0;
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
			//'N'环: a=faulting gpa(EXITINFO2) b=错误码(EXITINFO1) c=guest RIP;
			//错误码位域: bit0 P/bit1 RW/bit2 US/bit3 RSV/bit4 ID(取指)/
			//bit6 SS/bit32 终译fault/bit33 guest页表fault(§15.25.6)
			//风暴探针(仅Debug构建): 同gpa连续32次=单发'F'全档转储
			//(五事件: RIP/错误码/gpa + 易失GPR三组 + 指令字节
			//(DecodeAssists) + VMCB的CR组), 此后该核'N'静音(防行环
			//溢出吞转储+保T1落盘窗口); vmrun重执行循环不动=行为
			//不变劣(冻结形态与泄漏语义原样保留)
#if DBG
			{
				ULONG64 stormGpa = vmcb->Control.ExitInfo2;
				ULONG sc = cpu & 63;
				if (g_nStormGpa[sc] != stormGpa)
				{
					g_nStormGpa[sc] = stormGpa;
					g_nStormCnt[sc] = 0;
				}
				if (InterlockedIncrement(&g_nStormCnt[sc]) == 32)
				{
					g_nStormDone[sc] = 1;
					//五档单发, reason=档位序号, a/b/c=载荷(各64位):
					//1=RIP/错误码/gpa 2-3=易失GPR六值
					//4=指令字节16B+字节数(DecodeAssists) 5=guest CR组
					FlRingPush('F', cpu, 1, vmcb->State.Rip,
						vmcb->Control.ExitInfo1, stormGpa);
					FlRingPush('F', cpu, 2, Regs->rax, Regs->rcx, Regs->rdx);
					FlRingPush('F', cpu, 3, Regs->rbx, Regs->rsi, Regs->rdi);
					FlRingPush('F', cpu, 4,
						*(ULONG64*)(ULONG_PTR)vmcb->Control.GuestInstructionBytes,
						*(ULONG64*)(ULONG_PTR)(vmcb->Control.GuestInstructionBytes + 8),
						(ULONG64)vmcb->Control.NumOfBytesFetched);
					FlRingPush('F', cpu, 5, vmcb->State.Cr0,
						vmcb->State.Cr3, vmcb->State.Cr4);
				}
				if (!g_nStormDone[sc])
				{
					FlRingPush('N', cpu, SVM_EXIT_NPF, stormGpa,
						vmcb->Control.ExitInfo1, vmcb->State.Rip);
				}
			}
#endif
			return 0;    //fault语义: 不推RIP(FlRingExit计数+限流兜底)
		}
		case SVM_EXIT_EXCP_DB:    //0x41: #DB路由(窗口认领→DR位路由→残余甄别)
		{
			//路由顺序: ①单步机件窗口认领(我方注入TF的簿记收尾,
			//  含同场B位的DrBpDbExit二级路由) ②DR位路由(hook.c:
			//  guest断点/TF陷阱忠实投递=调试子系统裸机等价;
			//  我方断点改道; 探测期让位) ③残余甄别(int1/ICEBP
			//  软件陷阱忠实投递; 其余=我方簿记畸形的最后防线吞)
			if (GnptHookStepDbExit(vmcb, cpu))
			{
				GnptHookDrBpDbExit(vmcb, cpu);
				return 0;
			}
			if (GnptHookDrBpDbExit(vmcb, cpu))
			{
				return 0;
			}
			//残余#DB(无B无BS): 指令字节甄别后分流。
			//int1(CD 01)/ICEBP(F1)源: 软件中断陷阱, DR6零位设置
			//=唯一合法残余源(我方TF泄漏恒带BS→'a'路径, DR断点恒
			//带B→位路由)。裸机语义=投递(R3: VEH收STATUS_SINGLE_STEP;
			//R0: 原生KiDebugTrapOrFault)。旧"一律吞"形态=guest
			//int1永不达=经典hypervisor指纹(ICEBP探针)。trap语义
			//RIP已过指令, 不推; DR6不动(int1本就不置位);
			//DecodeAssists缺席(特性=0)=字节数0, 回落吞路径
			//(保守: 不确定的残余不投递——0x1E防护优先)
			{
				UCHAR nBytes = vmcb->Control.NumOfBytesFetched;
				PUCHAR ib = vmcb->Control.GuestInstructionBytes;
				if ((nBytes == 2 && ib[0] == 0xCD && ib[1] == 0x01) ||
					(nBytes == 1 && ib[0] == 0xF1))
				{
					static volatile LONG s_i1Cnt[64] = { 0 };
					GNPT_CRUMB(s_i1Cnt, 0xFF, cpu,
						FlRingPush('a', cpu, (ULONG)SVM_EXIT_EXCP_DB,
							vmcb->State.Rip, (ULONG64)nBytes, 0));
					vmcb->Control.EventInj =
						EVENTINJ_MAKE(1, EVENTINJ_TYPE_EXCP, 0, 0);
					return 0;    //trap语义: 不推RIP
				}
			}
			//真残余(无int1特征): 一律吞掉不注入。注入回guest无调试
			//接手=0x1E; guest可见#DB=0x3B——
			//#DB拦截常驻: 此处=最后防线, 吞+清TF自愈。
			//残留窗口位一并解除(LeakCheck已收口, 此为双保险)
			//'D'环在此形态=真异常信号(旧形态的常规IDLE流量已由
			//'a'环的忠实投递承接)
			static volatile LONG s_dbIdleCnt[64] = { 0 };
			GNPT_CRUMB(s_dbIdleCnt, 0xFF, cpu,
				FlRingPush('D', cpu, SVM_EXIT_EXCP_DB,
					vmcb->State.Rip, vmcb->State.Dr6, 0));
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
		case SVM_EXIT_NMI:    //0x61: 物理NMI拦截(NMI virt配套, §15.21.10)
		{
			//EVENTINJ注入NMI(type=NMI/vector=2): VMRUN即投递并硬件
			//置V_NMI_MASK(§15.21.10原文)——NMI掩蔽语义(handler内嵌套
			//NMI阻断/IRET解除)由硬件管理。事件型exit不推RIP(异步事件
			//无faulting指令, 推进=跳过一条guest指令=状态破坏)。
			//NMI交付延迟+1世界开关(罕见事件: WHEA/硬件看门狗类)
			vmcb->Control.EventInj =
				EVENTINJ_MAKE(2, EVENTINJ_TYPE_NMI, 0, 0);
			return 0;
		}
#if GNPT_SMI_INTERCEPT
		case SVM_EXIT_SMI:    //0x62: SMI拦截处置(APM Table 15-14+§15.35.11)
		{
			//手册协议: 外部SMI在exit后保持pending, STGI使其立即
			//从root进SMM——固件save/restore的是root(裸机形态)上下
			//文, 绕开guest态SMM/RSM窗口; 内部SMI无pending, STGI
			//同型无害。EXITINFO1: bit0=SMISRC(0内部/1外部)
			//bit1=MCREDIR(机器检查重定向SMI=杀手画像) bit33=VALID
			//(伴随IO指令, STGI未定义——诊断轮接受并留痕)。STGI→
			//SMM→RSM窗内SMI优先级高于INTR, 不存在中断入root窗
			FlRingPush('K', cpu, (ULONG)vmcb->Control.ExitInfo1,
				vmcb->Control.ExitInfo2, vmcb->State.Rip, 0);
			__svm_stgi();    //GIF=1: pending SMI立即从root进SMM
			__svm_clgi();    //恢复GIF=0处置纪律
			return 0;        //事件exit不推RIP, 原地重入guest
		}
#endif
		case SVM_EXIT_SHUTDOWN:    //0x7F: guest triple fault(硬件复位级)
		case SVM_EXIT_INIT:        //0x63: 外部INIT(复位类IPI; 含带引擎重启)
		case SVM_EXIT_EXCP_MC:     //0x52: 机器检查(#MC)
			//静默硬复位转化器——命中即留痕+标记蓝屏
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
		default:
		//异常exit防御族: 生产拦截位下全部可达码已有case——到达=
		//拦截向量异常在位/EXITCODE高位异变/未定义码。旧形态推RIP
		//对事件类=跳过一条guest指令、对指令类=吞掉指令裸机语义
		//(写内存/填寄存器消失), 双破坏方向; 防御=一律不推RIP重入
		//(事件类本无faulting指令; 指令类=原指令重执行)。
		//0x00-0xBF已定义码区: exit码=拦截向量位号(App C)——反算
		//剥除该拦截位=直通自愈: 重入后硬件按裸机语义执行(INTR类
		//的pending中断重投递=不丢中断; VMCB控制区exit不回写
		//(§15.6)+clean bits恒0=剥位下次vmrun即生效; 正常形态这些
		//位不在位, 剥除幂等无害)。高位异变(负值族已被前置拦截,
		//此处=bit63:32非零正值, 含F000_0000h host保留区)与0xC0-0x407
		//无case码=语义不可知, 纯留痕重入。'x'环采样(每核首条+每
		//4096条; Release零开销); 剥位登记g_svmDefHeal(自证探针读)
		{
			static volatile LONG s_defCnt[64] = { 0 };
			GNPT_CRUMB(s_defCnt, 0xFFF, cpu,
				FlRingPush('x', cpu, (ULONG)exitCode, vmcb->State.Rip,
					vmcb->Control.ExitInfo1, 0));
			if (exitCode <= 0xBF)
			{
				ULONG code = (ULONG)exitCode;
				g_svmDefHeal[cpu & 63] = (LONG64)code + 1;
				if (code < 0x10)
				{
					vmcb->Control.InterceptCrRead &= (USHORT)~(1UL << code);
				}
				else if (code < 0x20)
				{
					vmcb->Control.InterceptCrWrite &= (USHORT)~(1UL << (code - 0x10));
				}
				else if (code < 0x30)
				{
					vmcb->Control.InterceptDrRead &= (USHORT)~(1UL << (code - 0x20));
				}
				else if (code < 0x40)
				{
					vmcb->Control.InterceptDrWrite &= (USHORT)~(1UL << (code - 0x30));
				}
				else if (code < 0x60)
				{
					vmcb->Control.InterceptException &= ~(1UL << (code - 0x40));
				}
				else if (code < 0x80)
				{
					vmcb->Control.InterceptMisc1 &= ~(1UL << (code - 0x60));
				}
				else if (code < 0xA0)
				{
					vmcb->Control.InterceptMisc2 &= ~(1UL << (code - 0x80));
				}
				else
				{
					vmcb->Control.InterceptMisc3 &= ~(1UL << (code - 0xA0));
				}
			}
		}
		return 0;    //不推RIP: 异常码语义不可知/已定义码剥位后重执行
	}
	//内层白名单收窄后不可达; 兜底=不推RIP重入(与default防御同向)
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
	//exit窗口看门狗探针(仅Debug构建): 处置耗时超50ms(2000MHz档,
	//rdtsc差>1e8)='L'环留痕(exit窗口GIF=0, IPI/时钟中断悬挂窗口
	//的量化证据)。入口统一判定=覆盖全部exit类型(含CPUID短路路径)。
	//仅观测不干预——护栏数据先于任何处置变更
#if DBG
	{
		ULONG64 wdNow = __rdtsc();
		if (wdNow - Vcpu->WdTsc > 100000000ULL)
		{
			ULONG wdc = (ULONG)(UCHAR)Vcpu->CpuIndex & 63;
			static volatile LONG s_wdCnt[64] = { 0 };
			GNPT_CRUMB(s_wdCnt, 0xFF, wdc,
				FlRingPush('L', wdc, 0,
					wdNow - Vcpu->WdTsc, (ULONG64)gnCrumb, 0));
		}
	}
#endif
	//NX-FENCE统一信标(任意exit皆信标, 先于CPUID短路): fence页邻
	//函数驻留旗在且无在途detour→回P重武装fence(miss窗口=exit间隔,
	//CPUID/MSR等常规流量秒级必达)。在途detour护旗——其间exit
	//(如detour函数体内CPUID)不得翻视图(函数体自HOOKS执行)。
	//快路径2读+2比较(无fence流量近零开销; 旗恒0时纯直通)
	GnptHookNxBeacon((PVMCB)Vcpu->VmcbVa, (ULONG)(UCHAR)Vcpu->CpuIndex);
	//CPUID exit短路于TSC壳——不进T0/T1/扣除/水位/钳制(哨兵照常
	//刷新, dispatch/观测/计数照常走)。原因: TSC补偿壳的水位/钳制
	//与高频exit存在交互风险, 绕过壳消除交互; exit成本(~1500周期)
	//guest可见=CPUID自然延迟范围(100-3000)内; CPUID核滞后累计
	//无界但下一非CPUID exit钳制前跳=单调安全方向, 高频期滞后率
	//有界瞬态。
	{
		PVMCB vmcbFast = (PVMCB)Vcpu->VmcbVa;
		if (vmcbFast->Control.ExitCode == SVM_EXIT_CPUID)
		{
#if DBG
			g_svmLastExitTsc[(ULONG)(UCHAR)Vcpu->CpuIndex & 63] = __rdtsc();
#endif
			return SvmExitDispatch(Vcpu, Regs);
		}
	}
	Vcpu->ExitTsc = __rdtsc();              //T0: root驻留起点
#if DBG
	g_svmLastExitTsc[(ULONG)(UCHAR)Vcpu->CpuIndex & 63] =
		Vcpu->ExitTsc;                      //停泊哨兵刷新(核号取VCPU)
#endif
	ULONG stop = SvmExitDispatch(Vcpu, Regs);
#if !GNPT_L3_MINIMAL && (!GNPT_L3_G2 || GNPT_L3_G4)
	//L系列探针形态门: L3/L3G2=壳不编译(TscOffset恒0); L3G2G4=壳加回
	//(A轮IDLEDEMOTE的35.6/s EFER写exit全部过壳=壳×MSR密度交互探针,
	//见common.h L系列注释); 全配=壳常在
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
#endif
	return stop;
}

