#include<ntifs.h>
#include"common.h"
#include"svm.h"
#include"hook.h"
#include"msr.h"

//本文件=框架使用示例(面向二次开发者):
//  DriverEntry  -> SvmStartAllCpus接管全核 -> 安装自己的hook
//  DriverUnload -> 移除hook -> SvmShutdownAllCpus关停并释放资源
//框架细节(资源分配/串行启动/互斥仲裁/内置隐藏/日志)全在svm.c,
//使用者只需关心hook回调本身。API契约见hook.h头注释
//
//构建形态:
//  Debug(DBG=1)  = 完整验证轮: 故事面自证探针+多hook验证序列+
//                  MSR hook演示(结果落盘可判读)
//  Release(DBG=0)= 纯引擎生命周期示例(接管->驻留->干净卸载;
//                  demo层整体不编译——验证探针属调试功能,
//                  仅Debug构建工作; 源码本身即用法参考)

#if DBG

//demo目标(框架使用示例的验证轮):
//  ①"SVM未激活"自洽故事面探针(DriverEntry内联): 三MSR读+EFER回写+
//    SVM指令族11条逐条执行, 全走guest硬件路径=与真实探测器同型
//  ②多hook验证轮: TRANSPARENT(DR机件)与普通模式并存+触发+选择性移除
//demo候选(阶段A): T目标=DR0-3线性断点(每核≤4), 原页恒等
//    不动=读/写透明结构性成立; 触发=入口#DB改道跳板槽(每调用1 exit)
//候选纪律: 按名导出+可重定位+同页防御跳过(NPF引擎按TargetPa首匹配;
//DR断点按线性地址不受页约束)。普通模式目标选Ke*普通内核函数
//(hook.h使用纪律5: PG不覆盖类)
#define DEMO_T_MAX 2
static PVOID g_demoT[DEMO_T_MAX];               //live TRANSPARENT目标(触发/移除键)
static const char* g_demoTName[DEMO_T_MAX];     //窄名(日志)
static volatile LONG64 g_demoTCall[DEMO_T_MAX]; //每hook独立计数槽(Context传给回调)
static BOOLEAN g_demoTFree[DEMO_T_MAX];         //触发返回值须ExFreePool收尾(逐候选契约)
static PVOID g_demoN = NULL;                    //阶段B普通模式目标
static volatile LONG64 g_demoNCall = 0;
static volatile LONG64 g_demoColdCall = 0;      //冷靶计数槽

//冷靶(驱动本地): 普通模式hook对照目标——与热Ke*目标同构走
//CodePage全链, 但页冷无自然流量=单变量隔离"热页"因素。
//纯寄存器ALU链≥14B且无RIP-rel无相对分支=重定位安全门必过
static ULONG64 DemoColdTargetFn(ULONG64 a1, ULONG64 a2, ULONG64 a3,
	ULONG64 a4)
{
	ULONG64 r = a1;
	r ^= a2;
	r += a3;
	r -= a4;
	r ^= 0x5A5A5A5A5A5A5A5AULL;
	return r;
}

//demo回调(detour语义, 返回值=新函数返回值)。
//回调运行在任意线程/任意IRQL(含DISPATCH级): 只做IRQL安全操作,
//禁止FlLog/DbgPrint/分页内存/阻塞(完整纪律见hook.h)。
//多hook判读基础: Context=本hook独立计数槽(安装时逐hook绑定),
//并存/移除/被偷的判据=各槽计数的独立增长与冻结
static ULONG64 DemoCountCallback(PVOID Context, ULONG64 Arg1,
	ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4, ULONG64* StackArgs)
{
	UNREFERENCED_PARAMETER(StackArgs);
	InterlockedIncrement64((volatile LONG64*)Context);  //IRQL安全计数
	//示例=透传原函数并返回其结果(零副作用监控)。
	//拦截=直接return 0(目标语义的失败值);
	//篡改=修改Arg后经GnptCallOriginal转发改写值
	return GnptCallOriginal(Arg1, Arg2, Arg3, Arg4);
}

//demo2: MSR hook读回调(LSTAR=系统调用入口地址, 0xC0000082)
static volatile LONG64 g_demoRdmsr = 0;
static ULONG64 DemoLstarOnRead(PVOID Context, ULONG32 Msr)
{
	UNREFERENCED_PARAMETER(Context);
	InterlockedIncrement64(&g_demoRdmsr);    //IRQL安全计数
	//示例=返回真值(零副作用监控)。
	//伪造=直接return任意值(guest的rdmsr只能见到它)
	return GnptMsrReadReal(Msr);
}

//写回调: 计数+忠实放行——写位拦截后由exit handler root代写
//(斩断"直通写×读exit×隐蔽"三体竞态, 详见msr.h使用纪律5)
static volatile LONG64 g_demoWrmsr = 0;
static BOOLEAN DemoLstarOnWrite(PVOID Context, ULONG32 Msr, ULONG64 Value)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Msr);
	UNREFERENCED_PARAMETER(Value);
	InterlockedIncrement64(&g_demoWrmsr);   //IRQL安全计数
	return TRUE;    //放行代写(root真写, 与直通语义等价)
}

//MSR自触发线程: 内核线程在guest内rdmsr LSTAR×3(运行期系统
//几乎无人读LSTAR, 自触发=机制验证不依赖自然触发)。返回值比对=
//真值直读(恒等自检)
static KEVENT g_demoMsrDone;
static BOOLEAN g_demoMsrArmed = FALSE;
static VOID DemoMsrTriggerThread(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	LARGE_INTEGER iv;
	iv.QuadPart = -3LL * 10000000LL;    //3s: 等安装落定/系统稳定
	KeDelayExecutionThread(KernelMode, FALSE, &iv);
	for (ULONG i = 0; i < 3; i++)
	{
		//guest上下文rdmsr→MSRPM位→exit 0x7C→demo回调(真值返回)
		ULONG64 v = __readmsr(0xC0000082);
		FlLog("[Demo] MSR自触发#%u: LSTAR=%llX", i + 1,
			(unsigned long long)v);
		iv.QuadPart = -10000000LL;    //1s
		KeDelayExecutionThread(KernelMode, FALSE, &iv);
	}
	KeSetEvent(&g_demoMsrDone, IO_NO_INCREMENT, FALSE);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

//自触发一个T hook一次并留痕(计数槽读数=该hook生死判据)。
//四寄存器参全部传合法可写栈缓冲: 指针参数安全, 整型参数收垃圾值
//无害——一条调用形态覆盖全部≤4参候选(逐候选写面分析见文件头)。
//FreeRet候选(MmGetPhysicalMemoryRanges)的返回池数组当场ExFreePool
//收尾(该函数的调用方契约, hook状态无关——移除后触发同样要释放)
static VOID DemoFireT(ULONG idx)
{
	UNICODE_STRING name;
	UCHAR bufA[64];
	UCHAR bufB[32];
	ULONG ret4 = 0;
	RtlInitUnicodeString(&name, L"GNPTProbe");
	typedef PVOID(*GNPT_DEMO_FN)(PVOID, PVOID, PVOID, PVOID);
	PVOID retVal = ((GNPT_DEMO_FN)g_demoT[idx])(&name, bufA, bufB, &ret4);
	if (g_demoTFree[idx] && retVal != NULL)
	{
		ExFreePool(retVal);    //池数组契约: 调用方释放
	}
	FlLog("[MultiHook] T%u(%s)触发: 返回=%p 累计=%lld",
		idx + 1, g_demoTName[idx], retVal, g_demoTCall[idx]);
}

//自触发阶段B普通模式hook一次: NtClose(NULL哑句柄=零副作用,
//STATUS_INVALID_HANDLE返回值被弃)。目标选择: KeInitializeDpc已被
//实证为PatchGuard监视集成员(0x109, P3逐位匹配——普通模式读透明
//漏洞, NPT无X-only编码)→换NtClose(是否在PG集内未知——本demo即
//实测oracle)
static VOID DemoFireN(VOID)
{
	typedef NTSTATUS(*GNPT_DEMO_N_FN)(HANDLE);
	NTSTATUS r = ((GNPT_DEMO_N_FN)g_demoN)((HANDLE)0);
	FlLog("[MultiHook] N(NtClose)触发: st=0x%X 累计=%lld",
		(ULONG)r, g_demoNCall);
}

//注: 未按名导出的Nt系目标无SSDT兜底——x64内核不导出
//KeServiceDescriptorTable(链接不可得), 运行时定位器(LSTAR→
//KiSystemCall64模式扫描)依赖未经目标机验证的内部形态, 不做;
//demo候选均选可直解析的导出名
//MSR面独立安装函数(与hook面解耦: 不调用hook安装则MSR仍可独立装)
static VOID DemoMsrInstall(VOID)
{
	//MSR hook: 读写双拦+自触发线程验证。
	//写位必须拦截(OnWrite=忠实放行代写): "写直通×读exit×NPT改译
	//隐蔽"三体竞态=时钟看门狗蓝屏根因(msr.h使用纪律5); "系统运行期
	//无人写LSTAR"假设不成立(PatchGuard周期性重写)。OnWrite放行=
	//语义与直通等价(计数后root真写)
	{
		GNPT_MSR_HOOK msrHook = { 0 };
		msrHook.Msr = 0xC0000082;    //IA32_LSTAR
		msrHook.OnRead = DemoLstarOnRead;
		msrHook.OnWrite = DemoLstarOnWrite;   //写也拦截(忠实代写, 斩断竞态)
		NTSTATUS mst = GnptMsrHookInstall(&msrHook);
		FlLog("[Demo] MSR hook LSTAR(0xC0000082): %s(触发计数=卸载总结)",
			NT_SUCCESS(mst) ? "OK" : "FAIL(见[MSR]行)");
		if (NT_SUCCESS(mst))
		{
			KeInitializeEvent(&g_demoMsrDone,
				NotificationEvent, FALSE);
			g_demoMsrArmed = TRUE;
			HANDLE th = NULL;
			NTSTATUS tst = PsCreateSystemThread(&th, 0, NULL,
				NULL, NULL, DemoMsrTriggerThread, NULL);
			if (NT_SUCCESS(tst))
			{
				ZwClose(th);    //句柄即弃(线程对象自持有引用)
			}
			else
			{
				FlLog("[Demo] MSR自触发线程创建失败=0x%X", (ULONG)tst);
			}
		}
	}

}

//======== 故事面探针: 裸机探测器视角自证 ========
//DriverEntry线程=guest态(全核已in-guest), 以下读写/指令全走guest
//硬件路径=被测面与真实探测器完全同型:
//  ①rdmsr三MSR: EFER应SVME=0(伪造)/VM_CR应0x18/HSAVE应0(影子)
//  ②EFER RMW回写: 写回①读到的伪造值→再读应等值+引擎存活——写路径
//    "强制SVME=1只写VMCB"的防自锁闭环实测(裸机Windows无人写真EFER,
//    本探针=唯一合法触发者)
//  ③SVM指令族8条×两操作数形态, 全部应#UD(kernel SEH捕获, 与裸机
//    #UD同路)。两形态依据APM §15.9 Table 15-7(SVM族"Checks exceptions
//    (#GP) before the intercept"):
//    - 非规范PA形态(VMRUN/VMSAVE/VMLOAD传VA当PA=超MAXPHYADDR):
//      硬件raise #GP先于拦截位→0x4D处置(case: RIP字节0F 01 D8-DF
//      族判定→改注入#UD)——探针=处置路径的执行级自证
//    - 规范PA形态(真物理地址, 页对齐全零哑页): PA检查过→拦截位
//      触发(0x80/0x82/0x83)→'v' case注入#UD。探针安全性: VMRUN=
//      must-1位0(引擎在跑=本核位0必活, 探针核同理); VMSAVE=两态
//      安全(最坏=写自家哑页); VMLOAD=最坏态载零毁guest态→**门控**
//      (VMSAVE规范PA确认#UD后才探, 同一Misc2表达式先证活)
//    - VMMCALL(裸, 无签名): 签名门'u'+#UD(路径异于指令族; x64无
//      MSVC intrinsic 0F 01 D9, svm-asm.asm的CmSvmVmmCallRaw补全)
//异常码判读: #UD=STATUS_ILLEGAL_INSTRUCTION=0xC000001D
static UCHAR g_storyDummy[16];    //哑操作数(非规范PA形态: 仅取地址)
static DECLSPEC_ALIGN(4096) UCHAR g_storyVmcb[4096];  //规范PA哑页(静态全零)
static ULONG64 g_storyValidPa = 0;                     //哑页真PA(探针入口填)
static VOID StoryProbeVmrunI(VOID)   { __svm_vmrun((void*)g_storyDummy); }
static VOID StoryProbeVmsaveI(VOID)  { __svm_vmsave((void*)g_storyDummy); }
static VOID StoryProbeVmloadI(VOID)  { __svm_vmload((void*)g_storyDummy); }
static VOID StoryProbeVmrunV(VOID)   { __svm_vmrun((void*)g_storyValidPa); }
static VOID StoryProbeVmsaveV(VOID)  { __svm_vmsave((void*)g_storyValidPa); }
static VOID StoryProbeVmloadV(VOID)  { __svm_vmload((void*)g_storyValidPa); }
static VOID StoryProbeVmmcall(VOID)  { CmSvmVmmCallRaw(); }
static VOID StoryProbeStgi(VOID)     { __svm_stgi(); }
static VOID StoryProbeClgi(VOID)     { __svm_clgi(); }
static VOID StoryProbeSkinit(VOID)   { __svm_skinit(0); }
static VOID StoryProbeInvlpga(VOID)  { __svm_invlpga((void*)g_storyDummy, 0); }

//返回TRUE=确认#UD(0xC000001D); FALSE=其他异常/未异常(故事破, 已留痕)
static BOOLEAN DemoStoryTryInstr(const char* name, VOID(*fn)(VOID))
{
	ULONG code = 0;
	__try
	{
		fn();
		FlLog("[S1] %s: 未异常(**故事破**——拦截位/注入链失效, 查'v'/'G'环)", name);
		return FALSE;
	}
	__except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
	{
		BOOLEAN ud = (code == 0xC000001D);
		FlLog("[S1] %s: 异常码%X%s", name, code,
			ud ? "=#UD(裸机等价)" : "(非#UD——#GP手术/拦截链查'v'/'G'环)");
		return ud;
	}
}

//返回TRUE=确认无异常(直通断言); FALSE=异常(直通配置失效, 已留痕)
static BOOLEAN DemoStoryTryPass(const char* name, VOID(*fn)(VOID))
{
	ULONG code = 0;
	__try
	{
		fn();
		FlLog("[S1] %s: 直通无异常(裸机等价: 特性在场, 硬件静默执行)", name);
		return TRUE;
	}
	__except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
	{
		FlLog("[S1] %s: 异常码%X(**直通失效**——在场配置不应异常, 查拦截位)", name, code);
		return FALSE;
	}
}

static VOID DemoStoryProbe(VOID)
{
	//①三MSR读: 探测器视角(全走MSRPM→exit→伪造/影子)
	ULONG64 efer = __readmsr(MSR_EFER);
	ULONG64 vmcr = __readmsr(MSR_VM_CR);
	ULONG64 hsave = __readmsr(MSR_VM_HSAVE_PA);
	FlLog("[S1] 探测器视角: EFER=%llX(SVME=%u 应0) VM_CR=%llX(应18) "
		"HSAVE=%llX(应0)",
		(unsigned long long)efer, (ULONG)((efer >> 12) & 1),
		(unsigned long long)vmcr, (unsigned long long)hsave);
	//②EFER RMW回写探针(写回读到的伪造值→等值回读+存活)
	__writemsr(MSR_EFER, efer);
	ULONG64 efer2 = __readmsr(MSR_EFER);
	FlLog("[S1] EFER回写: 前%llX 后%llX(应等值; 引擎存活见后续探针)",
		(unsigned long long)efer, (unsigned long long)efer2);
	//③SVM指令族8条×两形态(非规范PA走0x4D处置/规范PA走拦截0x80/0x82/
	//0x83/VMMCALL走签名门/其余走0x7A/0x84-0x86; #UD注入→SEH捕获;
	//STGI例外=按SKINIT特性门控: 在场直通(断言=无异常)/缺席#UD)
	g_storyValidPa = MmGetPhysicalAddress(g_storyVmcb).QuadPart;
	DemoStoryTryInstr("VMRUN(非规范PA)", StoryProbeVmrunI);
	DemoStoryTryInstr("VMSAVE(非规范PA)", StoryProbeVmsaveI);
	DemoStoryTryInstr("VMLOAD(非规范PA)", StoryProbeVmloadI);
	DemoStoryTryInstr("VMRUN(规范PA)", StoryProbeVmrunV);
	if (DemoStoryTryInstr("VMSAVE(规范PA)", StoryProbeVmsaveV))
	{
		//门控通过(Misc2表达式已证活)→VMLOAD规范PA最坏态(载零毁)被排除
		DemoStoryTryInstr("VMLOAD(规范PA)", StoryProbeVmloadV);
	}
	else
	{
		FlLog("[S1] VMLOAD(规范PA): 跳过(VMSAVE未#UD=拦截位疑失效, 规避载零毁态)");
	}
	DemoStoryTryInstr("VMMCALL(无签名)", StoryProbeVmmcall);
	if (g_svmStgiPass)
	{
		DemoStoryTryPass("STGI", StoryProbeStgi);
	}
	else
	{
		DemoStoryTryInstr("STGI", StoryProbeStgi);
	}
	DemoStoryTryInstr("CLGI", StoryProbeClgi);
	DemoStoryTryInstr("SKINIT", StoryProbeSkinit);
	DemoStoryTryInstr("INVLPGA", StoryProbeInvlpga);
	FlLog("[S1] 故事面探针完成(判据①③; 停机S1计数+#GP手术总结另含本探针量)");
}

//0x6E0轴换算探针: 读原值→写未来值→读回(应≈写入)→立即恢复原值。
//窗口<1ms且probe取未来值=不触发定时器; 原值0=无系统deadline在飞
//(恢复写0=关闭, 等价)。仅在g_svmTscDlMode=1(拦截+换算在位)时执行;
//缺席模式如实跳过(直通形态无换算可验)
static VOID DemoTscDeadlineProbe(VOID)
{
	ULONG code = 0;
	if (!g_svmTscDlMode)
	{
		FlLog("[S3] 0x6E0轴换算: 非TSC-deadline模式, 探针跳过(直通形态)");
		return;
	}
	ULONG64 orig = 0;
	__try
	{
		orig = __readmsr(MSR_IA32_TSC_DEADLINE);
	}
	__except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
	{
		FlLog("[S3] 0x6E0: 读异常%X=LAPIC未用TSC-deadline模式, 轴换算探针跳过",
			code);
		return;
	}
	ULONG64 probe = orig;
	ULONG64 now = __rdtsc();
	if (probe < now)
	{
		probe = now;    //原值0/已过时: 垫到当前(避免写后立即触发)
	}
	probe += 0x100000000ULL;    //未来值(约1-2s): 写读窗口内不触发
	__try
	{
		__writemsr(MSR_IA32_TSC_DEADLINE, probe);
		ULONG64 back = __readmsr(MSR_IA32_TSC_DEADLINE);
		__writemsr(MSR_IA32_TSC_DEADLINE, orig);    //立即恢复(在飞deadline归位)
		FlLog("[S3] 0x6E0轴换算: 原值%llX 写%llX 读回%llX 残差%lld"
			"(读回≈写入=双向换算账平; 已恢复原值)",
			(unsigned long long)orig, (unsigned long long)probe,
			(unsigned long long)back, (LONGLONG)(back - probe));
	}
	__except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
	{
		FlLog("[S3] 0x6E0: 写读异常%X(模式异常, 已尝试恢复原值)", code);
	}
}

//PMU旁信道状态报告探针(Demo构建): 本框架恒LBR-only(0xB8 bit0),
//PMC virt永不使能(合置检查: 需AVIC/NMI virt配套)→PMC面=平台
//边界(root驻留指令计数可经PMC观测=已知残余信道)。探针按特性
//在场性如实报告并跳过——无隔离可自证, 不做测量(计数器未计数
//≠隔离生效, 测量读数无论何值都无判读意义)。
//未来若实现AVIC/VNMI配套并使能PMC virt, 恢复测量体:
//guest组使能PMC0(事件0x76, PERFEVNTSEL_0=0xC0010000 EN=bit22,
//PERF_CTR_0=0xC0010004)→清零→100次EFER读(每次=1 exit+root
//处置)→采样→恢复。隔离生效=读数≈循环自身(万级); 泄漏=含
//root路径(数十万级)
static VOID DemoPmuProbe(VOID)
{
	//本框架恒LBR-only: IBS/PMC virt特性在场也不使能(合置检查:
	//需AVIC/NMI virt配套, 置位=全核VMEXIT_INVALID)→PMC隔离
	//永不生效, 探针无可自证面, 如实报平台边界跳过
	if ((g_svmFeatBits & SVM_FEAT_PMCVIRT) == 0)
	{
		FlLog("[S4] PMU自证: PCMVIRT特性缺席(0xB8仅LBR), PMC面=平台边界"
			"(无硬件隔离), 探针跳过");
		return;
	}
	FlLog("[S4] PMU自证: PCMVIRT特性在场但本框架未使能(合置检查:"
		"需AVIC/NMI virt配套), PMC面=平台边界(root驻留指令计数可经"
		"PMC观测=已知残余信道), 探针跳过");
}

//======== 调试子系统忠实性自证探针(M15.4判据②验收) ========
//以检测方视角(设TF/设DR断点/回读DR/发int1)验证"调试面=裸机
//等价"——检测方的标准手法: 设TF观察#DB是否到达/设DR断点观察
//是否触发/DR写读一致性/int1陷阱投递。任一失败=裸机不可能的
//hypervisor指纹。
//  ①TF单步: 置TF→下一指令trap→#DB必须投递(SEH捕获
//    STATUS_SINGLE_STEP; 硬件陷阱时自动清TF=单步恰一条)
//  ②自断点: DR0=本地函数+DR7使能→调用→#DB必须投递(fault形态)
//  ③回读一致: DR0写后读=等值; DR7写1读回=0x401(bit10 RA1=
//    裸机回读形态)
//  ④INT1软件陷阱: int1指令→#DB必须投递(DR6零位设置=残余
//    路径甄别形态; 旧"一律吞"形态=int1永不达=经典hypervisor
//    指纹——ICEBP探针, R3侧VEH检测的标准手法, 内核侧以SEH
//    等价验证)。
//运行契约: 须在MultiHook开始前调用(②的靶函数此时未被hook=
//零干扰; 本探针对DR0/DR7的占用经影子机件, 结束时DR7清零归还)
static VOID DemoDebugFaithProbe(VOID)
{
	//①TF单步投递
	BOOLEAN tfGot = FALSE;
	ULONG64 tfExc = 0;
	__try
	{
		CmSetTF();    //置位后的ret指令即trap
	}
	__except (tfExc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
	{
		tfGot = TRUE;
	}
	FlLog("[DbgFaith] TF单步: 投递=%s(码%llX)——应OK且80000004"
		"(STATUS_SINGLE_STEP=单步陷阱忠实投递)",
		tfGot ? "OK" : "**FAIL**", (unsigned long long)tfExc);
	//②自断点投递+③回读一致(DemoColdTargetFn此时未被hook=零干扰)
	__writedr(0, (ULONG64)(ULONG_PTR)DemoColdTargetFn);
	__writedr(7, 1);    //L0使能(R/W=LEN=00=仅执行1B)
	ULONG64 rb0 = __readdr(0);
	ULONG64 rb7 = __readdr(7);
	BOOLEAN bpGot = FALSE;
	ULONG64 bpExc = 0;
	__try
	{
		(VOID)DemoColdTargetFn(1, 2, 3, 4);
	}
	__except (bpExc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
	{
		bpGot = TRUE;
	}
	__writedr(7, 0);    //撤防
	FlLog("[DbgFaith] 自断点: 投递=%s(码%llX 应80000004); "
		"回读DR0=%llX(应%llX) DR7=%llX(应401=含bit10 RA1)",
		bpGot ? "OK" : "**FAIL**", (unsigned long long)bpExc,
		(unsigned long long)rb0,
		(unsigned long long)(ULONG_PTR)DemoColdTargetFn,
		(unsigned long long)rb7);
	//④INT1软件陷阱投递(残余路径甄别: DR6无B无BS+指令字节=CD 01)
	BOOLEAN i1Got = FALSE;
	ULONG64 i1Exc = 0;
	__try
	{
		CmInt1();
	}
	__except (i1Exc = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
	{
		i1Got = TRUE;
	}
	FlLog("[DbgFaith] INT1陷阱: 投递=%s(码%llX)——应OK且80000004"
		"(int1软件陷阱经残余甄别忠实投递; 吞=int1指纹)",
		i1Got ? "OK" : "**FAIL**", (unsigned long long)i1Exc);
}

static KEVENT g_demoSeqDone;
static BOOLEAN g_demoSeqArmed = FALSE;

//多hook验证序列线程(PASSIVE; 每步面包屑落盘)
static VOID DemoMultiHookThread(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	KAFFINITY allCpus = KeQueryActiveProcessors();
	LARGE_INTEGER iv;
	iv.QuadPart = -5LL * 10000000LL;    //5s: 安装落定+sc-start窗口RPC突发消退
	KeDelayExecutionThread(KernelMode, FALSE, &iv);

	//======== 阶段A: TRANSPARENT目标(DR机件; 双T存活至普查) ========
	//wait族候选已剔除(运行期自然流量高频, DR机件无热约束但日志面
	//会被刷爆); MmGetPhysMemRanges prologue含相对call被[Reloc]拒
	//(留池=重定位安全门演示); MmGetSystemRoutineAddress=可重定位
	//真冷目标→必为T1
	static const struct
	{
		PCWSTR      Name;
		const char* Log;
		BOOLEAN     FreeRet;   //触发返回值须ExFreePool收尾(池数组契约)
	} cand[] = {
		{ L"MmGetSystemRoutineAddress",  "MmGetSystemRoutineAddress",  FALSE },
		{ L"MmGetPhysicalMemoryRanges",  "MmGetPhysicalMemoryRanges",  TRUE  },
	};
	ULONG tLive = 0;
	for (ULONG c = 0; c < RTL_NUMBER_OF(cand) && tLive < DEMO_T_MAX; c++)
	{
		UNICODE_STRING name;
		RtlInitUnicodeString(&name, cand[c].Name);
		PVOID target = MmGetSystemRoutineAddress(&name);
		if (target == NULL)
		{
			FlLog("[MultiHook] 候选%s解析失败, 下一候选", cand[c].Log);
			continue;
		}
		//同页候选跳过: NPF引擎按TargetPa首匹配, 同页第二hook永不可达
		//(已知引擎边界, 防御性留痕不修)
		ULONG sameIdx = 0xFFFFFFFF;
		for (ULONG k = 0; k < tLive; k++)
		{
			if ((ULONG_PTR)PAGE_ALIGN(g_demoT[k]) == (ULONG_PTR)PAGE_ALIGN(target))
			{
				sameIdx = k;
				break;
			}
		}
		if (sameIdx != 0xFFFFFFFF)
		{
			FlLog("[MultiHook] 候选%s与T%u同页, 跳过(引擎首匹配边界)",
				cand[c].Log, sameIdx + 1);
			continue;
		}
		GNPT_HOOK h = { 0 };
		h.Target = target;
		h.Callback = DemoCountCallback;
		h.Context = &g_demoTCall[tLive];    //独立计数槽
		h.Flags = HOOK_TRANSPARENT;         //DR机件(每核≤4)
		NTSTATUS st = GnptHookInstall(&h);
		FlLog("[MultiHook] 阶段A T%u候选%s(%p): %s",
			tLive + 1, cand[c].Log, target,
			NT_SUCCESS(st) ? "Install OK" : "FAIL(见[Hook]行, 下一候选)");
		if (NT_SUCCESS(st))
		{
			g_demoT[tLive] = target;
			g_demoTName[tLive] = cand[c].Log;
			g_demoTFree[tLive] = cand[c].FreeRet;
			tLive++;
		}
	}
	if (tLive == 0)
	{
		FlLog("[MultiHook] 阶段A: 候选全拒(hookless, 见[Hook]行判读)");
	}
	else
	{
		//双T并存格: 统一钉核1顺序触发(两槽各自独立增长=并存判据;
		//DR断点按线性地址各自独立=页粒度限制不存在)
		//Install/Remove内置SvmPinVirtualizedCpus会还原亲和——触发段前重钉
		KeSetSystemAffinityThread((KAFFINITY)1 << 1);
		if (tLive >= 2)
		{
			DemoFireT(0);
			DemoFireT(1);
			DemoFireT(0);
			DemoFireT(1);
			FlLog("[MultiHook] 阶段A: 双T并存触发完成(上四行两槽各自独立增长=并存判据)");
			//选择性移除: 摘T1后双触发——T1槽冻结(原页恒等直通)+T2槽续增(仍活)
			NTSTATUS rst = GnptHookRemove(g_demoT[0]);
			FlLog("[MultiHook] 选择性Remove T1(%s): %s",
				g_demoTName[0], NT_SUCCESS(rst) ? "OK" : "FAIL");
			KeSetSystemAffinityThread((KAFFINITY)1 << 1);  //Remove内置钉核还原后再钉
			DemoFireT(0);
			FlLog("[MultiHook] T1已移除: 上行累计应冻结(调用=原页恒等直通)");
			DemoFireT(1);
			FlLog("[MultiHook] T2对照: 上行累计应续增(选择性移除后仍活)");
		}
		else
		{
			DemoFireT(0);
			DemoFireT(0);
			FlLog("[MultiHook] 阶段A: 单T(tLive=1), 双T格本轮无样本");
		}
	}
	//======== 阶段B: 并存格+冷热靶(T驻留→N接管→冷热靶) ========
	//DR-TRANSPARENT契约: T(线性断点)与N(NPT视图)机制正交,
	//T驻留期间N Install成功=并存验证; N=NtClose此时布防,
	//④热靶改为触发验证
	ULONG aIdx = (tLive >= 2) ? 1 : 0;    //仍活的T(移除后=T2; 单live=T1)
	if (tLive >= 1)
	{
		UNICODE_STRING nName;
		RtlInitUnicodeString(&nName, L"NtClose");
		g_demoN = MmGetSystemRoutineAddress(&nName);
		if (g_demoN == NULL)
		{
			FlLog("[MultiHook] 阶段B: NtClose解析失败, 本轮跳过");
		}
		else if ((ULONG_PTR)PAGE_ALIGN(g_demoN) ==
			(ULONG_PTR)PAGE_ALIGN(g_demoT[aIdx]))
		{
			FlLog("[MultiHook] 阶段B: NtClose与活T同页, 本轮跳过");
		}
		else
		{
			GNPT_HOOK h = { 0 };
			h.Target = g_demoN;
			h.Callback = DemoCountCallback;
			h.Context = &g_demoNCall;
			h.Flags = 0;    //普通模式: Nt系syscall函数(hook.h纪律5)
			//①并存格: T驻留时N Install——两机制无交集(线性断点×
			//NPT视图), 应成功
			NTSTATUS st = GnptHookInstall(&h);
			FlLog("[MultiHook] 阶段B 并存格: T驻留时N Install→0x%X(%s)",
				(ULONG)st, NT_SUCCESS(st) ?
				"成功=正交并存(DR机件: 断点与视图无交集)" :
				"失败(应成功, 见[Hook]行)");
			//②撤除最后的活T(此前T1已在阶段A被选择性移除)
			NTSTATUS rst = GnptHookRemove(g_demoT[aIdx]);
			FlLog("[MultiHook] 阶段B 撤T: Remove %s→%s",
				g_demoTName[aIdx], NT_SUCCESS(rst) ? "OK" : "FAIL");
			//③冷靶先行: 驱动本地冷页走普通模式+工件隐蔽全链(与热
			//靶同构, 无热页自然流量)——绿则热靶再冻结=热页因素,
			//冻则'J'面包屑+心跳st=定位阶段
			KeSetSystemAffinityThread((KAFFINITY)1 << 3);
			{
				GNPT_HOOK hc = { 0 };
				hc.Target = DemoColdTargetFn;
				hc.Callback = DemoCountCallback;
				hc.Context = &g_demoColdCall;
				NTSTATUS cst = GnptHookInstall(&hc);
				FlLog("[MultiHook] 阶段B 冷靶接管(本地%u): %s(Flags=0)",
					(ULONG)((ULONG_PTR)DemoColdTargetFn & 0xFFF),
					NT_SUCCESS(cst) ? "Install OK" : "FAIL(见[Hook]行)");
				if (NT_SUCCESS(cst))
				{
					ULONG64 r = DemoColdTargetFn(0x1111111111111111ULL,
						0x2222222222222222ULL, 0x3333333333333333ULL,
						0x4444444444444444ULL);
					FlLog("[MultiHook] 阶段B 冷靶触发: 返回=%llX 累计=%lld"
						"(计数>0=普通模式全链路活)",
						(unsigned long long)r, g_demoColdCall);
				}
			}
			//④热靶触发: NtClose已在①布防(T驻留期间)——自然流量
			//累计+自触发双验证(detour全链路活)
			if (NT_SUCCESS(st))
			{
				DemoFireN();
				FlLog("[MultiHook] 阶段B 热靶触发: 累计=%lld(>0=detour全链路活)",
					g_demoNCall);
			}
			//⑤枚举契约: NULL探针取数+定容枚举(语义=MSR侧同款)
			{
				ULONG n = 0;
				GnptHookEnumerate(NULL, &n);
				GNPT_HOOK list[4];
				ULONG cnt = RTL_NUMBER_OF(list);
				NTSTATUS est = GnptHookEnumerate(list, &cnt);
				FlLog("[MultiHook] 阶段B Enumerate: live=%u(容量%u) st=0x%X "
					"回填%u 首条目Target=%p",
					n, (ULONG)GNPT_MAX_HOOKS, (ULONG)est, cnt,
					(cnt > 0) ? list[0].Target : NULL);
			}
		}
	}
	KeSetSystemAffinityThread(allCpus);
	FlLog("[MultiHook] 序列完成(tLive=%u): 残余hook交由卸载RemoveAll统一清理", tLive);
	KeSetEvent(&g_demoSeqDone, IO_NO_INCREMENT, FALSE);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

//启动多hook验证序列
static VOID DemoMultiHookStart(VOID)
{
	KeInitializeEvent(&g_demoSeqDone, NotificationEvent, FALSE);
	g_demoSeqArmed = TRUE;
	HANDLE th = NULL;
	NTSTATUS tst = PsCreateSystemThread(&th, 0, NULL, NULL,
		NULL, DemoMultiHookThread, NULL);
	if (NT_SUCCESS(tst))
	{
		ZwClose(th);    //句柄即弃(线程对象自持有引用)
	}
	else
	{
		g_demoSeqArmed = FALSE;
		FlLog("[MultiHook] 序列线程创建失败=0x%X", (ULONG)tst);
	}
}

//demo层收尾(DriverUnload调用, 仅Debug构建有实体)
static VOID DemoShutdown(VOID)
{
	//自触发线程收尾等待(有界: MSR 6s>3+3窗口; 多hook序列40s>
	//5s落定+装卸/触发/移除全程~25s——防序列在途回调撞卸载)
	if (g_demoMsrArmed)
	{
		LARGE_INTEGER to;
		to.QuadPart = -6LL * 10000000LL;
		KeWaitForSingleObject(&g_demoMsrDone, Executive,
			KernelMode, FALSE, &to);
	}
	if (g_demoSeqArmed)
	{
		LARGE_INTEGER to;
		to.QuadPart = -40LL * 10000000LL;
		KeWaitForSingleObject(&g_demoSeqDone, Executive,
			KernelMode, FALSE, &to);
	}
	//多hook总结: 各槽独立计数=并存证据; 阶段B双向冻结=互偷证据
	//(序列内已显式Remove的T1不再出现在RemoveAll清单)
	FlLog("[Unload] MultiHook总结: T1=%lld T2=%lld N=%lld, LSTAR读拦截=%lld次, 写拦截=%lld次",
		g_demoTCall[0], g_demoTCall[1], g_demoNCall, g_demoRdmsr, g_demoWrmsr);
	GnptMsrHookRemove(0xC0000082);
}

//demo层启动(DriverEntry调用, 仅Debug构建有实体)。
//故事面探针先行(全功能立即自证, 独立于demo hook轮序列)。
//仅虚拟化核安全: 拦截位是探针的防弹衣——裸核上STGI/SKINIT被
//硬件真实执行(APM三人组#UD条件带SVML/DEV豁免, SKINIT特性位
//在场时SVME=0不#UD), SKINIT=安全重初始化+跳转垃圾SLB=整机
//复位(C0轮实锤)。零接管轮跳过; 有接管核时钉核0防线程迁移
//落裸核
static VOID DemoStart(VOID)
{
	if (g_svmVcpuCount == 0)
	{
		FlLog("[S1] 零接管对照: 故事面探针跳过(裸核SKINIT被硬件真实执行=复位)");
	}
	else
	{
		//KeSetSystemAffinityThread返回void(WDK无旧值可存):
		//恢复亲和=重建全活跃核掩码
		ULONG cpuTotal = KeQueryActiveProcessorCount(NULL);
		KAFFINITY allAff = (cpuTotal >= 64) ? ~(KAFFINITY)0
			: (((KAFFINITY)1 << cpuTotal) - 1);
		KeSetSystemAffinityThread((KAFFINITY)1);
		DemoStoryProbe();
		DemoTscDeadlineProbe();
		DemoPmuProbe();
		DemoDebugFaithProbe();    //调试面忠实性(TF/自断点/回读/INT1)——须先于MultiHook(其阶段B将hook冷靶=②的零干扰前提)
		KeSetSystemAffinityThread(allAff);
	}
	DemoMultiHookStart();
	DemoMsrInstall();
}

#endif  //#if DBG——demo验证层结束(Release构建不编译)

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
#if DBG
	DemoShutdown();    //demo收尾: 线程等待+总结+MSR hook移除
#endif
	//关停: 移除残余hook(引擎仍在位=在途回调安全完成)→全核去虚拟化→释放资源
	GnptHookRemoveAll();
	if (SvmShutdownAllCpus())
	{
		GnptHookFreeMemory();    //全核已裸机: 纯内存释放(无人引用)
	}
	FlLog("[Unload] 完成");
	FlShutdown();    //最后调用: 停线程+T1最终落盘
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	pDriverObject->DriverUnload = DriverUnload;

	//观测体系最先初始化(T1/T2/看门狗线程)
	FlInit();

	//框架入口: 可用性检测+全核接管; 失败时资源已自清理
	NTSTATUS st = SvmStartAllCpus(pDriverObject);
	if (!NT_SUCCESS(st))
	{
		FlLog("[Entry] SvmStartAllCpus失败=0x%X, 资源已自清理", (ULONG)st);
		FlShutdown();
		return st;
	}

	//武装看门狗(驻留期观测: 行环30s零推进=黑匣子蓝屏留证)
	FlWdArm();
	//放行T2的Desktop镜像(加载窗口期已过)
	FlMarkEntryDone();

#if DBG
	//接管成功, 安装演示hook(验证轮: 故事面探针+多hook序列+MSR hook)。
	//目标解析=调用者责任(GNPT_HOOK.Target直接传函数指针, 无SSDT/
	//名称定位器——与EPT型框架契约一致)
	DemoStart();
#endif
	FlLog("[Entry] 完成(%s)", GNPT_BUILD_TAG);
	return STATUS_SUCCESS;
}
