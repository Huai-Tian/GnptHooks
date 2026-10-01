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

//demo目标(框架使用示例的两项扩展验证):
//  ①"SVM未激活"自洽故事面探针(DriverEntry内联): 三MSR读+EFER回写+
//    SVM指令族11条逐条执行, 全走guest硬件路径=与真实探测器同型
//  ②混装/多hook验证轮: TRANSPARENT与普通模式并存+逐核视图驻留普查
//本文件仍=面向二次开发者的使用示例(demo层扩展, 引擎零改动):
//  阶段A: 候选链装TRANSPARENT目标(候选三条件=冷+按名导出+可重定位;
//    MmGetSystemRoutineAddress=真冷目标必存活; MmGetPhysicalMemory
//    Ranges因prologue含相对call被[Reloc]拒, 留池作重定位安全门演示)
//  阶段B 16核驻留普查: 普通模式N(KeInitializeDpc, Flags=0)与活T并存,
//    逐核先T后N各触发一次并记Δ——(T增,N不增)=P/HIDE驻留,
//    (T不增,N增)=HOOKS驻留, 双向拓扑一次取齐(不依赖预设驻留:
//    钉单核的期望序会被自然流量先行占用); 核间1s隔=防普查自身
//    打满tstorm桶(单次T触发≈百级exit×16连发会破1024/700ms桶)
//候选纪律: 热探针筛选+自触发安全+非wait家族+同页防御跳过
//(NPF引擎按TargetPa首匹配)。普通模式目标选Ke*普通内核函数
//(hook.h使用纪律5: PG不覆盖类)
#define DEMO_T_MAX 2
static PVOID g_demoT[DEMO_T_MAX];               //live TRANSPARENT目标(触发/移除键)
static const char* g_demoTName[DEMO_T_MAX];     //窄名(日志)
static volatile LONG64 g_demoTCall[DEMO_T_MAX]; //每hook独立计数槽(Context传给回调)
static BOOLEAN g_demoTFree[DEMO_T_MAX];         //触发返回值须ExFreePool收尾(逐候选契约)
static PVOID g_demoN = NULL;                    //阶段B普通模式目标
static volatile LONG64 g_demoNCall = 0;
static volatile LONG64 g_demoColdCall = 0;     //冷靶计数槽

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

//自触发阶段B普通模式hook一次: KeInitializeDpc(栈上哑DPC对象=零
//副作用; void返回值的CallOriginal余RAX被弃)
static VOID DemoFireN(VOID)
{
	KDPC dummyDpc;
	typedef VOID(*GNPT_DEMO_N_FN)(PVOID, PVOID, PVOID);
	RtlZeroMemory(&dummyDpc, sizeof(dummyDpc));
	((GNPT_DEMO_N_FN)g_demoN)(&dummyDpc, NULL, NULL);
	FlLog("[MultiHook] N(KeInitializeDpc)触发: 累计=%lld", g_demoNCall);
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

//PMU旁信道自证探针: guest组使能PMC0(事件0x76 unhalted clocks)→
//清零→循环100次EFER读(每次=1个exit+root故事处置路径)→采样→
//恢复原配置(窗口<1ms)。PMC虚拟化(VMCB 0xB8 bit3)生效=世界切换
//交换guest/host寄存器组→root驻留指令进host组=guest读数≈循环
//自身(万级); 泄漏=计数含100次exit的root路径(数十万+)。判读:
//万级=隔离生效; 十万级以上=root泄漏。PCMVIRT特性缺席的平台
//0xB8 bit3不可置=PMC面无法硬件关闭(平台边界, guest启用计数
//可观测root指令量)→如实跳过。AMD PMC: PERFEVNTSEL_0=0xC0010000
//PERF_CTR_0=0xC0010004(EN=bit22)
static VOID DemoPmuProbe(VOID)
{
	ULONG code = 0;
	if ((g_svmFeatBits & SVM_FEAT_PMCVIRT) == 0)
	{
		FlLog("[S4] PMU自证: PCMVIRT特性缺席(0xB8仅LBR), PMC面=平台边界"
			"(无硬件隔离), 探针跳过");
		return;
	}
	__try
	{
		ULONG64 selOrig = __readmsr(0xC0010000);
		ULONG64 ctrOrig = __readmsr(0xC0010004);
		__writemsr(0xC0010000, 0x76ULL | (1ULL << 22));    //事件0x76+EN
		__writemsr(0xC0010004, 0);                          //计数器清零
		volatile ULONG64 sink = 0;
		ULONG64 efer = 0;
		for (int i = 0; i < 100; i++)      //100次exit+root处置, 泄漏面
		{
			efer = __readmsr(MSR_EFER);
			sink += efer;
		}
		ULONG64 cnt = __readmsr(0xC0010004);
		__writemsr(0xC0010000, selOrig);   //恢复(系统perf配置归位)
		__writemsr(0xC0010004, ctrOrig);
		FlLog("[S4] PMU自证: PMC0=%llu(100次EFER读+循环; 万级=guest组"
			"隔离生效, 十万级+=root泄漏), sink=%llu 已恢复原配置",
			(unsigned long long)cnt, (unsigned long long)sink);
	}
	__except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
	{
		FlLog("[S4] PMU自证: PMC访问异常%X(不可用形态), 跳过", code);
	}
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

	//======== 阶段A: TRANSPARENT目标(真冷单T存活至普查) ========
	//wait族候选已剔除(运行期自然流量会打满tstorm脱落); MmGetPhys
	//MemRanges prologue含相对call被[Reloc]拒(留池=重定位安全门演示);
	//MmGetSystemRoutineAddress=真冷(热探针零NPF)+可重定位→必为T1
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
#if GNPT_M92_VARIANT == 0 || GNPT_M92_VARIANT == 3 || GNPT_M92_VARIANT == 6 || GNPT_M92_VARIANT == 7
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
		h.Flags = HOOK_TRANSPARENT;        //含250ms安装期热探针
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
		//每核单步窗口在两个hook条目间交替=多hook窗口机制验证);
		//Install/Remove内置SvmPinVirtualizedCpus会还原亲和——触发段前重钉
		KeSetSystemAffinityThread((KAFFINITY)1 << 1);
		if (tLive >= 2)
		{
			DemoFireT(0);
			DemoFireT(1);
			DemoFireT(0);
			DemoFireT(1);
			FlLog("[MultiHook] 阶段A: 双T并存触发完成(上四行两槽各自独立增长=并存判据)");
			//选择性移除: 摘T1后双触发——T1槽冻结(恒等直通)+T2槽续增(仍活)
			NTSTATUS rst = GnptHookRemove(g_demoT[0]);
			FlLog("[MultiHook] 选择性Remove T1(%s): %s",
				g_demoTName[0], NT_SUCCESS(rst) ? "OK" : "FAIL");
			KeSetSystemAffinityThread((KAFFINITY)1 << 1);  //Remove内置钉核还原后再钉
			DemoFireT(0);
			FlLog("[MultiHook] T1已移除: 上行累计应冻结(调用=恒等直通)");
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
#endif
	//======== 阶段B: 混装拒绝纪律+模式切换链(T驻留→拒绝→T全撤→N接管) ========
	ULONG aIdx = (tLive >= 2) ? 1 : 0;    //仍活的T(移除后=T2; 单live=T1)
#if GNPT_M92_VARIANT == 0 || GNPT_M92_VARIANT == 3 || GNPT_M92_VARIANT == 6 || GNPT_M92_VARIANT == 7
	if (tLive >= 1)
	{
		UNICODE_STRING nName;
		RtlInitUnicodeString(&nName, L"KeInitializeDpc");
		g_demoN = MmGetSystemRoutineAddress(&nName);
		if (g_demoN == NULL)
		{
			FlLog("[MultiHook] 阶段B: KeInitializeDpc解析失败, 本轮跳过");
		}
		else if ((ULONG_PTR)PAGE_ALIGN(g_demoN) ==
			(ULONG_PTR)PAGE_ALIGN(g_demoT[aIdx]))
		{
			FlLog("[MultiHook] 阶段B: KeInitializeDpc与活T同页, 本轮跳过");
		}
		else
		{
			GNPT_HOOK h = { 0 };
			h.Target = g_demoN;
			h.Callback = DemoCountCallback;
			h.Context = &g_demoNCall;
			h.Flags = 0;    //普通模式: Ke*普通内核函数(hook.h纪律5), 无热探针
			//①混装拒绝格: T驻留期间N Install应被拒(两模式驻留视图
			//互斥, 并存=互偷静默失效——fail-loud是唯一安全纪律)
			NTSTATUS st = GnptHookInstall(&h);
			FlLog("[MultiHook] 阶段B 混装拒绝格: T驻留时N Install→0x%X(%s)",
				(ULONG)st, (st == STATUS_NOT_SUPPORTED) ?
				"拒绝OK=纪律生效" : "异常(应拒绝, 见[Hook]行)");
			//②撤除最后的活T(此前T1已在阶段A被选择性移除)
			NTSTATUS rst = GnptHookRemove(g_demoT[aIdx]);
			FlLog("[MultiHook] 阶段B 撤T: Remove %s→%s",
				g_demoTName[aIdx], NT_SUCCESS(rst) ? "OK" : "FAIL");
			//改钉未舞步核3(P驻留): 阶段A的T舞步把原驻核1/2留在
			//HIDE/EXEC驻留态, N接管链若在其上执行则叠加"安装核
			//非P驻留"变量; 钉3后布防→隐蔽→同步→触发全链单变量
			KeSetSystemAffinityThread((KAFFINITY)1 << 3);
			//③冷靶先行: 驱动本地冷页走普通模式+工件隐蔽全链(与热
			//靶同构, 无热页自然流量)——绿则热靶再冻结=热页因素,
			//冻则'J'面包屑+心跳st=定位阶段
			GNPT_HOOK hc = { 0 };
			hc.Target = DemoColdTargetFn;
			hc.Callback = DemoCountCallback;
			hc.Context = &g_demoColdCall;
			st = GnptHookInstall(&hc);
			FlLog("[MultiHook] 阶段B 冷靶接管(本地%u): %s(Flags=0)",
				(ULONG)((ULONG_PTR)DemoColdTargetFn & 0xFFF),
				NT_SUCCESS(st) ? "Install OK" : "FAIL(见[Hook]行)");
			if (NT_SUCCESS(st))
			{
				ULONG64 r = DemoColdTargetFn(0x1111111111111111ULL,
					0x2222222222222222ULL, 0x3333333333333333ULL,
					0x4444444444444444ULL);
				FlLog("[MultiHook] 阶段B 冷靶触发: 返回=%llX 累计=%lld"
					"(计数>0=普通模式全链路活)",
					(unsigned long long)r, g_demoColdCall);
			}
			//④热靶接管: KeInitializeDpc(热Ke*页, 自然流量千次/秒级)
			st = GnptHookInstall(&h);
			FlLog("[MultiHook] 阶段B 热靶接管: KeInitializeDpc(%p): %s(Flags=0)",
				g_demoN, NT_SUCCESS(st) ? "Install OK" : "FAIL(见[Hook]行)");
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
#endif
	KeSetSystemAffinityThread(allCpus);
	FlLog("[MultiHook] 序列完成(tLive=%u): 残余hook交由卸载RemoveAll统一清理", tLive);
	KeSetEvent(&g_demoSeqDone, IO_NO_INCREMENT, FALSE);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

//启动多hook验证序列(旧单候选DemoHookInstall的升级替代; 变体门在
//DemoMultiHookThread的阶段内, 门列表与旧函数一致)
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

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
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

	//变体形态标识(横幅外第二证据, 防测错形态)
#if GNPT_M92_VARIANT == 1
	FlLog("[Entry] M9.2鉴别构建: 全停基座(隐蔽/hook/MSR全停; 引擎+哨兵+TSC钳制在位)");
#elif GNPT_M92_VARIANT == 2
	FlLog("[Entry] M9.2鉴别构建: 裸隐蔽(hook/MSR停)");
#elif GNPT_M92_VARIANT == 3
	FlLog("[Entry] M9.2鉴别构建: 裸hook(隐蔽/MSR停)");
#elif GNPT_M92_VARIANT == 4
	FlLog("[Entry] M9.2鉴别构建: 裸MSR(隐蔽/hook停)");
#elif GNPT_M92_VARIANT == 5
	FlLog("[Entry] M9.2鉴别构建: 隐蔽+MSR(hook停)——死亡时刻活跃面复刻");
#elif GNPT_M92_VARIANT == 6
	FlLog("[Entry] M9.2鉴别构建: 隐蔽+hook(MSR停)");
#elif GNPT_M92_VARIANT == 7
	FlLog("[Entry] M9.2鉴别构建: hook+MSR(隐蔽停)");
#elif GNPT_M92_VARIANT == 9
	FlLog("[Entry] M10.2决策轮: 全功能(v0.9y基线)+CPUID拦截回归(单变量)");
#elif GNPT_M92_VARIANT == 10
	FlLog("[Entry] M10.5细分轮: 全功能+CPUID拦截+CPUID exit绕过TSC壳(毒位裁决)");
#endif

	//接管成功, 安装演示hook。
	//目标解析=调用者责任(GNPT_HOOK.Target直接传函数指针, 无SSDT/
	//名称定位器——与EPT型框架契约一致)
	//变体门: hook面=全功能(0)/裸hook(3)/隐蔽+hook(6)/hook+MSR(7);
	//序列线程沿用内层门语义, 线程恒启动
	//故事面探针先行(全功能立即自证, 独立于demo hook轮序列)。
	//仅虚拟化核安全: 拦截位是探针的防弹衣——裸核上STGI/SKINIT被
	//硬件真实执行(APM三人组#UD条件带SVML/DEV豁免, SKINIT特性位
	//在场时SVME=0不#UD), SKINIT=安全重初始化+跳转垃圾SLB=整机
	//复位(C0轮实锤)。零接管轮跳过; 有接管核时钉核0防线程迁移
	//落裸核
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
		KeSetSystemAffinityThread(allAff);
	}
	DemoMultiHookStart();
	//变体门: MSR面独立调用(全功能/裸MSR/隐蔽+MSR/hook+MSR/CPUID决策轮)
#if GNPT_M92_VARIANT == 0 || GNPT_M92_VARIANT == 4 || GNPT_M92_VARIANT == 5 || GNPT_M92_VARIANT == 7 || GNPT_M92_VARIANT == 9 || GNPT_M92_VARIANT == 10
	DemoMsrInstall();
#endif
	FlLog("[Entry] 完成(%s)", GNPT_BUILD_TAG);
	return STATUS_SUCCESS;
}
