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

//demo目标: 混装/多hook验证轮(M11.2b=方向一补格: 真冷单T存活至
//16核普查, HOOKS驻留核上TΔ=0=互偷方向一; M11.2已闭双T并存格)。
//本文件仍=面向二次开发者的使用示例; 仍为demo层扩展(引擎零改动):
//  阶段A: 候选链装TRANSPARENT目标(M11.2判读: NtRWRP三度脱落定罪
//    撤池; MmGetSystemRoutineAddress实证真冷[探针0NPF]+可重定位
//    =T必存活至普查; MmGetPhysicalMemoryRanges prologue含相对
//    call=[Reloc]拒的演示件, 候选三条件=冷+导出+可重定位)→触发证liveness
//  阶段B 16核互偷普查: 普通模式N(KeInitializeDpc, Flags=0)与活T
//    并存, 逐核先T后N各触发一次并记Δ——(T增,N不增)=P/HIDE驻留,
//    (T不增,N增)=HOOKS驻留, 双向互偷拓扑一次取齐(M11.1教训:
//    钉单核的期望序会被自然流量先行占用, 普查不依赖预设驻留);
//    核间1s隔=防普查自身打满tstorm桶(单次T触发≈百级exit×16连发
//    会破1024/700ms桶)
//候选纪律(沿用): 热探针实测筛选+自触发安全+非wait家族+同页防御
//跳过(NPF引擎按TargetPa首匹配)。候选写面分析: MmGetSystem
//RoutineAddress(1参=合法UNICODE_STRING→无命中返回NULL零写),
//MmGetPhysicalMemoryRanges(0参, 返回池数组须调用方ExFreePool
//收尾——本轮实际被[Reloc]拒, 留池作安全门演示)。普通模式目标
//选Ke*普通内核函数(hook.h使用纪律5: PG不覆盖类)
#define DEMO_T_MAX 2
static PVOID g_demoT[DEMO_T_MAX];               //live TRANSPARENT目标(触发/移除键)
static const char* g_demoTName[DEMO_T_MAX];     //窄名(日志)
static volatile LONG64 g_demoTCall[DEMO_T_MAX]; //每hook独立计数槽(Context传给回调)
static BOOLEAN g_demoTFree[DEMO_T_MAX];         //触发返回值须ExFreePool收尾(逐候选契约)
static PVOID g_demoN = NULL;                    //阶段B普通模式目标
static volatile LONG64 g_demoNCall = 0;

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

//v0.9y写回调(M9.6定罪修复): 计数+忠实放行——写位拦截后由
//exit handler root代写(斩断"直通写×读exit×隐蔽"三体竞态;
//x8验证: 写直通死107s→写拦截绿15min+)
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
//真值直读(virtual含root内读, 恒等自检)
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
//M9.2拆分(v2): MSR面独立安装函数(原在DemoHookInstall内,
//x5构建缺陷=不调用DemoHookInstall则MSR永不装——拆出修复)
static VOID DemoMsrInstall(VOID)
{
	//MSR hook: 读写双拦+自触发线程验证。
	//v0.9y(M9.6定罪): 写位必须拦截(OnWrite=忠实放行代写)——
	//"写直通×读exit×NPT改译隐蔽"三体竞态=0x101系列死亡根因
	//(x5_v2写直通钉C0死107s vs x8写拦截绿15min+, 单变量翻转);
	//"系统运行期无人写LSTAR"假设被证伪(PG KiErrata420Present
	//周期性写)。OnWrite放行=语义与直通等价(计数后root真写)
	{
		GNPT_MSR_HOOK msrHook = { 0 };
		msrHook.Msr = 0xC0000082;    //IA32_LSTAR
		msrHook.OnRead = DemoLstarOnRead;
		msrHook.OnWrite = DemoLstarOnWrite;   //v0.9y: 写也拦截(忠实代写, 斩断竞态)
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

static KEVENT g_demoSeqDone;
static BOOLEAN g_demoSeqArmed = FALSE;

//多hook验证序列线程(PASSIVE; 每步面包屑落盘, 判据见NOTES M11.2)
static VOID DemoMultiHookThread(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	KAFFINITY allCpus = KeQueryActiveProcessors();
	LARGE_INTEGER iv;
	iv.QuadPart = -5LL * 10000000LL;    //5s: 安装落定+sc-start窗口RPC突发消退
	KeDelayExecutionThread(KernelMode, FALSE, &iv);

	//======== 阶段A: TRANSPARENT目标(真冷单T存活至普查) ========
	//M11.2判读: NtRWRP三度脱落定罪撤池; MmGetPhysMemRanges prologue
	//含相对call被[Reloc]拒(留池=重定位安全门演示件);
	//MmGetSystemRoutineAddress=实证真冷(探针0NPF)+可重定位→必为T1,
	//方向一(HOOKS驻留核上T失效)由此可取
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
		//每核单步窗口在两个hook条目间交替=多hook窗口机制实测);
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
	//======== 阶段B: 16核互偷普查(普通模式×TRANSPARENT, 双向拓扑) ========
	ULONG aIdx = (tLive >= 2) ? 1 : 0;    //仍活的T(移除后=T2; 单live=T1)
#if GNPT_M92_VARIANT == 0 || GNPT_M92_VARIANT == 3 || GNPT_M92_VARIANT == 6 || GNPT_M92_VARIANT == 7
	if (tLive >= 1)
	{
		UNICODE_STRING nName;
		RtlInitUnicodeString(&nName, L"KeInitializeDpc");
		g_demoN = MmGetSystemRoutineAddress(&nName);
		if (g_demoN == NULL)
		{
			FlLog("[MultiHook] 阶段B: KeInitializeDpc解析失败, 混装本轮跳过");
		}
		else if ((ULONG_PTR)PAGE_ALIGN(g_demoN) ==
			(ULONG_PTR)PAGE_ALIGN(g_demoT[aIdx]))
		{
			FlLog("[MultiHook] 阶段B: KeInitializeDpc与T%u同页, 混装本轮跳过",
				aIdx + 1);
		}
		else
		{
			GNPT_HOOK h = { 0 };
			h.Target = g_demoN;
			h.Callback = DemoCountCallback;
			h.Context = &g_demoNCall;
			h.Flags = 0;    //普通模式: Ke*普通内核函数(hook.h纪律5), 无热探针
			NTSTATUS st = GnptHookInstall(&h);
			FlLog("[MultiHook] 阶段B 混装: 普通模式hook KeInitializeDpc(%p): %s(Flags=0)",
				g_demoN, NT_SUCCESS(st) ? "Install OK" : "FAIL(见[Reloc]/[Hook]行)");
			if (NT_SUCCESS(st))
			{
				//16核互偷普查: 每核先T后N各触发一次, 前后快照记Δ——
				//(TΔ>0, NΔ=0)=该核P/HIDE驻留; (TΔ=0, NΔ>0)=该核HOOKS驻留;
				//双向拓扑一次取齐, 不依赖预设驻留(M11.1教训: 自然流量先占)。
				//核间1s隔: 单次T触发≈百级exit, 16核连发会打满tstorm桶
				//(1024/700ms)致普查中途脱落
				ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
				if (cpuCount > 64)
				{
					cpuCount = 64;
				}
				FlLog("[MultiHook] 阶段B: %u核互偷普查开始(每核先T后N, 核间1s隔)",
					cpuCount);
				for (ULONG c = 0; c < cpuCount; c++)
				{
					KeSetSystemAffinityThread((KAFFINITY)1 << c);
					LONG64 tBefore = g_demoTCall[aIdx];
					LONG64 nBefore = g_demoNCall;
					DemoFireT(aIdx);
					DemoFireN();
					FlLog("[MultiHook] 普查核%u: TΔ=%lld, NΔ=%lld (T总=%lld, N总=%lld)",
						c,
						g_demoTCall[aIdx] - tBefore, g_demoNCall - nBefore,
						g_demoTCall[aIdx], g_demoNCall);
					iv.QuadPart = -10000000LL;    //1s: 隔开防普查自身打满tstorm桶
					KeDelayExecutionThread(KernelMode, FALSE, &iv);
				}
				FlLog("[MultiHook] 阶段B: 普查完成(逐核判读: T增且N不增=P/HIDE; T不增且N增=HOOKS)");
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

	//M9.2变体形态标识(横幅外第二证据, 防测错形态)
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

	//接管成功, 安装演示hook
	//v0.9p=全功能恢复轮: demo回归(v0.9n-v0.9o鉴别期停用)——
	//与隐蔽/MSR/CPUID面一起, 在新BIOS+加速框架下补测"全功能"格
	//M10.11终裁(SSDT定位器移除): 目标解析=调用者责任(EPT契约
	//对齐——GeptHooks同款, GNPT_HOOK.Target直接传指针; 判例
	//M10.11完整留档v2-v6五轮与版本无关架构, 重开此题从v6起步)
	//M9.2变体: hook面门=全功能(0)/裸hook(3)/隐蔽+hook(6)/hook+MSR(7)
	//——x9/x10虽在旧调用门内, 但旧detour内层门不含=M10轮无hook面;
	//M11.x序列线程沿用内层门语义(x系鉴别产物判读史保真), 线程恒启动
	DemoMultiHookStart();
	//M9.2(v2): MSR面独立调用(全功能/裸MSR/隐蔽+MSR/hook+MSR/M10.2决策轮/M10.5细分轮)
#if GNPT_M92_VARIANT == 0 || GNPT_M92_VARIANT == 4 || GNPT_M92_VARIANT == 5 || GNPT_M92_VARIANT == 7 || GNPT_M92_VARIANT == 9 || GNPT_M92_VARIANT == 10
	DemoMsrInstall();
#endif
	FlLog("[Entry] 完成(%s)", GNPT_BUILD_TAG);
	return STATUS_SUCCESS;
}
