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

//demo目标: TRANSPARENT模式hook——无痕验证主战场。选型=按序尝试
//的候选链+引擎安装期热探测实测筛选(页冷是TRANSPARENT唯一可行性
//前提, 且是运行时性质——Nt体按字母序聚簇, "名字冷"≠"页冷",
//v0.9h实测NtVdmControl页与NtWait*家族同页=63M exit风暴)。候选
//均须PG覆盖且页冷: KeBugCheckEx(经典PG守卫目标, 崩溃路径=页
//天然冷; 严禁自触发)。≥2h浸泡无0x109=读透明经受PG真实检验。
//普通模式(Flags=0)demo已毕业(v0.9f/g累计4.6M次触发), 且两模式
//不可并存(正常hook使核驻留HOOKS视图, 该树对TRANSPARENT页不
//布防=恒等直通, hook失效)
static PVOID g_demoTarget = NULL;
static volatile LONG64 g_demoCalls = 0;

//demo回调(detour语义, 返回值=新函数返回值)。
//回调运行在任意线程/任意IRQL(含DISPATCH级): 只做IRQL安全操作,
//禁止FlLog/DbgPrint/分页内存/阻塞(完整纪律见hook.h)
static ULONG64 DemoTargetCallback(PVOID Context, ULONG64 Arg1,
	ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4, ULONG64* StackArgs)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(StackArgs);
	InterlockedIncrement64(&g_demoCalls);    //IRQL安全计数(卸载总结读)
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

//TRANSPARENT自触发线程: 直接调用Nt体×3(经hook全链: 潜伏取指
//fault→EXEC窗口+TF→#DB归返潜伏→detour→CallOriginal单步重放)。
//参数=查询不存在的固件变量(预期错误码返回, 零副作用); 多余
//寄存器参数被少参目标按x64 ABI忽略——一条调用形态覆盖全部候选
static KEVENT g_demoPgDone;
static BOOLEAN g_demoPgArmed = FALSE;
static VOID DemoPgTriggerThread(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	LARGE_INTEGER iv;
	iv.QuadPart = -5LL * 10000000LL;    //5s: 等安装落定/系统稳定
	KeDelayExecutionThread(KernelMode, FALSE, &iv);
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"GNPTProbe");
	WCHAR buf[8];
	ULONG ret = 0;
	typedef NTSTATUS(*GNPT_DEMO_FN)(PUNICODE_STRING, PVOID, ULONG, PULONG);
	for (ULONG i = 0; i < 3; i++)
	{
		NTSTATUS st = ((GNPT_DEMO_FN)g_demoTarget)(
			&name, buf, sizeof(buf), &ret);
		FlLog("[Demo] TRANSPARENT自触发#%u: 状态=0x%X",
			i + 1, (ULONG)st);
		iv.QuadPart = -10000000LL;    //1s
		KeDelayExecutionThread(KernelMode, FALSE, &iv);
	}
	KeSetEvent(&g_demoPgDone, IO_NO_INCREMENT, FALSE);
	PsTerminateSystemThread(STATUS_SUCCESS);
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

static VOID DemoHookInstall(VOID)
{
	//M9.2变体: detour块=全功能(0)/裸hook(3)/隐蔽+hook(6)/hook+MSR(7)
#if GNPT_M92_VARIANT == 0 || GNPT_M92_VARIANT == 3 || GNPT_M92_VARIANT == 6 || GNPT_M92_VARIANT == 7
	//detour hook(TRANSPARENT模式): 目标=按序尝试的候选链(首个安装
	//成功者胜出; 引擎安装期热探测拒绝热页=正常降级, [Hook]行留痕)。
	//prologue不可重定位=[Reloc]拒绝取下一候选
	static const struct
	{
		PCWSTR     Name;
		const char* Log;        //窄字符名(FlLog为ANSI格式化)
		BOOLEAN    SelfTrigger; //候选可否安全自触发(KeBugCheckEx严禁)
	} targets[] = {
		{ L"KeBugCheckEx",           "KeBugCheckEx",           FALSE },
		{ L"NtRequestWaitReplyPort", "NtRequestWaitReplyPort", TRUE  },
	};
	//候选禁类: 同步原语页(wait家族同页的目标, 如NtVdmControl)——
	//页级单步对同步调用=全系统等待停顿, gate测不出页的"角色"(安装时
	//冷运行中热), shed有界exit数但有界不了UI关键路径的停顿后果
	//(3/3 DWM事故相关); 待出现页角色判定手段前不入选
	BOOLEAN installed = FALSE;
	BOOLEAN selfTrigger = FALSE;
	for (ULONG i = 0; i < RTL_NUMBER_OF(targets); i++)
	{
		UNICODE_STRING name;
		RtlInitUnicodeString(&name, targets[i].Name);
		g_demoTarget = MmGetSystemRoutineAddress(&name);
		if (g_demoTarget == NULL)
		{
			FlLog("[Demo] %s解析失败, 下一候选", targets[i].Log);
			continue;
		}
		GNPT_HOOK demo = { 0 };
		demo.Target = g_demoTarget;
		demo.Callback = DemoTargetCallback;
		demo.Context = NULL;
		demo.StackArgs = 0;
		demo.Flags = HOOK_TRANSPARENT;
		NTSTATUS st = GnptHookInstall(&demo);
		FlLog("[Demo] TRANSPARENT hook %s(%p): %s(候选%u/%u, 触发计数=卸载总结)",
			targets[i].Log, g_demoTarget,
			NT_SUCCESS(st) ? "OK" : "FAIL(见[Hook]行, 下一候选)",
			i + 1, (ULONG)RTL_NUMBER_OF(targets));
		if (NT_SUCCESS(st))
		{
			installed = TRUE;
			selfTrigger = targets[i].SelfTrigger;
			break;
		}
	}
	//自触发线程(仅可安全调用的候选): 验证TRANSPARENT单步链活跃
	//(detour/CallOriginal/窗口开合), 不依赖自然触发
	if (!installed)
	{
		FlLog("[Demo] TRANSPARENT: 候选全拒(hookless浸泡形态, "
			"引擎+隐蔽+MSR面验证)");
	}
	if (installed && selfTrigger)
	{
		KeInitializeEvent(&g_demoPgDone, NotificationEvent, FALSE);
		g_demoPgArmed = TRUE;
		HANDLE th = NULL;
		NTSTATUS tst = PsCreateSystemThread(&th, 0, NULL, NULL,
			NULL, DemoPgTriggerThread, NULL);
		if (NT_SUCCESS(tst))
		{
			ZwClose(th);    //句柄即弃(线程对象自持有引用)
		}
		else
		{
			FlLog("[Demo] TRANSPARENT自触发线程创建失败=0x%X", (ULONG)tst);
		}
	}
#endif
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	//自触发线程收尾等待(有界: MSR 6s>3+3窗口; TRANSPARENT 15s>
	//5+3×1窗口——防窗口内卸载撞在途单步)
	if (g_demoMsrArmed)
	{
		LARGE_INTEGER to;
		to.QuadPart = -6LL * 10000000LL;
		KeWaitForSingleObject(&g_demoMsrDone, Executive,
			KernelMode, FALSE, &to);
	}
	if (g_demoPgArmed)
	{
		LARGE_INTEGER to;
		to.QuadPart = -15LL * 10000000LL;
		KeWaitForSingleObject(&g_demoPgDone, Executive,
			KernelMode, FALSE, &to);
	}
	//按目标移除(未显式移除的hook由关停流程统一清理)
	FlLog("[Unload] Demo TRANSPARENT触发计数=%lld, LSTAR读拦截=%lld次, 写拦截=%lld次",
		g_demoCalls, g_demoRdmsr, g_demoWrmsr);
	GnptMsrHookRemove(0xC0000082);
	if (g_demoTarget != NULL)
	{
		GnptHookRemove(g_demoTarget);
	}
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
#endif

	//接管成功, 安装演示hook
	//v0.9p=全功能恢复轮: demo回归(v0.9n-v0.9o鉴别期停用)——
	//与隐蔽/MSR/CPUID面一起, 在新BIOS+加速框架下补测"全功能"格
	//M9.2变体: hook开启=全功能(0)/裸hook(3)/隐蔽+hook(6)/hook+MSR(7)
#if GNPT_M92_VARIANT == 0 || GNPT_M92_VARIANT == 3 || GNPT_M92_VARIANT == 6 || GNPT_M92_VARIANT == 7
	DemoHookInstall();
#endif
	//M9.2(v2): MSR面独立调用(全功能/裸MSR/隐蔽+MSR/hook+MSR)
#if GNPT_M92_VARIANT == 0 || GNPT_M92_VARIANT == 4 || GNPT_M92_VARIANT == 5 || GNPT_M92_VARIANT == 7
	DemoMsrInstall();
#endif
	FlLog("[Entry] 完成(%s)", GNPT_BUILD_TAG);
	return STATUS_SUCCESS;
}
