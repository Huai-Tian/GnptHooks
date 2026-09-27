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

//demo目标: NtClose(演示期间全系统句柄关闭都会被拦截)
static PVOID g_demoNtClose = NULL;
static volatile LONG64 g_demoCalls = 0;

//demo回调(detour语义, 返回值=新函数返回值)。
//回调运行在任意线程/任意IRQL(含DISPATCH级): 只做IRQL安全操作,
//禁止FlLog/DbgPrint/分页内存/阻塞(完整纪律见hook.h)
static ULONG64 DemoNtCloseCallback(PVOID Context, ULONG64 Handle,
	ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4, ULONG64* StackArgs)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(StackArgs);
	InterlockedIncrement64(&g_demoCalls);    //IRQL安全计数(卸载总结读)
	//示例=透传原函数并返回其结果(零副作用监控)。
	//拦截=直接return STATUS_INVALID_HANDLE;
	//篡改=修改Handle/Arg后经GnptCallOriginal转发改写值
	return GnptCallOriginal(Handle, Arg2, Arg3, Arg4);
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

//MSR自触发线程: 内核线程在guest内rdmsr LSTAR×3(v0.7a已验证
//形态; 运行期系统几乎无人读LSTAR, 自触发=机制验证不依赖自然
//触发)。返回值比对=真值直读(virtual含root内读, 恒等自检)
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

static VOID DemoHookInstall(VOID)
{
	//detour hook: 目标=内核函数地址。Flags=0普通模式(HOOKS视图
	//驻留=触发0-exit+同页邻居免费+外部读自带读透明单步;
	//TRANSPARENT模式见hook.h——页级单步窗口只适合低频目标)
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"NtClose");
	g_demoNtClose = MmGetSystemRoutineAddress(&name);
	if (g_demoNtClose == NULL)
	{
		FlLog("[Demo] NtClose解析失败, 无hook");
		return;
	}
	GNPT_HOOK demo = { 0 };
	demo.Target = g_demoNtClose;
	demo.Callback = DemoNtCloseCallback;
	demo.Context = NULL;
	demo.StackArgs = 0;
	demo.Flags = 0;
	NTSTATUS st = GnptHookInstall(&demo);
	FlLog("[Demo] detour hook NtClose(%p): %s(触发计数=卸载总结)",
		g_demoNtClose, NT_SUCCESS(st) ? "OK" : "FAIL(见[Hook]行)");
	//MSR hook: 读拦截(GeptHooks main.c同款demo; wrmsr不拦=系统
	//运行期无人写LSTAR, 写位不置=零额外exit面)+自触发线程验证
	{
		GNPT_MSR_HOOK msrHook = { 0 };
		msrHook.Msr = 0xC0000082;    //IA32_LSTAR
		msrHook.OnRead = DemoLstarOnRead;
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

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	//自触发线程收尾等待(有界6s>3+3窗口, 防3s窗口内卸载撞在途线程)
	if (g_demoMsrArmed)
	{
		LARGE_INTEGER to;
		to.QuadPart = -6LL * 10000000LL;
		KeWaitForSingleObject(&g_demoMsrDone, Executive,
			KernelMode, FALSE, &to);
	}
	//按目标移除(未显式移除的hook由关停流程统一清理)
	FlLog("[Unload] Demo NtClose触发计数=%lld, LSTAR读拦截=%lld次",
		g_demoCalls, g_demoRdmsr);
	GnptMsrHookRemove(0xC0000082);
	if (g_demoNtClose != NULL)
	{
		GnptHookRemove(g_demoNtClose);
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

	//接管成功, 安装演示hook
	DemoHookInstall();
	FlLog("[Entry] 完成(%s)", GNPT_BUILD_TAG);
	return STATUS_SUCCESS;
}
