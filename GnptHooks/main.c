#include<ntifs.h>
#include"common.h"
#include"svm.h"
#include"hook.h"

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
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	//按目标移除(未显式移除的hook由关停流程统一清理)
	FlLog("[Unload] Demo NtClose触发计数=%lld", g_demoCalls);
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
