#include<ntifs.h>
#include"common.h"
#include"svm.h"
#include"hook.h"

//本文件=框架使用示例(面向二次开发者):
//  DriverEntry  -> SvmStartAllCpus接管全核 -> 安装自己的hook
//  DriverUnload -> 移除hook -> SvmShutdownAllCpus关停并释放资源

//示例hook(M3验收): NtClose detour。回调IRQL纪律: Interlocked+无锁环事件
//+CallOriginal(高频路径防刷爆: 'h'环每64次留痕1条)
static volatile LONG64 g_demoNtCloseCalls = 0;
static ULONG64 DemoNtCloseHook(PVOID Context, ULONG64 Handle,
	ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4, ULONG64* StackArgs)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(StackArgs);
	LONG64 n = InterlockedIncrement64(&g_demoNtCloseCalls);
	if (n == 1 || (n & 63) == 0)
	{
		FlRingPush('h', KeGetCurrentProcessorNumber(),
			(ULONG)(Handle & 0xFFFFFFFFULL), (ULONG64)n, 0, 0);
	}
	return GnptCallOriginal(Handle, Arg2, Arg3, Arg4);
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	//关停: 移除残余hook(引擎仍在位=在途回调安全完成)→全核去虚拟化→释放资源
	FlLog("[Unload] NtClose示例hook触发计数=%lld", g_demoNtCloseCalls);
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

	//示例hook: NtClose(单寄存器参数; 系统高频路径=双NPT视图切换引擎压力面)
	//TRANSPARENT=1: 读透明模式(M4.6——db/PG只见原始字节, 每命中2exit)
	{
		GNPT_HOOK demo = { 0 };
		UNICODE_STRING name;
		RtlInitUnicodeString(&name, L"NtClose");
		demo.Target = MmGetSystemRoutineAddress(&name);
		demo.Callback = DemoNtCloseHook;
		demo.Context = NULL;
		demo.StackArgs = 0;
		demo.Flags = HOOK_TRANSPARENT;
		NTSTATUS hst = GnptHookInstall(&demo);
		FlLog("[Entry] NtClose示例hook安装%s(目标=%p)",
			NT_SUCCESS(hst) ? "成功" : "失败", demo.Target);
	}

	FlLog("[Entry] 完成(%s)", GNPT_BUILD_TAG);
	return STATUS_SUCCESS;
}
