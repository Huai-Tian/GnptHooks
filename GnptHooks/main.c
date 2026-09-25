#include<ntifs.h>
#include"common.h"
#include"svm.h"
#include"hook.h"

//本文件=框架使用示例(面向二次开发者):
//  DriverEntry  -> SvmStartAllCpus接管全核 -> 安装自己的hook
//  DriverUnload -> 移除hook -> SvmShutdownAllCpus关停并释放资源

//示例hook: ZwPowerInformation桩 TRANSPARENT detour。
//选桩理由: 用户态syscall绕过Zw桩直达SSDT体→桩冷(仅内核显式
//调用者); 桩页=nt .text(PG广域校验可能覆盖→浸泡期READ_TRANS
//面包屑=读透明证据); 自触发=无需用户操作(SetSystemTime类路径
//嵌套下拉黑)。回调IRQL纪律: Interlocked+无锁环+CallOriginal
static volatile LONG64 g_demoCalls = 0;
static ULONG64 DemoTransHook(PVOID Context, ULONG64 Arg1,
	ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4, ULONG64* StackArgs)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(StackArgs);
	LONG64 n = InterlockedIncrement64(&g_demoCalls);
	FlRingPush('h', KeGetCurrentProcessorNumber(),
		(ULONG)(Arg1 & 0xFFFFFFFFULL), (ULONG64)n, 0, 0);
	return GnptCallOriginal(Arg1, Arg2, Arg3, Arg4);
}

//自触发线程: 调Zw桩3次(1s间隔)=四视图舞步全链路自验证
//(取指fault→EXEC+TF→#DB→HIDE; 参数无效→体报错, 无害)
typedef NTSTATUS(*PFN_ZW_POWER)(ULONG, PVOID, ULONG, PVOID, ULONG);
static PVOID g_demoTarget = NULL;
static KEVENT g_demoTrigDone;
static BOOLEAN g_demoTrigArmed = FALSE;

static VOID DemoTriggerThread(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	LARGE_INTEGER iv;
	iv.QuadPart = -3LL * 10000000LL;    //3s: 等安装落定/系统稳定
	KeDelayExecutionThread(KernelMode, FALSE, &iv);
	PFN_ZW_POWER zw = (PFN_ZW_POWER)g_demoTarget;
	for (ULONG i = 0; i < 3; i++)
	{
		NTSTATUS st = STATUS_UNSUCCESSFUL;
		if (zw != NULL)
		{
			st = zw(0, NULL, 0, NULL, 0);    //经桩=舞步自触发
		}
		FlLog("[Demo] 自触发#%u: 状态=0x%X 累计=%lld",
			i + 1, (ULONG)st, g_demoCalls);
		iv.QuadPart = -10000000LL;    //1s
		KeDelayExecutionThread(KernelMode, FALSE, &iv);
	}
	KeSetEvent(&g_demoTrigDone, IO_NO_INCREMENT, FALSE);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	//自触发线程收尾等待(有界5s, 防在途回调竞态)
	if (g_demoTrigArmed)
	{
		LARGE_INTEGER to;
		to.QuadPart = -5LL * 10000000LL;
		KeWaitForSingleObject(&g_demoTrigDone, Executive,
			KernelMode, FALSE, &to);
	}
	//关停: 移除残余hook(引擎仍在位=在途回调安全完成)→全核去虚拟化→释放资源
	FlLog("[Unload] TRANSPARENT示例hook触发计数=%lld", g_demoCalls);
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

	//示例hook: ZwPowerInformation桩 TRANSPARENT(自触发验证,
	//见文件头注释)。安装后自触发3次; 随后驻留浸泡(PG读桩页→
	//READ_TRANS面包屑+无0x109=读透明证据)
	{
		GNPT_HOOK demo = { 0 };
		UNICODE_STRING name;
		RtlInitUnicodeString(&name, L"ZwPowerInformation");
		demo.Target = MmGetSystemRoutineAddress(&name);
		FlLog("[Entry] 目标解析 ZwPowerInformation = %p", demo.Target);
		if (demo.Target != NULL)
		{
			demo.Callback = DemoTransHook;
			demo.Context = NULL;
			demo.StackArgs = 0;
			demo.Flags = HOOK_TRANSPARENT;
			NTSTATUS hst = GnptHookInstall(&demo);
			FlLog("[Entry] TRANSPARENT示例hook安装%s(目标=%p)",
				NT_SUCCESS(hst) ? "成功" : "失败", demo.Target);
			if (NT_SUCCESS(hst))
			{
				//自触发线程(异步): 3s后调桩×3
				g_demoTarget = demo.Target;
				KeInitializeEvent(&g_demoTrigDone,
					NotificationEvent, FALSE);
				g_demoTrigArmed = TRUE;
				HANDLE th = NULL;
				NTSTATUS tst = PsCreateSystemThread(&th, 0, NULL,
					NULL, NULL, DemoTriggerThread, NULL);
				if (NT_SUCCESS(tst))
				{
					ZwClose(th);    //句柄即弃(线程对象自持有引用)
				}
				else
				{
					g_demoTrigArmed = FALSE;
					FlLog("[Entry] 自触发线程创建失败=0x%X(手动触发退路: 内核态ZwPowerInformation)", (ULONG)tst);
				}
			}
		}
		else
		{
			FlLog("[Entry] ZwPowerInformation=NULL, 无hook");
		}
	}

	FlLog("[Entry] 完成(%s)", GNPT_BUILD_TAG);
	return STATUS_SUCCESS;
}
