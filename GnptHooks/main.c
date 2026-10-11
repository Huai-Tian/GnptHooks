#include<ntifs.h>
#include"common.h"
#include"svm.h"
#include"hook.h"
#include"msr.h"

//本文件=框架使用示例(面向二次开发者):
//  DriverEntry  -> SvmStartAllCpus接管全核 -> 安装自己的hook
//  DriverUnload -> 移除hook -> SvmShutdownAllCpus关停并释放资源
//框架细节(资源分配/串行启动/互斥仲裁/内置隐藏/日志)全在svm.c,
//使用者只需关心hook回调本身。API契约见hook.h/msr.h头注释。
//demo不区分构建形态: Debug构建经观测体系留痕, Release构建
//FlLog为空操作(两种构建的安装/触发/移除行为完全一致)

//demo目标(按名解析; NULL=解析失败, 对应安装跳过)
static PVOID g_demoHot = NULL;    //热靶: TRANSPARENT(DR机件)
static PVOID g_demoCold = NULL;   //冷靶: 普通模式(CodePage)

//普通模式演示靶(驱动本地冷函数): 纯寄存器ALU链, 无RIP-rel无
//相对分支无控制转移=重定位安全门必过; 页冷无自然流量=普通
//模式的合规选型(使用纪律5b: 高频被调目标一律HOOK_TRANSPARENT)
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

//hook回调(detour语义, 返回值=新函数返回值)。
//回调运行在任意线程/任意IRQL(含DISPATCH级): 只做IRQL安全操作,
//禁止FlLog/DbgPrint/分页内存/阻塞(完整纪律见hook.h)
static ULONG64 DemoHookCallback(PVOID Context, ULONG64 Arg1,
	ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4, ULONG64* StackArgs)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(StackArgs);
	//示例=透传原函数并返回其结果(零副作用监控)。
	//拦截=直接return目标语义的失败值;
	//篡改=修改Arg后经GnptCallOriginal转发改写值
	return GnptCallOriginal(Arg1, Arg2, Arg3, Arg4);
}

//MSR hook读回调(LSTAR=系统调用入口地址, 0xC0000082)
static ULONG64 DemoLstarOnRead(PVOID Context, ULONG32 Msr)
{
	UNREFERENCED_PARAMETER(Context);
	//示例=返回真值(零副作用监控)。伪造=直接return任意值
	//(guest的rdmsr只能见到它)
	return GnptMsrReadReal(Msr);
}

//写回调: 忠实放行——hook的MSR写位必须拦截, 由root代写(写直通
//×读exit×NPT改译隐蔽的三体竞态=时钟看门狗蓝屏根因, 见msr.h
//使用纪律5)
static BOOLEAN DemoLstarOnWrite(PVOID Context, ULONG32 Msr, ULONG64 Value)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Msr);
	UNREFERENCED_PARAMETER(Value);
	return TRUE;    //放行代写(root真写, 与直通语义等价)
}

//安装演示hook(接管成功后调用)。命中流量由观测体系面包屑留痕,
//demo自身零记账
static VOID DemoHookInstall(VOID)
{
	//全核守卫: 裸核上hook布防/root原语=蓝屏——部分接管
	//(GNPT_TAKE_CORES剂量形态)下hook层整体让路=自动纯引擎
	if (g_svmVcpuCount != KeQueryActiveProcessorCount(NULL))
	{
		FlLog("[Demo] 非全核接管(诊断剂量形态), demo跳过");
		return;
	}
	//演示一: 热靶TRANSPARENT(DR机件)——高频被调目标按使用
	//纪律5b选HOOK_TRANSPARENT(原页恒等, 每次目标调用恰1 exit);
	//自然系统流量触发
	{
		UNICODE_STRING name;
		RtlInitUnicodeString(&name, L"PsGetProcessId");
		g_demoHot = MmGetSystemRoutineAddress(&name);
		if (g_demoHot == NULL)
		{
			FlLog("[Demo] PsGetProcessId解析失败, 演示一跳过");
		}
		else
		{
			GNPT_HOOK hook = { 0 };
			hook.Target = g_demoHot;
			hook.Callback = DemoHookCallback;
			hook.Flags = HOOK_TRANSPARENT;
			NTSTATUS st = GnptHookInstall(&hook);
			FlLog("[Demo] hook PsGetProcessId(%p, TRANSPARENT): %s",
				g_demoHot, NT_SUCCESS(st) ? "OK" : "FAIL(见[Hook]行)");
		}
	}
	//演示二: 冷靶普通模式(Flags=0)——双NPT视图+CodePage, 稳态
	//命中零VM-Exit; 安装后自调一次=detour全链闭环演示
	{
		GNPT_HOOK hook = { 0 };
		hook.Target = DemoColdTargetFn;
		hook.Callback = DemoHookCallback;
		NTSTATUS st = GnptHookInstall(&hook);
		FlLog("[Demo] hook 本地冷靶(普通模式): %s",
			NT_SUCCESS(st) ? "OK" : "FAIL(见[Hook]行)");
		if (NT_SUCCESS(st))
		{
			g_demoCold = (PVOID)DemoColdTargetFn;
			ULONG64 r = DemoColdTargetFn(1, 2, 3, 4);
			FlLog("[Demo] 冷靶自调: 返回=%llX(回调经GnptCallOriginal"
				"透传, 与直算值等值=detour闭环)",
				(unsigned long long)r);
		}
	}
	//演示三: MSR hook(读写双拦; 写位拦截=使用纪律5)
	{
		GNPT_MSR_HOOK msrHook = { 0 };
		msrHook.Msr = 0xC0000082;    //IA32_LSTAR
		msrHook.OnRead = DemoLstarOnRead;
		msrHook.OnWrite = DemoLstarOnWrite;
		NTSTATUS st = GnptMsrHookInstall(&msrHook);
		FlLog("[Demo] MSR hook LSTAR(0xC0000082): %s",
			NT_SUCCESS(st) ? "OK" : "FAIL(见[MSR]行)");
	}
}

//显式移除演示hook(教学); 卸载流程的GnptHookRemoveAll会收尾
//未显式移除的残余hook, 两道机制互为冗余
static VOID DemoHookShutdown(VOID)
{
	GnptMsrHookRemove(0xC0000082);
	if (g_demoCold != NULL)
	{
		GnptHookRemove(g_demoCold);
		g_demoCold = NULL;
	}
	if (g_demoHot != NULL)
	{
		GnptHookRemove(g_demoHot);
		g_demoHot = NULL;
	}
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	DemoHookShutdown();
	//关停: 移除残余hook(引擎仍在位=在途回调安全完成)→全核去虚拟化
	//→释放资源。三段顺序不可变(卸载契约见hook.h)
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

	//观测体系最先初始化(T1/T2/看门狗线程; Release构建空操作)
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
