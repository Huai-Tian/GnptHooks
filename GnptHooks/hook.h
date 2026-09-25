#pragma once
#ifndef HOOK_H
#define HOOK_H
#include"common.h"

//====================================================================
// 公开API——普通开发者零虚拟化知识即可用虚拟层HOOK(双NPT detour式)
//
//语义:
//  - hook触发=Secondary视图CodePage跳转→跳板槽→GnptStubEntry
//    →用户回调→ret回调用者
//  - GnptCallOriginal经LDE重定位跳板调原函数(prologue重放+尾跳,
//    视图无关; 跳板尾跳点在两视图下均为原始字节)
//  - 回调返回值=hook函数的新返回值(完整detour控制权: 可改参数/
//    返回值/不调用原函数直接拦截)
//
//使用纪律(违反=蓝屏/死锁风险):
//  1. 回调运行在原函数的**任意线程/任意IRQL上下文**(含DISPATCH级):
//     只做IRQL安全操作(Interlocked*/无锁环事件/GnptCallOriginal);
//     绝不FlLog/DbgPrint/分页内存访问/阻塞等待
//  2. 回调内调用本hook的原函数**必须经GnptCallOriginal**(直接call
//     Target=Secondary视图下撞CodePage跳转码无限递归)
//  3. 嵌套hook语义: 回调在当前视图执行——回调里调用的其他hook目标
//     正常触发(标准detour语义)
//  4. 第5+参数(栈参数)可转发: 安装时GNPT_HOOK.StackArgs=目标函数
//     栈参数个数(≤GNPT_MAX_STACK_ARGS)→回调收到StackArgs指针
//     (指向触发帧上实参, 可读可写——写后GnptCallOriginal按改写值
//     转发)+GnptCallOriginal自动转发; StackArgs=0=仅4寄存器参
//
//硬件要求: 引擎运行中(全核in-guest)才可安装; 目标prologue含相对
//  分支/RIP-relative超±2GB=Install拒绝(日志[Reloc]行留痕)
//====================================================================

//detour回调: 返回值=hook函数的返回值; Context=安装时原样传入;
//Arg1-4=原函数的rcx/rdx/r8/r9(x64前4个寄存器参数);
//StackArgs=第5+参数数组(指向触发帧上实参, 可读可写——写后
//GnptCallOriginal按改写值转发; NULL=安装时StackArgs=0未声明)
typedef ULONG64 (*GNPT_CALLBACK)(
	PVOID Context, ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4,
	ULONG64* StackArgs);

//栈参数转发上限(hook-asm.asm GnptCallOrigAsm固定帧=32槽×8B)
#define GNPT_MAX_STACK_ARGS  32
//最大同时驻留hook数(条目静态数组)
#define GNPT_MAX_HOOKS       16

//安装描述(值语义, 安装后内部自持)
typedef struct _GNPT_HOOK
{
	PVOID Target;             //目标函数(内核虚拟地址)
	GNPT_CALLBACK Callback;   //detour回调
	PVOID Context;            //用户上下文(原样传给回调)
	ULONG StackArgs;           //目标函数第5+栈参数个数(0=不转发;
	                          //>0时回调收StackArgs指针+CallOriginal
	                          //自动转发; 超上限Install拒绝)
	ULONG Flags;               //位0=HOOK_TRANSPARENT: 读透明模式
	                          //(潜伏P=0+执行窗口翻转, PG/扫描器读
	                          //=原始字节; 每指令2exit只适合低频
	                          //目标; 见hook.c/npt.h)
} GNPT_HOOK, *PGNPT_HOOK;

//hook模式标志(Flags位)
#define HOOK_TRANSPARENT        0x1   //读透明: 每核S副本潜伏P=0,
                                       //取指→执行窗口(#DB复位潜伏);
                                       //外部读→切P读原始字节。
                                       //低频目标专用(高频=NtClose式
                                       //每指令2exit风暴)

//安装hook(PASSIVE_LEVEL, 引擎运行中): CodePage构建+双NPT视图布防
//+全核TLB同步(布防即刻生效)
NTSTATUS GnptHookInstall(const GNPT_HOOK* Hook);

//移除hook(PASSIVE_LEVEL): 双视图PTE恒等还原+全核TLB同步→hook立即
//失效; 在途回调安全完成(槽/条目延迟到卸载释放)
NTSTATUS GnptHookRemove(PVOID Target);

//回调内调用原函数(仅回调上下文有效, 其他上下文返回0):
//统一经LDE重定位跳板(版本无关, 无prologue硬编码, 视图无关);
//声明StackArgs>0的hook, 第5+参数自动从触发帧转发
//(回调对StackArgs数组的改写一并生效)
ULONG64 GnptCallOriginal(ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4);

//卸载收尾: DriverUnload在关引擎**之前**调用GnptHookRemoveAll
//(移除全部live hook, 在途回调安全完成); 关引擎**之后**调用
//GnptHookFreeMemory(纯内存释放, 无引擎依赖)
VOID GnptHookRemoveAll(VOID);
VOID GnptHookFreeMemory(VOID);

//===== 引擎内部(svm.c exit handler调用; 使用者无需关注) =====
//NPF视图切换引擎: 处理返回TRUE(svm.c直接重入guest); FALSE=未处理
//(svm.c按异常留痕)。ExitInfo1/2=VMCB EXITINFO1/2
BOOLEAN GnptHookNpfEngine(struct _VMCB* Vmcb, ULONG Cpu,
	ULONG64 ExitInfo1, ULONG64 ExitInfo2);

//TF+#DB单步原语(读透明基础件): svm.c的0x41/0x70/0x71三case入口。
//返回TRUE=已处理(重入guest); FALSE=非单步窗口(svm.c防御留痕)
BOOLEAN GnptHookStepDbExit(struct _VMCB* Vmcb, ULONG Cpu);
BOOLEAN GnptHookStepEmuPushf(struct _VMCB* Vmcb, ULONG Cpu);
BOOLEAN GnptHookStepEmuPopf(struct _VMCB* Vmcb, ULONG Cpu);

//单步窗口泄漏防御收口: svm.c每exit首查——armed而guest TF
//已失(清TF类指令使#DB永不到达)=拦截位+视图泄漏, 统一收尾
VOID GnptHookStepLeakCheck(struct _VMCB* Vmcb, ULONG Cpu);

#endif // HOOK_H
