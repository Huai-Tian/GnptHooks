#pragma once
#ifndef GNPTMSR_H
#define GNPTMSR_H
#include<ntifs.h>

//====================================================================
// MSR拦截简易API(MSR数据伪装; SVM侧)
//
//原理: 每核MSRPM(8KB位图)置位后, guest内RDMSR/WRMSR对该MSR产生
//VMEXIT(0x7C) → 分发到用户回调:
//  - 读回调返回值=rdmsr可见值(伪造: 可返回假地址/假数据)
//  - 写回调返回TRUE=放行代写, FALSE=静默丢弃(guest认为写成功)
//位图零开销: 未hook的MSR仍直通(硬件按位图判定, 不产生exit)
//——MSR_PROT总开关SvmFillVmcb常置(位图全0=零exit, 与IOPM同型)
//
//SVM与VMX位图布局差异(APM §15.11 Table 15-8 vs SDM 25.6.9):
//  VMX: 4KB=[读低][读高][写低][写高]各1KB, 每MSR 1位
//  SVM: 8KB=4个2KB向量(每MSR 2位: lsb=读拦截, msb=写拦截):
//    向量0(字节+0x000): MSR 0x00000000-0x00001FFF
//    向量1(字节+0x800): MSR 0xC0000000-0xC0001FFF
//    向量2(字节+0x1000): MSR 0xC0010000-0xC0011FFF
//    向量3(字节+0x1800): Reserved
//  向量内: 字节=off/4, 位=(off&3)*2(读)或+1(写)
//
//范围外警示(APM §15.11原文): MSR_PROT活动时, 访问MSRPM未覆盖
//的MSR(如0x40000000+)自动exit——分发器须真值回放(裸机等价)
//
//使用纪律(与GNPT_CALLBACK同源, 违反=蓝屏/死锁风险):
//  1. 回调运行在exit handler上下文(任意线程/任意IRQL, 被中断
//     线程可能持任意锁): 只做Interlocked*/无锁环/GnptMsrReadReal;
//     绝不FlLog/DbgPrint/分页内存/阻塞
//  2. 读回调需要真实值时调GnptMsrReadReal(Msr)——对架构保留MSR
//     (真读=#GP)绝不可调, 直接返回伪造值即可
//  3. 写回调返回FALSE=静默丢弃: guest读到"写成功"假象。对系统
//     运行期会合法写的MSR(如GS base)慎用, 监控场景用TRUE放行
//  4. Remove后新触发立即停止; 在途exit(已查表)安全完成
//
//EXITINFO1位义(0x7C): bit0=0读/1写。APM附录A仅一行描述未载位
//义, 此处=NOIRVisor/SimpleSvm交叉共识, 首测验证(读hook触发时
//bit0应=0, 判据见NOTES M7.1)
//====================================================================

//读回调: 返回值=rdmsr可见值(伪造)。需要真值→GnptMsrReadReal
typedef ULONG64 (*GNPT_MSR_READ_CB)(PVOID Context, ULONG32 Msr);
//写回调: 返回TRUE=放行代写(监控语义), FALSE=静默丢弃(拦截语义)
typedef BOOLEAN (*GNPT_MSR_WRITE_CB)(PVOID Context, ULONG32 Msr, ULONG64 Value);

typedef struct _GNPT_MSR_HOOK
{
	ULONG32 Msr;               //目标MSR号(如IA32_LSTAR=0xC0000082;
	                          //须在MSRPM三向量覆盖范围内, 范围外Install拒绝)
	PVOID Context;             //用户上下文(原样传给回调)
	GNPT_MSR_READ_CB OnRead;   //NULL=读不拦截(读位不置)
	GNPT_MSR_WRITE_CB OnWrite; //NULL=写不拦截(写位不置)
} GNPT_MSR_HOOK, *PGNPT_MSR_HOOK;

//安装(PASSIVE_LEVEL, 引擎运行中): 全核MSRPM位图root直写(纯内存
//写, 无vmcall无TLB同步——位图内容硬件每指令现查, 基址不变无
//clean bit问题)。同MSR重复安装=拒绝
NTSTATUS GnptMsrHookInstall(const GNPT_MSR_HOOK* Hook);

//移除(PASSIVE_LEVEL): 先标Removed(分发立即停止命中)再清位图;
//在途exit(已查表)安全完成
NTSTATUS GnptMsrHookRemove(ULONG32 Msr);

//枚举live MSR hook(Buffer=NULL时*InOutCount返回数量)
NTSTATUS GnptMsrHookEnumerate(GNPT_MSR_HOOK* Buffer, ULONG* InOutCount);

//回调内取真实MSR值(root态__readmsr; 保留MSR勿调——会#GP蓝屏)
ULONG64 GnptMsrReadReal(ULONG32 Msr);

//==== exit handler内部调用(svm.c的0x7C case调用, 勿直接调) ====
//读分发: TRUE=已拦截(*OutValue=回调返回值即伪造值), FALSE=未
//hook→调用方真值回放
BOOLEAN GnptMsrDispatchRead(ULONG32 Msr, ULONG64* OutValue);
//写分发: TRUE=允许代写(未hook/回调放行), FALSE=回调拒绝(静默丢弃)
BOOLEAN GnptMsrDispatchWrite(ULONG32 Msr, ULONG64 Value);

#endif //GNPTMSR_H
