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
//  5. **读写位成对纪律(违反=时钟看门狗蓝屏风险)**: NPT自我隐蔽
//     在场时, 对"置了读拦截"的MSR, 其写路径**禁止直通**(OnWrite=
//     NULL)——"直通WRMSR×读exit×改译页"三体竞态=CLOCK_WATCHDOG_
//     TIMEOUT系列根因。正确形态=OnWrite忠实放行回调(TRUE+root
//     代写, 语义与直通等价)。MSR被系统周期性写是常态(如LSTAR被
//     PatchGuard周期性重写), "运行期无人写"假设不可依赖
//
//EXITINFO1位义(0x7C): bit0=0读/1写(APM附录A未载此位义, 为
//执行级验证结论)
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

//安装(PASSIVE_LEVEL, 引擎运行中): 全核MSRPM位图经vmmcall root
//原语操作(隐蔽生效后guest态直写无效; 位图内容硬件每指令现查,
//基址不变无clean bit/TLB问题)。同MSR重复安装=拒绝
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
//root位图原语(svm.c的0x81 MSRBIT case调用, GIF=0直访物理):
//全核MSRPM位操作(自我隐蔽配套)
VOID GnptMsrBitmapRootAllCpus(ULONG32 Msr, BOOLEAN IsWrite, BOOLEAN Set);

//==== 引擎内部共用(svm.c故事面布防调用) ====
//MSR号→MSRPM位定位(Table 15-8三向量): FALSE=范围外。
//OutByteOff/OutBit: 字节偏移+读位起始位(写位=+1)
BOOLEAN GnptMsrLocate(ULONG32 Msr, PULONG OutByteOff, UCHAR* OutBit);

//引擎保留MSR: EFER(0xC0000080)/VM_CR(0xC0010114)/VM_HSAVE_PA
//(0xC0010117)属"SVM未激活"自洽故事面——exit 0x7C的特判先于公共
//分发表, 用户Install同号=拒绝(fail-loud, 死hook零容忍)
BOOLEAN GnptMsrIsEngineReserved(ULONG32 Msr);

#endif //GNPTMSR_H
