#pragma once
#ifndef VMCB_H
#define VMCB_H
#include"common.h"

//VMCB结构定义。全部偏移经AMD APM Appendix B(24593 Rev3.45)原文核对:
//Table B-1(control area, VMCB基起)+Table B-2(state save area, +0x400起)。
//注: VMSAVE/VMLOAD只管段+系统MSR集(§15.5.2), 不碰RIP/RSP/RAX

#ifdef __cplusplus
extern "C" {
#endif

//===== control area 拦截位 (VMCB +0x00C/+0x010, APM Table B-1) =====
//Misc1 (+0x00C):
#define INTERCEPT_INTR          (1UL << 0)    //物理可屏蔽中断
#define INTERCEPT_NMI           (1UL << 1)
#define INTERCEPT_SMI           (1UL << 2)
#define INTERCEPT_INIT          (1UL << 3)
#define INTERCEPT_VINTR         (1UL << 4)    //虚拟中断
#define INTERCEPT_CR0_SEL_WRITE (1UL << 5)
#define INTERCEPT_IDTR_READ     (1UL << 6)
#define INTERCEPT_GDTR_READ     (1UL << 7)
#define INTERCEPT_LDTR_READ     (1UL << 8)
#define INTERCEPT_TR_READ       (1UL << 9)
#define INTERCEPT_IDTR_WRITE    (1UL << 10)
#define INTERCEPT_GDTR_WRITE    (1UL << 11)
#define INTERCEPT_LDTR_WRITE    (1UL << 12)
#define INTERCEPT_TR_WRITE      (1UL << 13)
#define INTERCEPT_RDTSC         (1UL << 14)
#define INTERCEPT_RDPMC         (1UL << 15)
#define INTERCEPT_PUSHF         (1UL << 16)
#define INTERCEPT_POPF          (1UL << 17)
#define INTERCEPT_CPUID         (1UL << 18)
#define INTERCEPT_RSM           (1UL << 19)
#define INTERCEPT_IRET          (1UL << 20)
#define INTERCEPT_INTn          (1UL << 21)
#define INTERCEPT_INVD          (1UL << 22)
#define INTERCEPT_PAUSE         (1UL << 23)
#define INTERCEPT_HLT           (1UL << 24)
#define INTERCEPT_INVLPG        (1UL << 25)
#define INTERCEPT_INVLPGA       (1UL << 26)
#define INTERCEPT_IOIO_PROT     (1UL << 27)   //IOPM生效总开关
#define INTERCEPT_MSR_PROT      (1UL << 28)   //MSRPM生效总开关
#define INTERCEPT_TASK_SWITCH   (1UL << 29)
#define INTERCEPT_FERR_FREEZE   (1UL << 30)
#define INTERCEPT_SHUTDOWN      (1UL << 31)
//Misc2 (+0x010):
#define INTERCEPT_VMRUN         (1UL << 0)    //一致性检查强制置位
#define INTERCEPT_VMMCALL       (1UL << 1)
//InterceptException (+0x008): 向量0-31按位(M4单步窗口用)
#define EXCP_INTERCEPT_DB       (1UL << 1)    //#DB(TF单步认领; APM页855 DR6.BS=bit14)
#define INTERCEPT_VMLOAD        (1UL << 2)
#define INTERCEPT_VMSAVE        (1UL << 3)
#define INTERCEPT_STGI          (1UL << 4)
#define INTERCEPT_CLGI          (1UL << 5)
#define INTERCEPT_SKINIT        (1UL << 6)
#define INTERCEPT_RDTSCP        (1UL << 7)
#define INTERCEPT_ICEBP         (1UL << 8)
#define INTERCEPT_WBINVD        (1UL << 9)
#define INTERCEPT_MONITOR       (1UL << 10)
#define INTERCEPT_MWAIT         (1UL << 11)
#define INTERCEPT_MWAIT_COND    (1UL << 12)
#define INTERCEPT_XSETBV        (1UL << 13)
#define INTERCEPT_RDPRU         (1UL << 14)
#define INTERCEPT_EFER_WTRAP    (1UL << 15)
#define INTERCEPT_CR0_WTRAP     (1UL << 16)
#define INTERCEPT_CR3_WTRAP     (1UL << 19)
#define INTERCEPT_CR4_WTRAP     (1UL << 20)

//TLB_CONTROL (+0x05C, APM Table B-1): 0=不动 1=全flush(legacy) 3=flush本guest 7=flush本guest非全局
#define TLB_CTRL_FLUSH_ALL_GUEST 3

//EVENTINJ (VMCB+0x0A8, APM §15.20 图15-5):
//  VECTOR[7:0] TYPE[10:8](0=INTR 2=NMI 3=exception 4=softint) EV[11] V[31] ERRORCODE[63:32]
#define EVENTINJ_TYPE_INTR      0
#define EVENTINJ_TYPE_NMI       2
#define EVENTINJ_TYPE_EXCP      3
#define EVENTINJ_TYPE_SOFTINT   4
#define EVENTINJ_MAKE(vector, type, errValid, errCode) \
    ((ULONG64)(vector) | ((ULONG64)(type) << 8) | \
     ((ULONG64)(errValid ? 1 : 0) << 11) | (1ULL << 31) | ((ULONG64)(errCode) << 32))
//注: 注入#UD(fault)时不推进RIP——fault语义指向引发指令(裸机等价)

//NP_ENABLE (VMCB+0x090)位:
#define NP_ENABLE_NP            (1ULL << 0)   //嵌套分页启用位

//===== VMCB control area (+0x000-0x3FF, APM Table B-1) =====
#pragma warning(push)
#pragma warning(disable: 4201)
typedef struct _VMCB_CONTROL_AREA
{
	USHORT InterceptCrRead;          //+0x000
	USHORT InterceptCrWrite;         //+0x002
	USHORT InterceptDrRead;          //+0x004
	USHORT InterceptDrWrite;         //+0x006
	ULONG  InterceptException;       //+0x008 异常向量0-31按位
	ULONG  InterceptMisc1;           //+0x00C
	ULONG  InterceptMisc2;           //+0x010
	ULONG  InterceptMisc3;           //+0x014 INVLPGB族(A0-A6区)
	UCHAR  Reserved1[0x03C - 0x018]; //+0x018
	USHORT PauseFilterThreshold;     //+0x03C
	USHORT PauseFilterCount;         //+0x03E
	ULONG64 IopmBasePa;              //+0x040 IOPM物理基址(12KB, 4KB对齐)
	ULONG64 MsrpmBasePa;             //+0x048 MSRPM物理基址(8KB, 4KB对齐)
	ULONG64 TscOffset;               //+0x050 guest RDTSC/RDTSCP加法偏移
	ULONG  GuestAsid;                //+0x058 (0非法——一致性检查)
	UCHAR  TlbControl;               //+0x05C 0=不动 1/3/7=flush类(单字节)
	UCHAR  Reserved2[3];             //+0x05D
	ULONG64 VIntr;                   //+0x060 V_TPR/V_IRQ/VGIF/V_INTR_PRIO/V_INTR_MASKING位域
	ULONG64 InterruptShadow;         //+0x068 bit0=interrupt shadow
	ULONG64 ExitCode;                //+0x070
	ULONG64 ExitInfo1;               //+0x078
	ULONG64 ExitInfo2;               //+0x080
	ULONG64 ExitIntInfo;             //+0x088
	ULONG64 NpEnable;                //+0x090 bit0=NP
	ULONG64 AvicApicBar;             //+0x098
	ULONG64 GuestPaOfGhcb;           //+0x0A0
	ULONG64 EventInj;                //+0x0A8
	ULONG64 NCr3;                    //+0x0B0 嵌套页表基址(NPT)
	ULONG64 LbrVirtEnable;           //+0x0B8 bit0=LBR bit1=VMSAVEvirt bit2=IBS bit3=PMC
	ULONG  VmcbClean;                //+0x0C0 clean bits(0=全dirty=vmrun全字段
	                                 //从VMCB加载, 现行形态; 位定义见§15.15.3:
	                                 //b0=拦截向量 b1=IOPM/MSRPM b2=ASID b3=TPR
	                                 //b4=NP(NCR3+G_PAT) b5=CRx b6=DRx b7=DT
	                                 //b8=SEG b9=CR2 b10=LBR b11=AVIC b12=CET;
	                                 //TLB_CONTROL/EXITCODE族/EventInj/RFLAGS/
	                                 //RIP/RSP/RAX不缓存无对应位)
	ULONG  Reserved3;                //+0x0C4
	ULONG64 NRip;                    //+0x0C8 next-RIP(NRIPS特性; exit指令下一条)
	UCHAR  NumOfBytesFetched;        //+0x0D0 decode assists
	UCHAR  GuestInstructionBytes[15];//+0x0D1
	ULONG64 AvicBackingPage;         //+0x0E0
	ULONG64 Reserved4;               //+0x0E8
	ULONG64 AvicLogicalTable;        //+0x0F0
	ULONG64 AvicPhysicalTable;       //+0x0F8
	UCHAR  Reserved5[0x400 - 0x100]; //+0x100 (含SEV区, 保持全零)
} VMCB_CONTROL_AREA, *PVMCB_CONTROL_AREA;
#pragma warning(pop)

//===== VMCB state save area (+0x400起, APM Table B-2; 表内偏移) =====
typedef struct _VMCB_SEGMENT
{
	USHORT Selector;                 //+0x00
	USHORT Attrib;                   //+0x02 12位: bits55:52|47:40
	ULONG  Limit;                    //+0x04
	ULONG64 Base;                    //+0x08 (段槽=2+2+4+8恰16B无pad)
} VMCB_SEGMENT;                     //sizeof=0x10

typedef struct _VMCB_STATE_SAVE_AREA
{
	VMCB_SEGMENT Es;                 //+0x000
	VMCB_SEGMENT Cs;                 //+0x010
	VMCB_SEGMENT Ss;                 //+0x020
	VMCB_SEGMENT Ds;                 //+0x030
	VMCB_SEGMENT Fs;                 //+0x040
	VMCB_SEGMENT Gs;                 //+0x050
	VMCB_SEGMENT Gdtr;               //+0x060 (selector域RESERVED)
	VMCB_SEGMENT Ldtr;               //+0x070
	VMCB_SEGMENT Idtr;               //+0x080 (selector域RESERVED)
	VMCB_SEGMENT Tr;                 //+0x090
	UCHAR   Reserved1[0x0CB - 0x0A0];//+0x0A0
	UCHAR   Cpl;                     //+0x0CB
	ULONG   Reserved2;               //+0x0CC
	ULONG64 Efer;                    //+0x0D0
	UCHAR   Reserved3[0x148 - 0x0D8];//+0x0D8 (PERF_CTL/CTR区)
	ULONG64 Cr4;                     //+0x148
	ULONG64 Cr3;                     //+0x150
	ULONG64 Cr0;                     //+0x158
	ULONG64 Dr7;                     //+0x160
	ULONG64 Dr6;                     //+0x168
	ULONG64 Rflags;                  //+0x170
	ULONG64 Rip;                     //+0x178
	UCHAR   Reserved4[0x1D8 - 0x180];//+0x180
	ULONG64 Rsp;                     //+0x1D8
	UCHAR   Reserved5[0x1F8 - 0x1E0];//+0x1E0 (S_CET/SSP/ISST_ADDR)
	ULONG64 Rax;                     //+0x1F8
	ULONG64 Star;                    //+0x200
	ULONG64 Lstar;                   //+0x208
	ULONG64 Cstar;                   //+0x210
	ULONG64 Sfmask;                  //+0x218
	ULONG64 KernelGsBase;            //+0x220
	ULONG64 SysenterCs;              //+0x228
	ULONG64 SysenterEsp;             //+0x230
	ULONG64 SysenterEip;             //+0x238
	ULONG64 Cr2;                     //+0x240
	UCHAR   Reserved6[0x268 - 0x248];//+0x248
	ULONG64 GPat;                    //+0x268 guest PAT(NP启用时用)
	ULONG64 DbgCtl;                  //+0x270 LBR虚拟化时用
	ULONG64 BrFrom;                  //+0x278
	ULONG64 BrTo;                    //+0x280
	ULONG64 LastExcFrom;             //+0x288
	ULONG64 LastExcTo;               //+0x290
	UCHAR   Reserved7[0x400 - 0x298];//+0x298
} VMCB_STATE_SAVE_AREA, *PVMCB_STATE_SAVE_AREA;

//VMCB整体: 4KB对齐单页。Appendix B: control(0x000)+state(0x400)
typedef struct _VMCB
{
	VMCB_CONTROL_AREA Control;            //+0x000
	VMCB_STATE_SAVE_AREA State;           //+0x400
} VMCB, *PVMCB;

//save area字段在VMCB内的绝对偏移(asm侧硬编码使用; 与上文结构互为契约):
#define VMCB_OFF_RIP        0x578    //0x400+0x178
#define VMCB_OFF_RSP        0x5D8    //0x400+0x1D8
#define VMCB_OFF_RAX        0x5F8    //0x400+0x1F8
#define VMCB_OFF_RFLAGS     0x570    //0x400+0x170

//VMSAVE/VMLOAD指令处理的状态集(APM §15.5.2, 与VMRUN保存集互补):
//  FS/GS/TR/LDTR(含隐藏态)+KernelGsBase+STAR/LSTAR/CSTAR/SFMASK+SYSENTER_CS/ESP/EIP
//  ——不含RIP/RSP/RAX/CR(vmsave不覆盖这些字段)
//VMRUN host保存集(§15.5.1): CS.SEL/NEXT_RIP/RFLAGS/RAX/SS.SEL/RSP/CR0/CR3/CR4/EFER/
//  IDTR/GDTR/ES.SEL/DS.SEL——不含FS/GS基址与SYSCALL MSR(#VMEXIT后保持guest值;
//  本框架host与guest同为Windows, exit handler可直接执行C代码)

#ifdef __cplusplus
}
#endif

#endif // VMCB_H
