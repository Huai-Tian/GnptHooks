#pragma once
#ifndef SVM_H
#define SVM_H
#include"common.h"

//SVM常量定义。全部经AMD APM(24593/24594 Rev 3.45/3.38)原文核对:
//  - exit codes: Appendix C Table C-1
//  - VM_CR/VM_HSAVE_PA: §15.30
//  - CPUID Fn8000_000A_EDX: Vol3 Appendix E.4.9
//  - EFER.SVME=bit12: Vol2 EFER位表
//注: 异常exit code=0x40+向量号(40h-5Fh连续映射)

#ifdef __cplusplus
extern "C" {
#endif

//===== SVM相关MSR (APM §15.30) =====
#define MSR_VM_CR               0xC0010114  //DPD(b0) R_INIT(b1) DIS_A20M(b2) LOCK(b3) SVMDIS(b4)
#define MSR_IGNNE               0xC0010115
#define MSR_SMM_CTL             0xC0010116
#define MSR_VM_HSAVE_PA         0xC0010117  //host state保存区物理地址(4KB对齐, 低12位非0=#GP)
#define MSR_TSC_RATIO           0xC0000104  //TSC比率(乘法缩放, 与VMCB TSC_OFFSET加法补偿互补)

#define VM_CR_DPD               (1ULL << 0)
#define VM_CR_R_INIT            (1ULL << 1)  //置1: 非拦截INIT转#SX异常
#define VM_CR_DIS_A20M          (1ULL << 2)
#define VM_CR_LOCK              (1ULL << 3)  //置1后LOCK/SVMDIS写入被忽略, 仅SVM_KEY可解
#define VM_CR_SVMDIS            (1ULL << 4)  //置1: EFER写入把SVME当MBZ(SVM被禁)

//EFER (0xC0000080)
#define EFER_SVME               (1ULL << 12)
#ifndef MSR_EFER
#define MSR_EFER                0xC0000080  //EFER寄存器号(SVME=bit12)
#endif
#ifndef MSR_PAT
#define MSR_PAT                 0x00000277  //IA32_PAT(VMCB G_PAT源)
#endif

//===== CPUID =====
//Fn8000_0001_ECX bit2=SVM支持
#define CPUID_SVM_ECX_BIT       2
//Fn8000_000A: EAX= SVM revision(bits7:0); EBX= NASID(可用ASID数)
//             ECX bit5=EnhancedTlbi bit6=x2AVIC_EXT
//             EDX=特性位(下表)
#define CPUID_FN_SVM            0x8000000A
#define SVM_FEAT_NP             (1ULL << 0)   //嵌套分页
#define SVM_FEAT_LBRVIRT        (1ULL << 1)
#define SVM_FEAT_SVML           (1ULL << 2)   //SVM lock支持
#define SVM_FEAT_NRIPS          (1ULL << 3)   //exit保存next-RIP
#define SVM_FEAT_TSCRATEMSR     (1ULL << 4)
#define SVM_FEAT_VMCBCLEAN      (1ULL << 5)   //VMCB clean bits
#define SVM_FEAT_FLUSHBYASID    (1ULL << 6)
#define SVM_FEAT_DECODEASSIST   (1ULL << 7)   //exit附带指令字节
#define SVM_FEAT_PMCVIRT        (1ULL << 8)
#define SVM_FEAT_PAUSEFILTER    (1ULL << 10)
#define SVM_FEAT_PAUSEFILTHR    (1ULL << 12)
#define SVM_FEAT_AVIC           (1ULL << 13)
#define SVM_FEAT_VMSAVEVIRT     (1ULL << 15)
#define SVM_FEAT_VGIF           (1ULL << 16)
#define SVM_FEAT_GMET           (1ULL << 17)
#define SVM_FEAT_x2AVIC         (1ULL << 18)
#define SVM_FEAT_VNMI           (1ULL << 25)

//===== exit codes (APM Appendix C Table C-1) =====
//CR/DR读写: 0x00-0x0F=CR[0-15]读 0x10-0x1F=CR写 0x20-0x2F=DR读 0x30-0x3F=DR写
//异常: 0x40-0x5F=EXCP[0-31](exit code=0x40+向量号, 连续)
#define SVM_EXIT_EXCP_BASE      0x40
#define SVM_EXIT_EXCP_DE        0x40
#define SVM_EXIT_EXCP_DB        0x41
#define SVM_EXIT_EXCP_NMI       0x42
#define SVM_EXIT_EXCP_BP        0x43
#define SVM_EXIT_EXCP_UD        0x46
#define SVM_EXIT_EXCP_DF        0x48
#define SVM_EXIT_EXCP_TS        0x4A
#define SVM_EXIT_EXCP_NP        0x4B
#define SVM_EXIT_EXCP_SS        0x4C
#define SVM_EXIT_EXCP_GP        0x4D
#define SVM_EXIT_EXCP_PF        0x4E
#define SVM_EXIT_EXCP_MC        0x52
#define SVM_EXIT_EXCP_SX        0x5E
//事件与指令
#define SVM_EXIT_INTR           0x60   //物理可屏蔽中断
#define SVM_EXIT_NMI            0x61
#define SVM_EXIT_SMI            0x62
#define SVM_EXIT_INIT           0x63
#define SVM_EXIT_VINTR          0x64   //虚拟中断
#define SVM_EXIT_CR0_SEL_WRITE  0x65
#define SVM_EXIT_IDTR_READ      0x66
#define SVM_EXIT_GDTR_READ      0x67
#define SVM_EXIT_LDTR_READ      0x68
#define SVM_EXIT_TR_READ        0x69
#define SVM_EXIT_IDTR_WRITE     0x6A
#define SVM_EXIT_GDTR_WRITE     0x6B
#define SVM_EXIT_LDTR_WRITE     0x6C
#define SVM_EXIT_TR_WRITE       0x6D
#define SVM_EXIT_RDTSC          0x6E
#define SVM_EXIT_RDPMC          0x6F
#define SVM_EXIT_PUSHF          0x70
#define SVM_EXIT_POPF           0x71
#define SVM_EXIT_CPUID          0x72
#define SVM_EXIT_RSM            0x73
#define SVM_EXIT_IRET           0x74
#define SVM_EXIT_SWINT          0x75
#define SVM_EXIT_INVD           0x76
#define SVM_EXIT_PAUSE          0x77
#define SVM_EXIT_HLT            0x78
#define SVM_EXIT_INVLPG         0x79
#define SVM_EXIT_INVLPGA        0x7A
#define SVM_EXIT_IOIO           0x7B
#define SVM_EXIT_MSR            0x7C
#define SVM_EXIT_TASK_SWITCH    0x7D
#define SVM_EXIT_FERR_FREEZE    0x7E
#define SVM_EXIT_SHUTDOWN       0x7F
#define SVM_EXIT_VMRUN          0x80
#define SVM_EXIT_VMMCALL        0x81
#define SVM_EXIT_VMLOAD         0x82
#define SVM_EXIT_VMSAVE         0x83
#define SVM_EXIT_STGI           0x84
#define SVM_EXIT_CLGI           0x85
#define SVM_EXIT_SKINIT         0x86
#define SVM_EXIT_RDTSCP         0x87
#define SVM_EXIT_ICEBP          0x88
#define SVM_EXIT_WBINVD         0x89
#define SVM_EXIT_MONITOR        0x8A
#define SVM_EXIT_MWAIT          0x8B
#define SVM_EXIT_MWAIT_COND     0x8C
#define SVM_EXIT_XSETBV         0x8D
#define SVM_EXIT_RDPRU          0x8E
#define SVM_EXIT_EFER_WTRAP     0x8F
#define SVM_EXIT_CR0_WTRAP      0x90
#define SVM_EXIT_CR3_WTRAP      0x93
#define SVM_EXIT_CR4_WTRAP      0x94
#define SVM_EXIT_INVLPGB        0xA0
#define SVM_EXIT_INVLPGB_ILL    0xA1
#define SVM_EXIT_INVPCID        0xA2
#define SVM_EXIT_MCOMMIT        0xA3
#define SVM_EXIT_TLBSYNC        0xA4
#define SVM_EXIT_BUSLOCK        0xA5
#define SVM_EXIT_IDLE_HLT       0xA6
//0x400区
#define SVM_EXIT_NPF            0x400  //嵌套页故障(EXITINFO1=错误码, EXITINFO2=gpa)
#define SVM_EXIT_AVIC_IPI       0x401
#define SVM_EXIT_AVIC_NOACCEL   0x402
#define SVM_EXIT_VMGEXIT        0x403
#define SVM_EXIT_PML_FULL       0x407
//负值(VMEXIT_INVALID=-1等): #VMEXIT前VMCB非法——asm出口检查EXITCODE
//最高位(全1区)判定

//===== 每核vCPU观测态 =====
typedef struct _GNPT_VCPU
{
	volatile LONG bInGuest;         //1=本核guest运行中(vmrun接管成功)
	volatile LONG bLaunchFailed;    //1=vmrun失败(本核保持裸机)
	volatile LONG bSvmOn;           //1=EFER.SVME已置位(去虚拟化路径清零)
	volatile LONG PendingIntrCount; //积压中断数(中断直通记账)
} GNPT_VCPU, *PGNPT_VCPU;

//观测态载体=g_svmVcpu[c].base(单组64核上限, 多组系统不覆盖)

//===== 每核SVM引擎态 =====
//asm世界开关(svm-asm.asm)与exit handler以此结构为契约;
//VCPU指针经VMM栈底传递(栈布局契约见svm-asm.asm头注释)
typedef struct _GNPT_VCPU_SVM
{
	GNPT_VCPU base;                //+0x00 观测态(16B)
	PVOID VmcbVa;                  //+0x10
	ULONG64 VmcbPa;                //+0x18
	PVOID HsaveVa;                 //+0x20 (VMRUN host保存区, 软件勿读内容)
	ULONG64 HsavePa;               //+0x28
	PVOID IopmVa;                  //+0x30 (12KB, 全0=不拦任何端口)
	ULONG64 IopmPa;                //+0x38
	PVOID MsrpmVa;                 //+0x40 (8KB, 全0=不拦任何MSR)
	ULONG64 MsrpmPa;               //+0x48
	PVOID VmmStack;                //+0x50 (2页16KB; 栈底8字节区={VCPU指针, VmcbPa})
	PVOID VmmStackTop;             //+0x58 = VmmStack+16KB
	HANDLE ThreadHandle;           //+0x60 发起线程(每核一个, 钉核)
	PVOID ThreadObj;               //+0x68
	CHAR CpuIndex;                 //+0x70
	CHAR Pad[7];
} GNPT_VCPU_SVM, *PGNPT_VCPU_SVM;

extern GNPT_VCPU_SVM g_svmVcpu[64];
extern ULONG64 g_svmFeatBits;       //Fn8000_000A_EDX快照(降级决策)
extern KEVENT g_svmShutdownEvent;   //卸载: 唤醒全部发起线程

//段快照helper(svm-asm.asm): x64内核CS/SS/DS/ES基址恒0(64位规范)
USHORT CmGetSegCs(VOID);
USHORT CmGetSegSs(VOID);
USHORT CmGetSegDs(VOID);
USHORT CmGetSegEs(VOID);
ULONG CmGetSegLimitCs(VOID);    //lsl字节粒度段限
ULONG CmGetSegLimitSs(VOID);
ULONG CmGetSegLimitDs(VOID);
ULONG CmGetSegLimitEs(VOID);
ULONG64 CmGetGdtBase(VOID);     //sgdt
ULONG CmGetGdtLimit(VOID);
ULONG64 CmGetIdtBase(VOID);     //sidt
ULONG CmGetIdtLimit(VOID);
ULONG64 CmGetRflags(VOID);     //pushfq全宽读取(VMCB.Rflags源; MSVC无x64对应intrinsics)
//段attrib(12位=描述符55:52|47:40拼接, APM §15.5.1)由C侧直读GDT描述符
//(svm.c: SvmGetSegAttrib)

//世界开关(svm-asm.asm): 见文件头注释
VOID CmSvmEnter(PGNPT_VCPU_SVM Vcpu);   //发起接管; 返回=本核已guest化
ULONG SvmExitHandler(PGNPT_VCPU_SVM Vcpu, PGUEST_REGS Regs);
//返回0=重入guest; 非0=STOP(卸载: 桥值已填GUEST_REGS)

//内部vmmcall功能码(当前已实现):
#define GNPT_VMCALL_STOP  1    //卸载: 发起线程自guest内请求本核去虚拟化
#define GNPT_VMCALL_KEEP  3    //KEEP放行(落地探针第二段)
#define GNPT_VMCALL_NPTSYNC 4  //NPT改动全核TLB同步(exit handler置TLB_CONTROL=3)


//SVM可用性三态判定(APM §15.4):
//  0=SVM可用  1=CPU不支持  2=BIOS禁用且不可解锁(SVMDIS=1且SVML=0)
//  3=BIOS禁用但有钥匙可能(SVMDIS=1且SVML=1)
ULONG CommCheckSvm(VOID);

//生命周期: 每核发起线程+vmrun世界开关+探针+干净去虚拟化
NTSTATUS SvmStartAllCpus(PDRIVER_OBJECT DriverObject);
BOOLEAN SvmShutdownAllCpus(VOID);   //TRUE=全核已裸机; FALSE=拒绝(park)引擎仍在位

#ifdef __cplusplus
}
#endif

#endif // SVM_H
