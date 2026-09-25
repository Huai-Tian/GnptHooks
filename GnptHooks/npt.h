#pragma once
#ifndef NPT_H
#define NPT_H
#include"common.h"

//嵌套页表(NPT)双视图恒等映射: gpa->spa 1:1, AMD APM §15.25。
//  Primary  = 常态视图: 全恒等2MB大页; hooked页拆4KB后置NX
//             (数据读写正常, 取指NPF触发切换)
//  Secondary= hook视图: 全恒等RWX(驻留视图: 取指detour/回调/
//             CallOriginal/后续执行全速零exit); hooked页改指
//             CodePage。TRANSPARENT下核取指fault切S后**长期驻留**,
//             detour=零切换成本(M4.12)
//两树全核共享(单实例), 每核VMCB按当前视图选择NCR3/ASID。

#ifdef __cplusplus
extern "C" {
#endif

//页表项位(标准x86-64格式, NPT复用)
#define NPT_PTE_P               (1ULL << 0)    //Present
#define NPT_PTE_RW              (1ULL << 1)    //ReadWrite
#define NPT_PTE_US              (1ULL << 2)    //User/Supervisor
#define NPT_PTE_A               (1ULL << 5)    //Accessed(预置, 免硬件回写)
#define NPT_PTE_D               (1ULL << 6)    //Dirty(预置)
#define NPT_PTE_PS              (1ULL << 7)    //PageSize(PD级=2MB大页)
#define NPT_PTE_NX              (1ULL << 63)   //不可执行(需host EFER.NXE=1)
#define NPT_PTE_FLAGS_LEAF2MB   (NPT_PTE_P | NPT_PTE_RW | NPT_PTE_US | \
                                 NPT_PTE_A | NPT_PTE_D | NPT_PTE_PS)
#define NPT_PTE_FLAGS_INTER     (NPT_PTE_P | NPT_PTE_RW | NPT_PTE_US)  //中间级
//4KB恒等leaf(全开放): 可读可写可执行
#define NPT_PTE_FLAGS_LEAF4K_RWX (NPT_PTE_P | NPT_PTE_RW | NPT_PTE_US | \
                                  NPT_PTE_A | NPT_PTE_D)
//Primary的hooked页: 原页可读可写不可执行(取指触发NPF)
#define NPT_PTE_FLAGS_HOOKP      (NPT_PTE_FLAGS_LEAF4K_RWX | NPT_PTE_NX)
//Secondary的hooked页: CodePage只读可执行(写触发NPF回Primary转发)
#define NPT_PTE_FLAGS_HOOKS      (NPT_PTE_P | NPT_PTE_US | \
                                   NPT_PTE_A | NPT_PTE_D)
//TRANSPARENT的hooked页(Secondary): EXEC常驻=CodePage全权(P|RW)。
//S视图驻留形态: detour零切换; 读者(同核)读hooked页=见CodePage
//(含跳转码)——NPT无read-deny位, **读透明如实降级为未实现**,
//真读透明留M5 per-CPU NPT+ASID免flush后的P=0方案(M4.12)
#define NPT_PTE_FLAGS_HOOKT_EXEC  NPT_PTE_FLAGS_LEAF4K_RWX

//视图标识与固定ASID配对(ASID=0保留host, §15.25.1)
#define GNPT_VIEW_PRIMARY      0
#define GNPT_VIEW_SECONDARY    1
#define NPT_ASID_PRIMARY       1
#define NPT_ASID_SECONDARY     2

//构建双树恒等映射(全核共享): Ncr3Out[2]=Primary/Secondary顶层PA。
//成功TRUE; 失败FALSE(内部已自清理)。CoverOut/PagesOut=诊断
BOOLEAN SvmBuildDualNpt(PULONG64 Ncr3Out, PULONG64 CoverOut, PULONG PagesOut);

//释放两树全部页表页(幂等; 卸载路径, 须全核裸机后调用)
VOID SvmFreeNpt(VOID);

//诊断: 覆盖字节数/页表页数(日志用)
ULONG64 SvmNptCoverageBytes(VOID);
ULONG SvmNptPageCount(VOID);

//当前视图的顶层NCr3
ULONG64 SvmNptViewNcr3(ULONG View);

//确保gpa所在的2MB区域已拆为4KB条目, 返回该gpa的PTE槽地址
//(NULL=gpa未覆盖/资源耗尽)。拆分后未修改的条目=恒等可执行。
PULONG64 SvmNptEnsureSplit(ULONG View, ULONG64 Gpa);

//把视图内gpa的4KB条目写为 Pa|Flags(EnsureSplit+置位)
VOID SvmNptSetPte(ULONG View, ULONG64 Gpa, ULONG64 Pa, ULONG64 Flags);

//把视图内gpa的4KB条目恢复恒等(P|RW|US|A|D, 指回原物理页)
VOID SvmNptRestoreIdentity(ULONG View, ULONG64 Gpa);

#ifdef __cplusplus
}
#endif

#endif // NPT_H
