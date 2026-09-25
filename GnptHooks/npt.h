#pragma once
#ifndef NPT_H
#define NPT_H
#include"common.h"

//嵌套页表(NPT)多视图恒等映射: gpa->spa 1:1, AMD APM §15.25。
//四棵**静态共享树**(运行时零PTE写零flush: 各视图独立成树,
//ASID配对切换; §15.16换ASID=官方免flush失效法):
//  P    (ASID1)=常态: 全恒等2MB大页; hooked页拆4KB置NX
//  HOOKS(ASID2)=常规hook驻留: 全恒等RWX; hooked页=CodePage只读
//  HIDE (ASID3)=TRANSPARENT潜伏驻留: 全恒等RWX; hooked页P=0
//             (读/写fault→切P读原始字节=抗PG读透明)
//  EXEC (ASID4)=TRANSPARENT执行窗口: 全恒等RWX; hooked页=
//             CodePage全权(取指进detour, TF收尾切回HIDE)
//舞步(P/HIDE取指fault→EXEC+TF→1指令→#DB→HIDE)=纯ASID切换,
//每指令2exit零flush; 单核单线程=PG不可能与窗口并发, 他核
//恒潜伏→破洞=0

#ifdef __cplusplus
extern "C" {
#endif

//页表项位(标准x86-64格式, NPT复用)
#define NPT_PTE_P               (1ULL << 0)    //Present
#define NPT_PTE_RW              (1ULL << 1)    //ReadWrite
#define NPT_PTE_US              (1ULL << 2)    //User/Supervisor
#define NPT_PTE_A               (1ULL << 5)    //Accessed(预置, 免硬件回写)
#define NPT_PTE_D               (1ULL << 6)     //Dirty(预置)
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
//HOOKS的hooked页: CodePage只读可执行(写NPF→回Primary转发)
#define NPT_PTE_FLAGS_HOOKS      (NPT_PTE_P | NPT_PTE_US | \
                                   NPT_PTE_A | NPT_PTE_D)
//TRANSPARENT两态(静态化: 布防一次写死, 运行时只切树)
#define NPT_PTE_FLAGS_HOOKT_HIDE  0ULL                            //HIDE树: P=0
#define NPT_PTE_FLAGS_HOOKT_EXEC  NPT_PTE_FLAGS_LEAF4K_RWX       //EXEC树: CodePage全权

//视图标识与固定ASID配对(ASID=0保留host, §15.25.1)
#define GNPT_VIEW_PRIMARY      0
#define GNPT_VIEW_SECONDARY    1     //HOOKS(常规hook驻留)
#define GNPT_VIEW_HIDE         2     //TRANSPARENT潜伏驻留
#define GNPT_VIEW_EXEC         3     //TRANSPARENT执行窗口
#define GNPT_VIEW_COUNT        4
#define NPT_ASID_PRIMARY       1
#define NPT_ASID_SECONDARY     2
#define NPT_ASID_HIDE          3
#define NPT_ASID_EXEC          4

//构建四棵静态树(全核共享): Ncr3Out[GNPT_VIEW_COUNT]=各视图顶层PA。
//成功TRUE; 失败FALSE(已自清理)
BOOLEAN SvmBuildNptViews(PULONG64 Ncr3Out,
	PULONG64 CoverOut, PULONG PagesOut);

//释放全部树页表页(幂等; 卸载路径, 须全核裸机后调用)
VOID SvmFreeNpt(VOID);

//诊断: 覆盖字节数/页表页数(日志用)
ULONG64 SvmNptCoverageBytes(VOID);
ULONG SvmNptPageCount(VOID);

//视图顶层NCr3
ULONG64 SvmNptViewNcr3(ULONG View);

//把视图内gpa的4KB条目写为 Pa|Flags(现场拆分+置位)。
//仅Install/Remove/临时RW调用——热路径零PTE写
VOID SvmNptSetPte(ULONG View, ULONG64 Gpa, ULONG64 Pa, ULONG64 Flags);

//把视图内gpa的4KB条目恢复恒等(P|RW|US|A|D, 指回原物理页)
VOID SvmNptRestoreIdentity(ULONG View, ULONG64 Gpa);

#ifdef __cplusplus
}
#endif

#endif // NPT_H
