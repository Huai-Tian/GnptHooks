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

//==== NPT自我隐蔽 ====
//语义: 把全部框架私有物理页(四棵NPT树页/VMCB/HSAVE/IOPM/MSRPM/
//VMM栈, 每核)在四视图统一改译共享零页(P=1,RW=0,X=0)——guest
//物理内存扫描只见零; root与NPT硬件walker按HPA直访页表页不受
//影响(§15.25: 硬件walker物理寻址; vmrun加载VMCB/位图均按
//VMCB内物理基址)。
//时序契约: 须在全部核资源分配后+首核launch前调用(裸机root态
//直访物理=写隐蔽页自免疫; launch后guest态写NPT页须走vmmcall
//root原语)。
//零页翻译flags=P|US|A(RW=0,X=0): guest读=静默零(理想隐蔽);
//写/执行该gpa→NPF→'O'兜底恢复该页(自愈优先)。
BOOLEAN SvmNptConcealAll(VOID);    //登记+四树改译零页(PASSIVE)
//诊断: 零页PA(0=未隐蔽)/登记页数/'O'恢复计数/登记页访问
ULONG64 SvmNptHideZeroPa(VOID);
ULONG SvmNptConcealCount(VOID);
ULONG SvmNptConcealHits(VOID);
ULONG64 SvmNptConcealPa(ULONG Index);  //登记页gpa(卸载恢复迭代)
//'O'兜底(exit handler): faulting页已隐蔽→四树恢复恒等+留痕。
//返回TRUE=已处置(重执行=访问自愈)。须在NPF分发的最前(先于
//hook引擎: 隐蔽页gpa不是hook目标, 但泄漏态自愈分支会误切)
BOOLEAN SvmNptConcealFaultFix(ULONG64 Gpa);
//只读查PTE(不拆分; 'O'兜底判定用): 返回视图内gpa的4KB条目
//现值(未拆分区返回2MB大页条目值; 非法gpa返回0)
ULONG64 SvmNptPeekPte(ULONG View, ULONG64 Gpa);
//==== 运行期工件隐蔽(Install冷路径, 须root上下文=vmcall进) ====
//登记一页gpa并入既有隐蔽体系: 身份PTE四视图改译零页+登记表
//挂靠。含级联收尾——改译拆分副产物页表页(运行期树修改新增的
//arena槽页)一并登记改译(登记游标排水), 迭代到不动点。
//全有全无: 资源不足(登记表满/页表页数组满/arena块边界/超512GB
//覆盖/级联超轮)→FALSE且零PTE改译(拆分残留无害, 游标自愈);
//成功→TRUE。幂等(重复登记=仅排水, 无副作用)
BOOLEAN SvmNptConcealPageRuntime(ULONG64 Pa);
//登记表移除一页(交换末尾; 纯.data操作, 任意上下文)。PTE侧
//还原走既有NPTRES(0xF); 'O'兜底按PTE现值判定, 不依赖此表
VOID SvmNptConcealRemove(ULONG64 Pa);
//root上下文标记(exit handler进出成对调用): 置位期间
//SvmNptAllocPage拒绝触发新arena块分配(Mm连续分配非IF=0/任意
//IRQL安全), 块边界=返回NULL由调用方fail-loud; 槽切取不受限
VOID SvmNptRootCtxMark(BOOLEAN InRoot);

#ifdef __cplusplus
}
#endif

#endif // NPT_H
