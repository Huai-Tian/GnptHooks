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
//  5. 目标选型(PatchGuard): 普通模式驻留视图可读——外部读者
//     (PatchGuard/内核扫描器)读到的是CodePage跳转码, 对SSDT/
//     系统服务等PG覆盖目标=0x109蓝屏(PG检查周期随机, 短浸泡
//     不触发不代表安全)。高频且非PG覆盖的普通内核函数用Flags=0;
//     **PG覆盖目标(含热靶)用HOOK_TRANSPARENT**——DR机件下原页
//     恒等不动, 外部读恒=原始字节(结构性读透明, 零exit),
//     PG覆盖×热页×长驻全兼容。AMD NPT无exec-only权限位=普通
//     模式无免费读透明(架构边界, 非可修缺陷)
//  6. TRANSPARENT容量与边界(DR机件): 每核≤4个(DR0-3硬件数,
//     超出Install拒绝fail-loud); 断点=线性地址标记(同页多目标
//     各自独立=页粒度限制不存在); 每次目标函数调用恰1 exit
//     (热页无惩罚); **探测期让位(fail-open)**——guest调试活动
//     (单步TF/自身断点/GD)期间被探测的hook对该次调用走原函数
//     (裸机等价优先: 调试子系统必须"正常工作", 否则=可检出
//     指纹), 监控回调在探测窗口内可能丢事件; guest占用的DR槽
//     所在核上hook同样让位(guest释放后自动恢复)。DR0-3对guest
//     可见面=影子(其断点真实可触发+回读一致, DR7回读恒含
//     bit10 RA1=裸机形态)
//  6b. DR槽选址纪律(检测面): **纯监控优先**——回调透传
//     (GnptCallOriginal转发)或仅计数统计的hook用TRANSPARENT
//     安全; **拦截型(改参/改返回值/阻断调用)慎用**——DR断点
//     作用域=线性地址, 检测方对目标函数做**重映射别名调用**
//     (映射同一物理页的其他VA调用函数=绕过DR断点)可差分出
//     "某VA被hook而别名未hook"=改道式hook的返回值不一致指纹
//     (普通/NX-FENCE为物理页作用域, 对别名调用同样生效=结构性
//     免疫)。透传监控无返回值差分面=DR线性作用域不可探测。
//     拦截需求×PG覆盖目标=权衡接受残余或改普通模式冷靶
//  7. 模式并存: TRANSPARENT(DR线性断点)与普通模式(NPT视图)
//     机制正交, 可同机并存(不同目标); NX-FENCE与TRANSPARENT同为
//     PG安全族可并存; **fence与普通模式并存时, 普通hook驻留HOOKS
//     的核上fence不触发**(fence页HOOKS恒等RWX无fault=miss窗口,
//     退出驻留即恢复)——混用场景fence命中率按普通hook驻留时长
//     折损, 见纪律9。唯一余约束=普通模式同页多hook的NPF首匹配
//     边界(引擎按TargetPa首匹配, 同页第二个普通hook永不可达)。
//     单写者契约见纪律8
//  8. 单写者契约: Install/Remove/RemoveAll/Enumerate内部无锁
//     (条目分配/隐蔽登记/树游标均为单写者设计), 调用方须自行
//     串行化(专用工作线程或互斥); 并发调用=条目与登记表竞态
//  9. NX-FENCE容量位边界(HOOK_NXFENCE): PG安全零工件(两视图皆
//     原始字节)+无限容量(仅条目数限)。稳态2 exit/调用(入口NPF
//     改道+rearm vmmcall)。边界: ①同页唯一且不得与任何已有hook
//     同页(页级NX为共享资产, Install fail-loud拒绝); ②目标页
//     邻函数执行触发页级NPF→该核驻留HOOKS+置旗, 下个任意exit
//     信标回P(fence重武装; miss窗口=exit间隔, 加载态µs级/空闲
//     态秒级)——热页邻函数=exit流量放大, fence选**冷页/页隔离**
//     目标(驱动本地目标用#pragma code_seg专用节=结构性隔离);
//     ③detour回调内直调其他fence目标不触发(fail-open原函数
//     直跑); ④回调必须正常返回(stub尾rearm依赖返回路径);
//     ⑤回调期间线程跨核迁移=入口核远程自愈(dispatch检测迁移→
//     清入口核在途旗+置驻留旗→该核下个任意exit信标回P); 入口
//     trap→stub首指令间的迁移窗口不在覆盖内(该核fence miss
//     直至外部写/后续迁移自愈, 概率~ns级窗口)
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
//最大同时驻留hook数(条目静态数组; 发布后不可变=分发器无锁读。
//NPF引擎按TargetPa线性首匹配, 超此量级需哈希索引=另行演进)
#define GNPT_MAX_HOOKS       64

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
	                          //(DR0-3执行断点入口陷阱+原页恒等,
	                          //外部读=原始字节, PG覆盖/热靶可用;
	                          //每核≤4个, 见使用纪律6)
	                          //位1=HOOK_NXFENCE: 容量位(NX-Fence,
	                          //见使用纪律9)
} GNPT_HOOK, *PGNPT_HOOK;

//hook模式标志(Flags位)
#define HOOK_TRANSPARENT        0x1   //读透明(DR机件): DRn=目标入口
                                       //线性地址执行断点(仅执行1B),
                                       //入口取指#DB fault→root改道
                                       //RIP=跳板槽(等价补丁跳转);
                                       //原页恒等原始字节=读/写透明
                                       //结构性成立; 函数体自原页
                                       //执行零exit
#define HOOK_NXFENCE            0x2   //容量位(NX-Fence机件): 目标页
                                       //P视图RW|NX(取指NPF→root改道
                                       //RIP=跳板槽+切HOOKS恒等RWX),
                                       //回调返回前rearm vmmcall回P。
                                       //零工件(无CodePage无补丁字节,
                                       //两视图皆原始字节=PG安全),
                                       //无限容量(同页唯一), 稳态
                                       //2 exit/调用

//安装hook(PASSIVE_LEVEL, 引擎运行中): TRANSPARENT=DR槽分配+全核
//武装广播; NX-FENCE=P视图页级NX布防+全核TLB同步(无CodePage);
//普通模式=CodePage构建+两视图布防+CodePage工件隐蔽
//(身份PTE两视图零页——guest物理扫描不可见)+全核TLB同步
NTSTATUS GnptHookInstall(const GNPT_HOOK* Hook);

//移除hook(PASSIVE_LEVEL): TRANSPARENT=全核DR解除广播; 普通模式=
//布防PTE恒等还原+全核TLB同步→hook立即失效; 随后root代写还原
//CodePage补丁字节+解除工件隐蔽(PFN复用安全)。在途回调安全完成
//(槽/条目延迟到卸载释放)
NTSTATUS GnptHookRemove(PVOID Target);

//枚举live hook(Buffer=NULL时*InOutCount返回数量; 容量不足=
//STATUS_BUFFER_TOO_SMALL并回填所需数量)
NTSTATUS GnptHookEnumerate(GNPT_HOOK* Buffer, ULONG* InOutCount);

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

//DR-TRANSPARENT机件(svm.c的0x41 case与0x20-0x3F(MOV DR拦截)入口)
//  DbExit: #DB的DR6位路由+guest忠实投递——guest断点/TF陷阱=
//  裸机等价投递(含影子DR6的B/BS位同步); 我方断点=改道跳板槽
//  +清位(返回TRUE); 探测期(guest TF置位/断点同场)=让位该次
//  调用(消费我方位+置RFLAGS.RF防重执行再触发断点=exit死循环;
//  RF只压指令断点恰一指令, 不影响guest TF陷阱下exit投递)。
//  可在单步机件收尾后调用(同场合并事件)
//  MovExit: MOV DR仿真(guest优先租用制)——读=影子(DR7回读含
//  bit10 RA1); 写DR0-3=仅影子(硬件装填延迟到DR7启用); 写DR7
//  =合并重算(guest槽装填+我方槽自动重武装); GD=投递#DB(BD);
//  DR4/5/8-15=注入#UD。恒返回TRUE
BOOLEAN GnptHookDrBpDbExit(struct _VMCB* Vmcb, ULONG Cpu);
BOOLEAN GnptHookDrMovExit(struct _VMCB* Vmcb, ULONG Cpu,
	PGUEST_REGS Regs, ULONG ExitCode);
//每核武装/解除(svm.c的DRSET case调用): guest占用槽=让位,
//否则__writedr+VMCB.Dr7合并置位(仅执行1B)
VOID GnptHookDrArmCore(struct _VMCB* Vmcb, ULONG Cpu, ULONG Slot,
	BOOLEAN On, ULONG64 Addr);
//每核DR影子初始化(svm.c的VMCB init DR卫生段调用): DR7影子
//=裸机恒读值0x400(bit10 RA1)——guest读DR7零差异, 写读幂等
VOID GnptHookDrShadowInit(ULONG Cpu);

//NX-FENCE机件(svm.c调用)
//  NxRearm: NXREARM vmmcall处置(stub尾自发)——在途detour旗清
//  +视图回P(fence重武装); 旗不在=移除后补发/跨核迁移(入口核
//  由dispatch远程自愈)等竞态形态, 静默(调用方推进RIP即可)
//  NxBeacon: exit外壳统一信标(先于CPUID短路)——fence页邻函数
//  驻留旗在且无在途detour→回P重武装; 任意exit皆信标(CPUID/
//  MSR等常规流量秒级必达)=miss窗口有界; 在途detour护旗(其中
//  段exit不得翻视图, 函数体自HOOKS执行)
VOID GnptHookNxRearm(struct _VMCB* Vmcb, ULONG Cpu);
VOID GnptHookNxBeacon(struct _VMCB* Vmcb, ULONG Cpu);

#endif // HOOK_H
