#pragma once
#ifndef COMMON_H
#define COMMON_H
#include<ntifs.h>
#include<ntddk.h>
#include<intrin.h>
//日志通道=文件日志FlLog(构建配置统辖, 见下方DBG节)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _GUEST_REGS
{
	ULONG64 rax;
	ULONG64 rcx;
	ULONG64 rdx;
	ULONG64 rbx;
	ULONG64 rsp;
	ULONG64 rbp;
	ULONG64 rsi;
	ULONG64 rdi;
	ULONG64 r8;
	ULONG64 r9;
	ULONG64 r10;
	ULONG64 r11;
	ULONG64 r12;
	ULONG64 r13;
	ULONG64 r14;
	ULONG64 r15;
} GUEST_REGS, *PGUEST_REGS;

typedef struct
{
	USHORT sel;
	USHORT attributes;
	ULONG32 limit;
	ULONG64 base;
} SEGMENT_SELECTOR;

#pragma warning(push)
#pragma warning(disable: 4201)
typedef struct
{
	USHORT LimitLow;
	USHORT BaseLow;
	UCHAR BaseMid;
	UCHAR AttributesLow;
	struct
	{
		UCHAR LimitHigh : 4;
		UCHAR AttributesHigh : 4;
	};
	UCHAR BaseHigh;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;
#pragma warning(pop)

//C侧内部vmmcall统一入口: rcx=功能码(rax=同rcx), rdx/r8/r9=参数。
//返回值=rax(exit handler改写GuestRegs->rax即透传; 不写的功能码
//rax=功能码本身)。r10/r11=vmmcall签名(与common-asm.asm同步),
//校验在exit handler的VMMCALL case(不符->'u'环留痕+#UD注入)
ULONG64 CmVmmCall(ULONG opcode, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4);
//shutdown park本体(asm, sti+hlt自旋, 永不返回)。SVM的VMEXIT_SHUTDOWN
//处置终点: 本核退出虚拟化但持续服务中断, 切断级联冻结
void CmShutdownPark();

//shutdown park核位掩码(bit i=cpu i已park)。park核的VMM栈/代码页仍被
//占用, 卸载守卫据此拒绝卸载
extern volatile LONG g_gnptParkedMask;

//落地探针魔数: guest侧探针首条vmmcall携带。
//改动必须同步common-asm.asm的 mov rcx, 6BEEh
#define GNPT_PROBE_MAGIC 0x6BEE

//vmmcall签名门: 内部vmmcall(CmVmmCall/落地探针)在r10/r11携带128位
//签名, exit handler的VMMCALL case先校验, 不符->'u'环留痕+#UD注入
//(=裸机vmmcall"EFER.SVME=0"#UD语义)。改动必须同步common-asm.asm的
//mov r10/r11立即数(CmVmmCall一处+探针两段)
#define GNPT_VMMCALL_SIG0 0x8F3C1D7A9E2B5461ULL
#define GNPT_VMMCALL_SIG1 0x3A7C5E1F9B2D8467ULL

//内部vmmcall功能码总表见svm.h(已实现: STOP/KEEP/NPTSYNC/NPTSET/
//NPTRES/MSRBIT/MEMCPY/CONCEAL/DRSET); 后续功能预留未接线:
//  10=TSC校准探针(空handler)  11=时钟布防

//当前虚拟化目标核(-1=未启动), 启动循环置位, 日志心跳读它
extern volatile LONG g_gnptVcpuCpu;

//hook安装/移除当前阶段号(hook.c维护; 阶段表见hook.c)——HB心跳行
//st=字段读它: 冻结吞掉环尾时, 存活的任一心跳行仍能定位冻结阶段
extern volatile LONG g_gnptHookStage;

//===== 文件日志 =====
//DriverEntry/DriverUnload路径零文件I/O(加载窗口期过滤驱动可能死锁):
//FlLog只写入无锁行环, 磁盘写只发生在后台线程:
//  T1(Temp): 权威副本+心跳+二进制环排空;  T2(Desktop): 尽力镜像
//IRQL约束: FlLog仅PASSIVE_LEVEL; FlLogSpin<=DISPATCH_LEVEL;
//FlRingPush任意IRQL(含#VMEXIT上下文)
#define GNPT_RING_SIZE       1024   //二进制事件环条目数(须为2的幂)
#define GNPT_LINE_RING_SIZE  512    //格式化行环条目数(须为2的幂)
#define GNPT_LINE_TEXT       496    //单行最大长度
#define GNPT_EXIT_REASON_MAX 0x420  //SVM exit code上限(覆盖0x400-0x407 AVIC/PML区)

typedef struct _GNPT_RING_ENTRY
{
	ULONG64 a;        //rip 或 gpa
	ULONG64 b;        //EXITINFO1 / 辅助参数
	ULONG64 c;        //辅助参数
	ULONG64 tsc;
	ULONG  seq;       //提交标记: 等于环形序号才算有效(防读到半写条目)
	ULONG  reason;    //SVM exit code
	USHORT cpu;
	CHAR   tag;       //环事件类型(见下方tag表)
	USHORT pad;
} GNPT_RING_ENTRY, *PGNPT_RING_ENTRY;

//环事件tag含义(语义表; 日志解析依赖此表):
//  E=#VMEXIT采样(rsn=exit code) R=vmrun一致性失败 W=落地探针
//  Q=KEEP放行 S=STOP桥通过(卸载留痕, rsn=0x81, a=1)
//  u=vmmcall签名门拒绝(rsn=0x81, b=试探的功能码) B=#UD注入采样(rsn=引发exit)
//  D=同(code,rip)环路 X=NPF风暴逃生(rsn=0x400) T/U=预留(park/未知exit族)
//  i=NPTSYNC每核TLB同步确认(rsn=0x81, 安装/移除布防面包屑)
//  V=NPT视图切换采样(a=视图 b=每核计数) H=detour分发入口(a=目标)
//  O=CallOriginal入口(a=重定位跳板) N=NPF留痕(rsn=0x400, a=gpa, b=错误码)
//  h=hook命中采样(用户回调发出, rsn=Arg1低32位, a=命中计数) w=CallOriginal误用警告(非回调上下文)
//  s=单步arm(rsn=用途1读透明/2临时RW, a=hook条目, b=采样计数; 读透明链起点)
//  e=单步#DB收尾(rsn=用途, a=0(BS=1 TF引发)/1(BS=0 Dr断点抢入), b=计数; 链终点)
//  b=MSRBIT root位图原语(rsn=0x81, a=msr, b=op)
//  n=NPT root原语(rsn=功能码5/6, a=gpa, b=pa|view或view, c=flags)
//  m=MSR exit采样(rsn=0x7C, a=msr, b=读写1位, c=计数; 首条+每4096条)
//  Z=自我隐蔽完成(rsn=0, a=零页pa, b=登记页数, c=页表页数; 一次)
//  o=隐蔽页兜底恢复(rsn=0x400, a=隐蔽页pa, b=faulting gpa, c=累计次数)
//  F=NPF风暴五档转储(rsn=1-5档位: 1=RIP/错误码/gpa 2-3=易失GPR
//    4=指令字节(DecodeAssists) 5=guest CR组; 同gpa连续32次单发,
//    此后该核'N'静音)
//  Y=复位类事件命中(rsn=exit码0x7F/0x63/0x52, a=RIP, b/c=Info; 随后
//    0xDEADDEAD标记蓝屏——把无痕迹硬复位变成带dump可分析崩溃)
//  P=pushf仿真(窗口内) p=popf仿真(窗口内)
//  L=单步窗口泄漏收口(rsn=用途 a=RIP b=RFLAGS——armed而TF已失,
//    清TF类指令把窗口卡死, 防御体系按use收尾)
//  I=INTn步进帧清洗(a=RIP b=帧内RFLAGS清洗后值——int压入活
//    RFLAGS含注入TF, 不清则handler iret弹回=TF复活)
//  t=TSC时间轴补偿终值(卸载留痕, rsn=offset低32位, a=offset高32位
//    ——负值累计量=本核会话root驻留总扣除, 补偿循环活性铁证)
//  v=SVM指令族#UD注入采样(rsn=exit码0x7A/0x80/0x82-0x86, a=RIP;
//    首条+每4096条——预期个位数=探测器/自触发)
//  G=#GP拦截处置采样(rsn=0x4D, a=RIP, b=1族字节命中转注入#UD/
//    0忠实回注; 首条+每4096条)
//  c=运行期工件隐蔽登记(rsn=功能码, a=pa, b=0拒绝/1成功, c=登记
//    总数; Install冷路径)
//  M=root拷贝原语(rsn=功能码, a=dst, b=src, c=len; Remove冷路径)
//  J=安装/移除阶段面包屑(cpu=阶段号, rsn=阶段号; 表见hook.c——
//    冻结吞环尾时HB行st=字段仍能指示最后阶段)
//  j=全核同步DPC跳过(rsn=NPTSYNC; 非in-guest核留痕)
//  g=DR-TRANSPARENT武装/解除(rsn=DRSET, a=slot|on<<8, b=入口
//    线性地址, c=VMCB.Dr7; 每核逐条——install/remove广播面包屑)
//  y=DR断点改道采样(rsn=B位图, a=跳板槽RIP, b=计数; 首条+每
//    4096条——TRANSPARENT触发链起点)
//  q=MOV DR影子仿真采样(rsn=exit码0x20-0x3F, a=推进后RIP,
//    b=计数, c=EXITINFO1; 首条+每1024条; rsn&0xF>7或4/5=#UD注入)
//  a=guest #DB忠实投递(rsn=B位图|BS<<8|BD<<12, a=RIP, b=投递
//    后影子DR6——guest单步/其断点/GD访问=裸机等价语义)
//  f=DR hook探测期让位(rsn=1 guest单步中BP命中fail-open/
//    2槽被guest占用跳过武装/3 guest断点同场冲突; a=RIP, b=计数
//    ——让位审计面, 高频出现=探测者在场的信号)
//  k=NX-Fence入口陷阱(rsn=0x400, a=改道后跳板槽RIP, b=fault gpa;
//    fence触发链起点)
//  r=NX-Fence rearm完成(rsn=0x81, a=vmmcall处RIP; stub尾收尾=
//    在途旗清+视图回P, fence触发链终点)
//  A=NX-Fence信标回P(rsn=0, a=当前RIP; fence页邻函数驻留旗被
//    任意exit消费=fence重武装)
typedef struct _GNPT_LINE_ENTRY
{
	ULONG  seq;       //提交标记(=入环序号, 即最终行号-1)
	CHAR   text[GNPT_LINE_TEXT];
} GNPT_LINE_ENTRY, *PGNPT_LINE_ENTRY;

//===== 蓝屏黑匣子 =====
//级联冻结时磁盘日志可能一起失效, 黑匣子(环尾快照+元数据)由看门狗
//主动KeBugCheckEx(0xDEADC0DE)随MEMORY.DMP保留。检测者=双自旋看门狗
//线程(钉cpu0/cpu1, 纯rdtsc计时)。
//解析: tools/gnpt_bb_parse.py扫MEMORY.DMP找"GNPTBB01"魔数
//(解析器与此结构逐字节契约)
typedef struct _GNPT_BLACKBOX
{
	//字节偏移(解析器必须与此逐字节一致; 全部自然对齐, 无pragma pack)
	CHAR    magic[8];       //+0x000 "GNPTBB01"
	CHAR    build[24];      //+0x008 构建标签
	ULONG64 bbVer;          //+0x020 =1(布局版本)
	ULONG64 fireTsc;        //+0x028 触发时刻rdtsc
	ULONG64 fireIntrTime;   //+0x030 触发时刻中断时钟(100ns)
	ULONG64 wdArmed;        //+0x038 武装时刻(0=未武装)
	ULONG64 lineHead;       //+0x040 行环写游标(冻结时的最后行号)
	ULONG64 ringHead;       //+0x048 事件环写游标
	ULONG64 t1Seq;          //+0x050 T1已写行游标
	ULONG64 t2Seq;          //+0x058 T2已镜像行游标
	ULONG64 writeGuard;     //+0x060 写盘护卫状态
	ULONG64 launchHot;      //+0x068 热轮询状态
	ULONG64 vcpuCpu;        //+0x070 虚拟化目标核
	ULONG64 pendCount;      //+0x078 目标核积压中断数
	ULONG64 pollCnt;        //+0x080 看门狗DPC累计轮询数(活体证明)
	ULONG64 exitCounts[GNPT_EXIT_REASON_MAX];  //+0x088 全部exit精确计数(0x2100B)
	GNPT_RING_ENTRY ring[48];   //+0x2188 事件环尾48条快照(按seq升序)
	CHAR    lines[20][256];     //+0x2A88 行环尾20条快照(超256截断)
	CHAR    magic2[8];          //+0x3E88 "GNPTBB02"(完整性尾标)
} GNPT_BLACKBOX, *PGNPT_BLACKBOX;   //sizeof=0x3E90
//(g_flBlackBox/g_flWdTscPerSec的extern在下方#if DBG块内; 结构体
//定义无条件保留=解析器契约)

//===== 文件日志开关(构建配置判据) =====
//唯一开关=DBG(VS构建配置):
//  Debug(DBG=1)  = 完整观测(T1/T2写盘+事件环+看门狗黑匣子)
//  Release(DBG=0)= 全部Fl*接口空操作宏, 日志实现代码不进产物
#if DBG
extern volatile LONG g_flEnabled;      //1=开启(FlInit置位; 仅Debug构建可达)
VOID FlInit(VOID);                     //DriverEntry最先调用: 创建T1/T2/看门狗线程
VOID FlShutdown(VOID);                 //DriverUnload最后调用: 停线程+T1最终落盘
VOID FlLog(const char* fmt, ...);      //仅PASSIVE_LEVEL: 入行环(零文件I/O)
VOID FlLogSpin(const char* fmt, ...);  //自旋等待版(<=DISPATCH_LEVEL/IF=0安全, rdtsc限界500ms)
VOID FlMarkEntryDone(VOID);            //DriverEntry末尾调用: 放行T2的Desktop镜像
VOID FlRingPush(CHAR tag, ULONG cpu, ULONG reason, ULONG64 a, ULONG64 b, ULONG64 c);
                                       //任意IRQL(含#VMEXIT): 无锁写二进制事件环
VOID FlRingExit(ULONG cpu, ULONG reason, ULONG64 rip, ULONG64 qual);
                                       //#VMEXIT统一采样入口(内部含reason计数)
//vmrun观测预热: 置hot+踢T1+睡5ms(仅PASSIVE_LEVEL, vmrun前调用),
//vmrun窗口毫秒级落盘
VOID FlArmLaunchWatch(VOID);
//武装看门狗(行环游标30s不动=触发黑匣子蓝屏); FlShutdown解除
VOID FlWdArm(VOID);
//仅FlShutdown/VMfail路径调用: 解除武装
VOID FlWdDisarm(VOID);
extern volatile LONG64 g_flWriteGuardTsc;   //护卫武装时刻(100ns单位)——超时未清=T1强制解除并补写
extern GNPT_BLACKBOX g_flBlackBox;
extern volatile LONG64 g_flWdTscPerSec;     //TSC频率(标定, 默认2GHz)
//探针窗口写盘护卫(仅Debug构建有消费者): 置位期间T1停止ZwWriteFile
//(事件照常入环), probe返回后补写
extern volatile LONG g_flWriteGuard;
//exit精确计数(仅Debug构建累加于FlRingExit): HB心跳/黑匣子/卸载总结读
extern volatile LONG64 g_flExitCounts[GNPT_EXIT_REASON_MAX];
#else
//Release构建: 空操作宏——调用点连参数带格式串整体消失
#define FlInit()
#define FlShutdown()
#define FlLog(fmt, ...)
#define FlLogSpin(fmt, ...)
#define FlMarkEntryDone()
#define FlRingPush(tag, cpu, reason, a, b, c)
#define FlRingExit(cpu, reason, rip, qual)
#define FlArmLaunchWatch()
#define FlWdArm()
#define FlWdDisarm()
#endif

//===== 采样面包屑宏(Debug构建专用) =====
//热路径观测点统一入口: 每核计数+首条/每Mod条采样入环(Mod=采样掩码,
//0xFFF=每4096条)。Release构建整体消失(计数与入环皆无=调用点零开销)
//——"调试功能仅在Debug构建工作"的机制化保证。Cnt=LONG[64]静态数组;
//Push=入环表达式, 可引用gnCrumb(本次计数值)入载荷
#if DBG
#define GNPT_CRUMB(Cnt, Mod, Cpu, Push) do { \
	LONG gnCrumb = InterlockedIncrement((Cnt) + ((Cpu) & 63)); \
	if (gnCrumb == 1 || (gnCrumb & (Mod)) == 0) { Push; } \
} while (0)
#else
#define GNPT_CRUMB(Cnt, Mod, Cpu, Push)
#endif

//vmrun热轮询标志(两种构建都在, svm.c无条件写): vmrun前置1,
//结果行落盘后清0(T1热模式毫秒级落盘)
extern volatile LONG g_flLaunchHot;

//构建标签: 打进日志第一行核对二进制版本。代码改动必须同步修改
#define GNPT_BUILD_TAG "v0.10c"
//L系列配置二分探针(已完成使命, 保留供复验)。组表:
//G1=异常拦截(#DB/#GP/#MC)+DR位 G2=MSRPM故事位 G3=SMI/SHUTDOWN/
//INIT/INVLPGA/SVM族 G4=TSC补偿壳; GNPT_L3_NODEMO=1(任意组合下
//禁demo=纯引擎纪律)
//毕业链要点: 冻结族杀手=DR+#DB+#GP三位组合(生产已剥#GP/#MC,
//见svm.c填充注释); 三位以下组合与电源/剂量因素均已排除归因
//当前形态(=GNPT_BUILD_TAG): cave写入原语——锁页RW重映射
// (MmProbeAndLockPages(IoReadAccess)只读锁定+MmMapLockedPages
// SpecifyCache建全新RW映射, 新PTE权限由映射API决定不继承源
// RO)。禁用组合: MmBuildMdlForNonPagedPool+MmGetSystemAddress
// ForMdlSafe——置MDL_SOURCE_IS_NONPAGED_POOL后GetSystemAddress
// 直接返回原VA="别名"=原地址=直写RX页(映像页非非分页池, 契约
// 外)。CET在场平台(CR4.CET=1)WP瞬清=死路, 重映射为唯一正道。
// 验收: 选址行段数>0+无蓝屏+demo全绿+卸载cave复原行。
// accel -ExpectTag与GNPT_BUILD_TAG同步
#define GNPT_L3_MINIMAL 0
#define GNPT_L3_G2      0
#define GNPT_L3_G4      0
#define GNPT_L3_NODEMO  0
#define GNPT_L3_NOLBR   0
#define GNPT_L3_NOG1    0
#define GNPT_L3_G1DR    0
#define GNPT_L3_G1EXC   0
#define GNPT_L3_G1DDB   0
#define GNPT_L3_G1DGP   0
#define GNPT_L3_G1DMC   0
#define GNPT_L3_G1DDBGP 0

//==================== 引擎配置开关(功能语义; 历史演进见开发文档) ====================
//TRANSPARENT模式=DR机件(DR0-3线性地址执行断点作入口陷阱, 原页恒等
//不动=读/写透明结构性成立, PG覆盖×热靶×长驻全兼容; 每次目标调用恰
//1 exit; 零翻译翻转=op-cache类陈旧译码缺陷结构性缺席; 每核≤4个
//(DR硬件数, 超出fail-loud), guest自身调试断点被MOV DR影子吸收
//(同KVM/VMware调试影子语义)。机制详见hook.c的DR-TRANSPARENT机件节

//每核DPC哨兵(崩溃取证, Debug构建): 1=挂死核检测+黑匣子蓝屏留证
#define GNPT_DPC_SENTINEL 1

//接管核数: 64=全核(正式值)。部分接管仅限纯引擎诊断形态(hook布防/
//root原语落裸核=蓝屏, 低剂量轮须零hook零MSR面); 剂量敏感平台
//可用低剂量构建做日常观测(死亡率∝接管核数, 低剂量+高负载
//触发器存活——平台SMI×VMRUN碰撞模型, 详见开发文档)
#define GNPT_TAKE_CORES 64

//槽池cave刻槽强制池回退: 1=跳过cave选址, 槽一律池分配
//(ExAllocatePool裸内存地址形态)。紧急回退通道(cave路径故障
//时回已验安全态); 正常形态=0(cave刻槽经MDL别名写入, CET安全)
#define GNPT_SLOT_FORCE_POOL 0

//CPUID伪装: 1=置INTERCEPT_CPUID+handler伪装(Fn8000_0001 SVM位
//清零=固件级禁用形态, 与VM_CR伪LOCK|SVMDIS读伪造自洽; 无签名
//leaf归零; maxleaf真值不收敛)。伪装面=接管核集合的函数, 全核
//形态是唯一完整伪装
#define GNPT_CPUID_STEALTH 1

//SMI拦截: 1=置INTERCEPT_SMI+0x62处置(STGI手册协议: SMI从root
//进SMM, 绕开guest态SMM/RSM窗口)。HWCR.SMMLOCK=1时硬件忽略
//(启动横幅读报go/no-go)
#define GNPT_SMI_INTERCEPT 1
extern CHAR g_gnptBuildTag[24];      //common.c定义(=GNPT_BUILD_TAG)

#ifdef __cplusplus
}
#endif

#endif // COMMON_H
