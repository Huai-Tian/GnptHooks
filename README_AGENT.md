# README_AGENT.md — AI 协作者契约文档 (v0.7e 现状)

> **本文档的读者是大语言模型 / 编码 Agent，不是人类。** 人类请阅读 [README.md](README.md) / [README_ZH.md](README_ZH.md)。
>
> 你（Agent）即将在一个**内核态 Type-1 hypervisor**项目上工作。这不是普通的驱动开发：
> 本框架在**正在运行的 Windows 系统**上虚拟化全部 CPU 核心（AMD SVM）。一个错误的 VMCB 字段、
> 一次错误的 RIP 推进、一个在错误 IRQL 上的阻塞调用、甚至一处丢失的 PML4 顶层链接，
> 都会直接蓝屏（bugcheck）或整机冻结。历史上每一个判例都已写进本文档。
>
> 本文档包含四类知识：
> 1. **红线铁律**（§2）：惯性思维最想"修复"但绝对不能碰的代码模式，每条附违例后果；
> 2. **反直觉设计决策**（§3）："看起来错"但正确的代码；
> 3. **架构与执行模型**（§4-§7）：快速建立正确的系统心智模型；
> 4. **验证协议**（§10-§11）：改完之后如何证明没有破坏系统。

---

## 0. 阅读协议（元指令）

- **权威顺序**：源码注释 > 本文档 > README。若本文档与代码注释冲突，以代码为准，并视为本文档的 bug。
- 本文档**自包含**：不引用任何仓库外文档。设计依据以 APM 章节号形式内嵌于代码注释与本文档。
- §2 的每条铁律都标注了 `[违例后果]`。这些不是代码风格偏好，是已发生事故的总结。
- 修改任何 `.c/.h/.asm` 之前：先过 §9 的 checklist。
- 你无法在本机运行此项目（需要 Windows + VS2022 + WDK + AMD SVM 实机/嵌套环境 + 测试签名）。你能做的验证是：静态编译正确性推理、与本文档契约的一致性核对、编码规范校验（§13）、标识符拼写 grep 核对（沙箱无编译器，笔误不可自愈）。
- **生成代码时的默认姿态**：这个代码库的设计决策经常与教科书/通用驱动开发直觉相反（§3）。当你觉得"这里明显写错了"时，**先假设是你错了**，去 §2/§3 找依据；找不到再向人类提出质疑。

---

## 1. 项目本质（30 秒版）

**GnptHooks = Windows 10 x64 内核驱动，用 AMD SVM 接管正在运行的全部 CPU 核心，通过双 NPT 视图实现稳态零 VM-Exit 的内核函数 hook。**

姊妹项目 GeptHooks（Intel VT-x/EPT）已 v1.12 毕业；本项目是 AMD 侧的独立重设计，概念映射：

| GeptHooks (Intel) | GnptHooks (AMD) | 备注 |
|---|---|---|
| VMCS | VMCB | 控制区+状态保存区，偏移完全不同（vmcb.h 逐字节契约） |
| VM-exit | #VMEXIT | exit code 编号不同（0x81=VMMCALL, 0x400=NPF, 0x72=CPUID） |
| EPT violation (48) | NPF (0x400) | 错误码位域同构但布局不同（EXITINFO1） |
| INVEPT | INVLPGA / TLB_CONTROL | NPT 的 TLB 失效走 VMCB.TlbControl，无 all-context 指令式对应 |
| EPTP switching (VMFUNC) | **不存在** | AMD 无 VMFUNC；双视图=每核换 NCR3+ASID（NPF 被动驱动） |
| MTF monitor trap flag | **不存在** | AMD 单步须 TF+EFLAGS 影子+#DB 拦截（M4，最高风险） |
| EPT 内存类型位 | **不存在** | NPT PTE 无 MTRR 位——不可把 EPT 的 memoryType 逻辑平移 |
| EPT exec-only | **不存在** | NPT 最细只有 RW 位；读透明须 M4 单步原语实现 |

核心事实：

| 事实 | 含义 |
|---|---|
| 驱动形态，非可执行安装包 | 以源码并入使用者自己的驱动工程编译 |
| 全核接管 | `DriverEntry` → 每核发起线程 → vmrun，OS 从此运行在 NPT 之下 |
| 双 NPT 视图 | Primary（恒等，hooked 页 NX）/ Secondary（hooked 页→CodePage），按核持有 |
| 稳态 hook 命中零 VM-Exit | 每核首次取指 NPF 切入 Secondary 后**永驻**；后续命中纯 guest 态 detour |
| bug = 蓝屏/冻结 | 没有用户态容错边界，一切以裸机正确性为准 |
| 嵌套环境是开发形态 | VMware 嵌套 SVM 特性位失真；异常先物理机复现再定性（勿追鬼） |

**当前版本 v0.7e = M5 毕业（v0.7d 全链路 E2E 验收通过）**：M0 骨架/M1 世界开关/M2 NPT 恒等/M3 hook 引擎封版（v0.3c）；M4 TF+#DB 单步原语毕业（EFLAGS 影子/PUSHF/POPF 窗口仿真/读透明双方案）；M5 四视图 TRANSPARENT 毕业并实测（v0.7d：自触发×3+真实内核调用 17 次+265s 浸泡 18 万单步窗口全收口+干净卸载零泄漏核；单步窗口泄漏防御四道防线；重定位器超±2GB 改写器+执行级单测 DbgTools/test_reloc.c）。**CPUID 伪装、TSC 时间轴、时钟域、自我隐蔽仍未实现**（M5 剩余隐蔽面/M6/M7），你也不要"顺手实现"。

---

## 2. 红线铁律（RED LINES — 绝对禁止清单）

每条格式：**规则 / 为什么 / [违例后果]**。编号 RL-xx 供引用。

### A. APM 核对与 AMD/Intel 差量（第一优先级）

- **RL-01** 任何 SVM/NPT/VMCB 语义（指令行为/MSR 号/位定义/VMCB 偏移/exit code）写入代码前，**必须**用 AMD APM 原文核对（*AMD64 Architecture Programmer's Manual Vol2*, Rev 3.45+；从 AMD 官网下载 PDF，pymupdf 检索），出处章节号须标注在紧邻的代码注释中。**你的记忆不可信**——本项目第一个判例：异常 exit code 实为 0x40+向量号（APM §15.5.1 exit-code 表），记忆中的 0x40+2N 是错的。
- **RL-02** **勿把 Intel/VMX 语义想当然平移到 AMD**。已核对差量：无 MTF（用 TF+#DB）、NPT 无 execute-only、NPT PTE 无内存类型位、无 VMFUNC、GIF 语义（vmrun 置/exit 清）、#PF 无 error-code 过滤、EXITINTINFO/EVENTINJ 与 Intel 同构但布局不同。未列出的差量靠 RL-01 兜底。
- **RL-03** MSDN 签名核对同样是最后一道防线：API 参数类型不许凭直觉写。`[判例 M3.7: MmGetSystemRoutineAddress(L"NtClose")——参数须 PUNICODE_STRING, 误传 PWSTR → 字符串内容被当结构体解析 → 0x7E 蓝屏。且 DisableSpecificWarnings 禁了 C4133, 编译器静默]`

### B. exit handler 上下文纪律（SVM root 态，最高危区）

- **RL-04** exit handler（`SvmExitHandler` 及其一切被调函数）内**绝不** `FlLog`/`DbgPrint`/`FlLogSpin`/睡眠/等待对象/获取可能被占的锁。全程 GIF=0，被中断线程可能持有任意锁。`[死锁/系统冻结]` 日志只能用 `FlRingPush`（无锁环，任意 IRQL 安全）。
- **RL-05** exit handler 内**绝不**访问分页内存（可能缺页 → root 态 #PF）。`[root 异常]` 框架自身数据全部 NonPaged。
- **RL-06** 新增 exit 采样点**必须**带限流（`FlRingExit` 模式：首事件+计数+周期采样）。`[风暴场景下观测体系自身成为放大器]`
- **RL-07** 跨核并发计数用 `InterlockedXXX` + `static volatile`；每核数组索引统一 `[cpu & 63]`（与既有数组宽度一致）。

### C. RIP 推进与 NPF 引擎（exit 分发核心语义）

- **RL-08** 指令性 exit（CPUID/VMMCALL 等）：handler 逻辑完成后 `SvmAdvanceRip`（NRIP 硬件回写非零才推）。case 内不要自己算长度——本项目依赖 NRIPS 特性（缺 = 启动拒绝，勿删该 gate）。
- **RL-09** fault 语义 exit（NPF 未处理分支）：**RIP 原样写回，绝不推进**。`[推进 = 跳过 faulting 指令 → 语义破坏]`
- **RL-10** `GnptHookNpfEngine` 的视图切换决策树不可改动语义：取指 NPF（ID 位）在 Primary 且命中 hooked 页 → 切 Secondary；写 NPF（RW 位）在 Secondary 且命中 → 切 Primary；Secondary 态非 hooked 取指 fault = 不可达分支（留痕逃生）。引擎返回 FALSE = 调用方 'N' 环留痕不推 RIP。**勿把"切完视图要不要推 RIP"想当然**——NPF 是 fault，重执行同一条取指，这次走新视图成功。

### D. 双 NPT 视图纪律

- **RL-11** **视图是核级状态，绝不是线程/stub 级状态。** 绝不能恢复"hook 回调前后在 stub 里切视图"的设计。回调期间线程可能迁移到另一核，或被阻塞后本核跑其他线程。`[竞态: 原函数入口在错误视图取指 → 跳转码中段被当指令解码 → 0xC0000005]` 正确语义：回调恒在当前视图执行（嵌套 hook 正常触发，标准 detour 语义），`GnptCallOriginal` 经 LDE 重定位跳板（视图无关）。
- **RL-12** NPT 表（任一视图）PTE 修改后**必须**全核 TLB 同步：`HookSyncAllCpus()` → 每核 vmcall(4) → exit handler 置 `TlbControl=3`。`[陈旧 TLB → 硬件仍按旧翻译走 → 布防不生效或视图撕裂]`
- **RL-13** NPT 树构建**必须**完成顶层链接：`Pml4Va[0] = PdptPa | NPT_PTE_FLAGS_INTER`。`[判例 M3.4: 重构丢此一行 → PML4 全零 → guest 首条取指即 NPF 无 hook 可查 → exit/vmrun 活锁 → 整机无声冻结。特征: 两核打出"接管(vmrun循环就绪)"后系统冻结、'W'/'Q' 零出现]`
- **RL-14** `SvmNptLocatePte` 现场 4KB 拆分：新 PT 页 512 条**先整页填完才换 PDE**（去 PS 位改指 PT）。`[硬件 walker 观察半填 PT = 翻译不确定态]`
- **RL-15** 布防顺序：Secondary 先布（布防窗口内该核取指 fault 再切即无害），Primary 后布。移除时先还原 CodePage 字节再还原 PTE——尚持旧 TLB 翻译的核此刻也只见原始字节。
- **RL-16** 每次 `HookSwitchView` 置 `TlbControl=3`（bring-up 形态，正确性优先）+ ASID 配对（Primary=1/Secondary=2）。ASID 免 flush 切换是**物理机定案项**，勿在嵌套形态"优化"掉 flush。

### E. hook 原函数调用与栈契约

- **RL-17** hook 回调内调用**本 hook 的原函数必须经 `GnptCallOriginal`**。直接 `call Target` = Secondary 视图下取指进 CodePage 跳转码 = 无限递归或跳转码中段被解码成野指令。`[0xC0000005 蓝屏族]`
- **RL-18** `GnptCallOriginal` 的实现 = LDE 重定位跳板（`ReplayVA`：副本 prologue 重放 + 尾 jmp 回原函数体），**视图无关**。不要改成"切 Primary 视图直调原入口"——那是 RL-11 判例删除的方案。
- **RL-19** `hook-asm.asm` 栈纪律不可破坏：`GnptStubEntry` 的 `sub rsp, 28h`（call 点 RSP%16==0；注意帧内**双 push rbp**——第二个是 rsp 槽占位，`[rsp+20h]` 写入的 RSP0 值恰被恢复序列的第一个 `pop rbp` 覆盖前的位置读取）；`GnptCallOrigAsm` 的 `sub rsp, 120h` 固定布局（32B 影子 + 32 槽栈参区，arg5 恒在 `[rsp+20h]`）。`[x64 ABI 违反 = movaps 对齐 #GP 蓝屏族]`
- **RL-20** 栈参数（第 5+ 参）统一取 `Regs->rsp + 0x28`（x64 ABI：返回地址+32B 影子空间之后）。`GUEST_REGS` 字段顺序与 asm push 序一致（rax 最低）——改一处必须同步另一处。
- **RL-21** `GnptCallOrigAsm` 必须保持 `PROC FRAME` + unwind 指令：被调原函数抛异常且上层 SEH 捕获时，内核 unwinder 要能穿越此帧。`[删 unwind = 异常展开野指针]`

### F. 生命周期与卸载

- **RL-22** 卸载顺序**不可变动**：`GnptHookRemoveAll()`（关 SVM **前**，在途回调安全完成）→ `SvmShutdownAllCpus()`（STOP 桥全核去虚拟化，返回 TRUE 才继续）→ `GnptHookFreeMemory()`（关 SVM **后**，纯内存释放）。参考 main.c 的 DriverUnload 三段式。
- **RL-23** park 守卫不可拆：`g_gnptParkedMask` 非零时 `SvmShutdownAllCpus` 拒绝去虚拟化（park 核的 VMM 栈/代码页仍被占用，释放 = 蓝屏），资源泄漏保留是**安全降级**。`[判例: shutdown park 核资源释放 = 蓝屏]`
- **RL-24** STOP 桥契约：exit handler 把 VMCB.RSP/RIP/RAX 填进触发帧的**易失 r10/r11/rax 槽**（asm CmSvmStop: mov rsp,r10; stgi; jmp r11），非易失寄存器全保真。改 vmcall(1) 语义必须同步 svm-asm.asm。
- **RL-25** 发起线程钉核失败 / vmrun 一致性失败（'R' 环）→ 本核不接管，资源回滚；**绝不**带病继续。

### G. VMCALL 签名门与白名单

- **RL-26** 内部 vmmcall 在 r10/r11 携带 128 位签名（`GNPT_VMMCALL_SIG0/SIG1`，common.h）。exit handler 的 VMCALL case 先校验 CPL=0 + 签名 + 功能码白名单（0x6BEE 探针 / 3 KEEP / 1 STOP / 4 NPTSYNC），不符 = 'u' 环留痕 + 注入 #UD（= 裸机 vmmcall 语义）。**改动签名值必须同步 common-asm.asm 的 mov 立即数**；新增功能码必须同时进白名单——静默放行未知码 = hypervisor 泄漏面。
- **RL-27** `GNPT_PROBE_MAGIC`(0x6BEE) 改动必须同步 svm-asm.asm 的 `mov rcx, 6BEEh`。

### H. 编码与构建（编译期就会咬人的）

- **RL-28** 源文件编码铁律：`.c/.h` = **UTF-8 带 BOM + 纯 CRLF**；`.asm` = **无 BOM + CRLF**；全部字符 GBK 可表示。`[判例 M3.5: 整文件重写丢 BOM → cl 按 CP936 解析 → 中文注释尾字节与 \r 配对吞换行 → C4819+C2143 连锁语法错, 报错行号比实际小 2]` **AI 工具改写文件后必须字节级验证 BOM+行尾**（工具默认常剥 BOM/转 LF）。
- **RL-29** 任何代码改动必须同步 `GNPT_BUILD_TAG`（common.h，打进日志第一行）。上机测试第一件事 = 核对横幅版本号（历史跑旧二进制的教训）。
- **RL-30** 结构体 typedef **指针别名必须完整**：`} NPT_TREE, *PNPT_TREE;`。`[判例 M3.3: 漏 *PNPT_TREE → 函数签名里未定义标识符被当隐式声明 → C2146/C2061 级联 + C4013]` 重构后 grep 一遍 `P` 前缀别名的定义与使用。
- **RL-31** MSVC x64 不支持 `__asm` 内联汇编——裸指令（pushfq/lsl/sgdt 等）写入 \*-asm.asm。ml64 操作数必须同尺寸（`lsl eax,eax` 不许 `lsl ecx,ax`）。`[判例 A2022]`

---

## 3. 反直觉设计决策（"看起来错"但正确的代码）

当你产生"这段该重构/修复"的冲动时，先查此表：

| 直觉冲动 | 为什么是错的 | 正确认知 |
|---|---|---|
| "HB 行 r400=2 应该等于 0 才算零 exit" | 每核首次命中 NPF 切 Secondary 是设计内的**一次性**成本 | r400 = 核数（每核 1）且**恒定不增长** = 健康形态；增长 = 视图反复切换（'V' 环采样可辨）才是病 |
| "ExAllocatePoolWithTag(NonPagedPool) 不可执行, 槽池/跳板需要换分配" | MSDN《NX and Execute Pool Types》：NonPagedPool = **可执行**（NonPagedPoolExecute 即其别名, 同值 0）；NX 仅显式 NonPagedPoolNx | 槽池/重定位跳板用 NonPagedPool 正确（M3.6 已查证） |
| "每次视图切换 TlbControl=3 太粗暴, 应优化" | bring-up 形态正确性优先 | 嵌套实测 80 秒仅 2 次切换, flush 开销可忽略；ASID 免 flush 是物理机定案项（RL-16） |
| "NPT 拆页后的 Splits 记录应该跟踪释放" | 交付语义：泄漏 PT 页换管理简单性（GeptHooks 同款裁决） | 有意为之，勿"修" |
| "Secondary 视图该在回调返回后切回 Primary" | 视图是核级状态（RL-11）；数据访问在 Secondary 完全正常 | 常态**永驻** Secondary；仅写 fault 才切回（写随即落在真实页, 再切回） |
| "CPUID 应该过滤隐藏" | 未实现特性（M5）；当前 = 全真值直透传 | 勿"顺手实现"半吊子隐身——失真即特征 |
| "'i' 环事件是中断交付" | 'i' 已被 NPTSYNC 确认占用 | tag 表以 common.h 注释为权威（本文档 §8.2 同步） |
| "SvmShutdownAllCpus 返回 void 够了" | park 拒绝时引擎仍在位, 卸载方不能释放 hook 内存 | BOOLEAN：TRUE=全核裸机可 FreeMemory |
| "重定位跳板失败可以警告后继续安装" | 带病上机 = 不可调试时机的蓝屏 | FAIL → 拒绝安装（安全门语义） |
| "VMware 嵌套 SVM 测出的异常就是 bug" | 嵌套环境特性位失真（无 vGIF 判例等） | 先物理机复现再定性（勿追鬼） |
| "LeakCheck 每个 exit 都跑一遍太浪费, 该缓存/挪位/删除" | 清 TF 类指令（syscall/sysret/iret）使 #DB 永不到达 → 单步窗口永不关闭 → 拦截位+EXEC 视图永久泄漏（0x1E 判例: r70 心跳风暴 44→2542） | `GnptHookStepLeakCheck` 必须保持在 exit handler 每个 exit 首查；判据"armed 而 guest TF 已失"开销 = 窗口外 2 读+1 比较 |
| "#DB 拦截应随单步窗口关闭而解除" | 窗口外残余 TF 的 #DB 直送 guest = 0x3B/0x1E（两判例） | #DB 拦截**常驻**（VMCB init 即设）；IDLE #DB = 吞+清 TF 自愈；只有 PUSHF/POPF 是窗口位 |
| "int 帧清洗加 DR6.BS 门控更严谨" | 嵌套环境以 BS=0 投递 TF 陷阱（实测铁证）→ 门控恒假 = 清洗永不执行 → iretq 弹回 TF 复活链（0x3B 根因） | 帧清洗只看 `g_stepArmIntn`，不看 bs |
| "0x70/0x71 非窗口路径该推进 RIP 防死循环" | 推进 = 跳过 pushfq/popfq 的栈/标志效应 → guest 状态破坏（0x1E 根因之一） | 解除窗口位 + 不推 RIP = 重执行真指令 |
| "窗口关闭时 TF 一律清零更干净" | guest 自身可能持有 TF（单步调试中）——盲清 = 吞掉 guest 状态 | 按 `g_stepTfShadow` 影子忠实还原 |

---

## 4. 架构地图（v0.7e）

```
仓库根/
├── README.md / README_ZH.md     人类文档（英文/中文）
├── README_AGENT.md              本文档
├── DbgTools/                    调试与测试工具集（同 GeptHooks 目录语义）
│                                test_reloc.c 重定位器执行级单测（用户态 x64；
│                                与 hook.c 生成器为镜像契约, 改动须双向同步）
└── GnptHooks/                    源码（VS 工程）
    ├── main.c                   使用示例：DriverEntry→SvmStartAllCpus→TRANSPARENT demo(自触发)→DriverUnload
    ├── svm.c/.h                 SVM 核心：三态检测/资源分配/VMCB 填充/exit 分发/生命周期
    ├── vmcb.h                   VMCB 结构（控制区+状态保存区, 逐偏移, clean bits 位表）
    ├── npt.c/.h                 NPT：四棵静态共享树恒等构建/4KB 拆分/PTE 操作/释放
    ├── hook.c/.h                Hook API：Install/Remove/CallOriginal + NPF 视图切换引擎
    │                            + 跳板槽池 + LDE 重定位跳板生成器（回扫自检+超±2GB改写）
    │                            + TF+#DB 单步原语 + 单步窗口泄漏防御收口
    ├── common.c/.h              观测体系（Fl* 家族/T1/T2/看门狗/黑匣子, 整体 #if DBG）
    ├── common-asm.asm           CmVmmCall（签名门入口）/shutdown park
    ├── svm-asm.asm              世界开关（CmSvmEnter）/exit 汇编壳/STOP 桥/段助手
    ├── hook-asm.asm             GnptStubEntry（detour stub）/GnptCallOrigAsm（栈参转发桩）
    └── LDasm.c/.h               LDE 反汇编引擎（长度计算/指令边界/标志位）
```

关键数据流（一屏版）：

```
DriverEntry(main.c)
  → FlInit → SvmStartAllCpus(svm.c): 三态检测→SvmBuildNptViews(四树恒等)
    →逐核资源预分配(VMCB/HSAVE/IOPM/MSRPM/VMM栈)→逐核发起线程
    →vmrun→CmGuestProbe自证('W')→KEEP('Q')→停泊(中断直通)
  → GnptHookInstall(main.c demo): LDE重定位跳板(回扫自检)→跳板槽→CodePage
    →多视图PTE布防(TRANSPARENT: HIDE潜伏P=0+EXEC全权)→HookSyncAllCpus('i'×N)

hook 命中（常规hook: 双 NPT 稳态零 VM-Exit）:
  每核首次: Primary取指hooked页→NPF(ID位)→GnptHookNpfEngine切Secondary('V')
  此后: guest取指→Secondary PTE→CodePage→目标偏移14B绝对跳转
    →跳板槽(mov r10,entry; jmp GnptStubEntry)→SAVE_ALL('H')
    →GnptCallbackDispatch→你的回调(可GnptCallOriginal('O'))
    →RESTORE_ALL→ret

hook 命中（TRANSPARENT: 每指令2exit, 低频目标专用）:
  潜伏态取指/读hooked页→NPF→EXEC窗口+arm TF('s' rsn=3)→1条指令
    →#DB('e')→切回HIDE潜伏; 外部读→切P+TF读原始字节(读透明)
  防线: 每exit首查LeakCheck(armed而TF已失=收口'L')+
    #DB拦截常驻(IDLE残余=吞+清TF'D')+INTn帧清洗('I')

卸载(DriverUnload): 计数留痕→GnptHookRemoveAll(Remove OK+'i'×N)
  →SvmShutdownAllCpus(STOP桥'S'×N, SVME回读=0)→TRUE→GnptHookFreeMemory
```

---

## 5. 执行模型（建立心智模型）

### 5.1 两种特权态

| | SVM guest（OS） | SVM host（VMM） |
|---|---|---|
| 运行者 | OS 全部代码 + 我们的驱动代码（驱动在 guest 里！） | exit handler / vmmcall 处理器 |
| 地址翻译 | 经 NPT（两套视图之一, gpa→spa） | 不经 NPT（裸机页表） |
| 触发进入 | 敏感指令/事件 → #VMEXIT | — |
| 关键约束 | — | GIF=0（§2.B 全部纪律）；栈=每核 VMM 栈 |

**关键认知**：本驱动的代码大部分时间以 guest 身份运行（包括 `GnptHookInstall` 的 PASSIVE 段）；只有 exit handler 内段在 root 态。**同一函数可能两种态都跑**——用"当前是否在 exit 处理链"判断纪律适用性。

### 5.2 双 NPT 视图（与 GeptHooks 的关键差异）

- 两棵全核共享树：`g_nptTree[0]`=Primary（恒等, hooked 页 `NPT_PTE_FLAGS_HOOKP`=RW+NX）、`g_nptTree[1]`=Secondary（恒等, hooked 页 `NPT_PTE_FLAGS_HOOKS`→CodePage, R+X 无 W）。
- **切换时机不同**：GeptHooks 在安装/移除时主动逐核切 EPTP；GnptHooks 由 **NPF 被动驱动**——每核首次取指 hooked 页 fault 一次, 引擎换 NCR3+ASID+TlbControl=3 切 Secondary, 此后永驻。
- 每核视图状态：`g_view[Cpu]`；切换=写 VMCB 控制区三字段（NCr3/GuestAsid/TlbControl）。
- hooked 页 PTE 形态：Primary=R+W+NX（数据完全透明）；Secondary=R+X 无 W（写 fault → 切回 Primary 落真实页）。

### 5.3 #VMEXIT 分发（SvmExitHandler）

```
exit帧修正(rax/rsp以VMCB为准) → EVENTINJ清场 → FlRingExit(计数+限流采样)
→ 负值族(VMEXIT_INVALID): 'R'环+launchFailed+探针栈桥 → return 1
→ switch(exitCode):
   0x81 VMCALL→签名门+CPL门+白名单→探针('W')/KEEP('Q')/STOP('S'+桥值)/NPTSYNC('i')
   0x72 CPUID→__cpuidex直透传+推RIP
   0x400 NPF→GnptHookNpfEngine(TRUE=已处理重入guest; FALSE='N'留痕不推RIP)
   default→'U'类留痕+推RIP(观察语义)
```

### 5.4 asm 帧布局契约（改 hook-asm.asm/分发器前必背）

`GnptStubEntry` 的 SAVE_ALL 帧（push 序，rax 最低）：

```
偏移(帧基起): rax@00 rcx@08 rdx@10 rbx@18 rbp@20(双push占位,后一槽=rsp) rsi@30
              rdi@38 r8@40 r9@48 r10@50 r11@58 ...
RSP0(guest入口rsp)=帧基+80h;  栈参数首址=RSP0+28h  (= C侧 Regs->rsp+28h)
sub rsp,28h 后 call 点 RSP%16==0  —— 28h 不是笔误
```

`GUEST_REGS`（common.h）= exit 路径的 C 侧寄存器帧，字段顺序与上表一致。
`GNPT_ORIG_CALL` 参数块偏移（+00 Target/+08 StackArgs源/+10 Count/+18..30 Arg1-4）与 hook-asm.asm `GnptCallOrigAsm` 硬契约——改一处须同步。

### 5.5 每核资源（SvmAllocContig 分配，512GB 物理上限内）

VMCB(4KB) / HSAVE(4KB) / IOPM(12KB) / MSRPM(8KB) / VMM 栈(16KB)。共享：双 NPT 树（~1028 页）+ 拆分 PT 页（每 hook 每视图 1 页, 上限 16 区/树）。

---

## 6. API 契约（二次开发视角）

```c
GNPT_HOOK hook = { 0 };
hook.Target   = (PVOID)NtClose;        // 内核函数地址
hook.Callback = OnNtClose;              // detour 回调
hook.Context  = NULL;                   // 原样传回
hook.StackArgs = 0;                     // 目标第5+栈参数个数(0=不转发, ≤32)
GnptHookInstall(&hook);                 // PASSIVE_LEVEL, 引擎运行中
GnptHookRemove(hook.Target);            // PASSIVE_LEVEL
```

- 回调签名 `ULONG64 (*)(Context, Arg1..Arg4, StackArgs*)`，返回值 = hook 的新返回值（完整 detour 控制权）。
- `GnptCallOriginal(Arg1..Arg4)`：仅回调上下文有效（否则静默 0+'w' 环留痕）；栈参自动转发（回调对 StackArgs 的改写一并生效）。
- 嵌套语义：回调内调用其他 hook 目标正常触发（detour 语义）。
- 上限：条目 16 个 hook / 槽池 64 槽 / 拆分区 16 个 2MB 区每树。
- **回调上下文纪律**：运行在原函数的任意线程、任意 IRQL（含 DISPATCH 级）。只允许 Interlocked 操作 / 无锁环事件 / GnptCallOriginal。禁止 FlLog/DbgPrint/分页内存/阻塞（= §2.B 铁律的来源）。
- 卸载三段式（RL-22）。

---

## 7. 内部 vmmcall 功能码表（common.h，签名门保护）

| 码 | 语义 | 备注 |
|---|---|---|
| 0x6BEE | 落地探针首段（'W' 留痕） | 签名 r10/r11 同步 svm-asm.asm |
| 1 | STOP 桥（卸载：本核去虚拟化） | 'S' 留痕 + r10/r11/rax 桥值 |
| 3 | KEEP 放行（探针第二段） | 'Q' 留痕, bInGuest=1 |
| 4 | NPTSYNC（NPT 改动 TLB 同步） | 置 TlbControl=3 + 'i' 留痕 |

**新增功能码时**：白名单 + 签名门 + 'u' 拒绝语义三处同步（RL-26）。

---

## 8. 日志与观测体系（Debug 构建；Release 零代码）

### 8.1 Fl\* 家族 IRQL 矩阵

| 接口 | 允许上下文 | 说明 |
|---|---|---|
| `FlLog` | 仅 PASSIVE_LEVEL | 格式化→行环，T1 线程落盘 Temp 权威副本 |
| `FlRingPush` | **任意 IRQL（含 exit/IPI）** | 48B 二进制环条目，唯一 exit 安全通道 |
| `FlMarkEntryDone` | PASSIVE | 放行 T2 Desktop 镜像 |
| `FlWdArm` / `FlShutdown` | PASSIVE | 看门狗武装 / 解除+停线程 |

### 8.2 事件环 tag 表（与 common.h 注释同步维护——它才是权威）

```
E=#VMEXIT采样(rsn=exit code) R=vmrun一致性失败 W=落地探针
Q=KEEP放行 S=STOP桥通过(卸载留痕, rsn=0x81, a=1)
u=vmmcall签名门拒绝(rsn=0x81, b=试探的功能码) B=#UD注入采样(rsn=引发exit)
D=同(code,rip)环路 X=NPF风暴逃生(rsn=0x400) T/Z/U=预留(park/未知exit族)
i=NPTSYNC每核TLB同步确认(rsn=0x81, 安装/移除布防面包屑)
V=NPT视图切换采样(a=视图 b=每核计数) H=detour分发入口(a=目标)
O=CallOriginal入口(a=重定位跳板) N=NPF留痕(rsn=0x400, a=gpa, b=错误码)
h=hook命中采样(用户回调发出, rsn=Arg1低32位, a=命中计数) w=CallOriginal误用警告(非回调上下文)
s=单步arm(rsn=用途1读透明/2临时RW/3REHIDE, a=hook条目, b=采样计数; 读透明链起点)
e=单步#DB收尾(rsn=用途, a=0(BS=1 TF引发)/1(BS=0 Dr断点抢入), b=计数; 链终点)
b=EXITINTINFO.V=1重放(guest事件递送途中被拦) P=pushf仿真 p=popf仿真(窗口内)
L=单步窗口泄漏收口(rsn=用途 a=RIP b=RFLAGS——armed而TF已失, 防御按use收尾)
I=INTn步进帧清洗(a=RIP b=清洗后帧内RFLAGS——int压入活RFLAGS含注入TF)
```

触发链面包屑顺序：`i`(布防)→`V`(首切)→`H`(分发)→`h`(回调)→`O`(CallOriginal)。

### 8.3 黑匣子与看门狗

Debug 构建双自旋看门狗线程（纯 rdtsc 计时）：行环游标 30s 不动 → 主动 `KeBugCheckEx(0xDEADC0DE)` → MEMORY.DMP 保留黑匣子（"GNPTBB01" 魔数, 环尾 48 条快照 + exitCounts）。**这是调试设施**；Release 构建 common.c 日志区整体 `#if DBG` 不编译。

---

## 9. 修改代码前的 Checklist（逐项过）

```
[ ] 我改动的函数在哪些上下文运行?(guest PASSIVE / exit handler / IPI) → §2.B 纪律适用?
[ ] 是否触碰 exit handler 的 RIP 语义? → RL-08..10
[ ] 是否涉及 NPT 表/视图? → RL-12..16 (TLB同步? 顶层链接? 整页填完才换PDE?)
[ ] 是否动了 hook 链/asm? → RL-17..21 (帧契约? CallOriginal路径? unwind?)
[ ] 物理地址/池分配? → MSDN 签名核对(RL-03), 指针别名完整(RL-30)
[ ] 卸载/生命周期? → RL-22..25 (三段式顺序? park守卫?)
[ ] 新增内部 vmcall 功能码? → RL-26/27 白名单+签名三处同步
[ ] GNPT_BUILD_TAG 已更新? → RL-29
[ ] 文件编码(BOM/CRLF/GBK) 字节级验证? → RL-28
[ ] 新观测点带限流? → RL-06
[ ] tag 语义变化同步 common.h 注释 + 本文档 §8.2?
```

---

## 10. 构建与上机验证协议

### 10.1 构建

- VS2022 + WDK，x64，工程在 `GnptHooks/`（.sln/.vcxproj）。
- **Debug 构建（DBG=1）= 完整观测**：T1 写 `C:\Windows\Temp\gnpt_log.txt`（权威）+ T2 Desktop 镜像（`C:\Users\Public\Desktop\gnpt_log.txt`——通用路径，与登录用户名无关）+ 二进制环 + 看门狗黑匣子。开发/排障一律用它。
- **Release 构建（DBG=0）= 零日志代码进产物**（Fl\* 全部空操作宏）。交付形态。
- inf2cat 已在 Debug/Release 双配置关闭（EnableInf2cat=false）。

### 10.2 上机判据序列（Debug 构建，每次改动后全过一遍）

1. **横幅**：日志第一行 `vXXX` 与源码 GNPT_BUILD_TAG 一致（防旧二进制）。
2. **接管**：每核 `接管(vmrun循环就绪)` → `已guest化(KEEP确认)` × 全核 → `全核接管完成`；'W'/'Q' 每核齐。
3. **hook 安装**：`[Hook] Install OK`（目标/回调/槽/重定位跳板/CodePage 全要素）→ 'i' × 核数（布防同步确认）。
4. **触发**：开关任意程序 → 'V'（首切）→ 'H'/'h'/'O' 推进；HB 行 r400 = 核数且**恒定**；r81 账目精确。TRANSPARENT 目标另查：'s'(rsn=3)/'e' 推进正常；泄漏面包屑 'L'/'D' 允许少量（每秒成百 = 异常须报告）；r70/r41 ≈ 0.1（0.8 = 泄漏风暴形态）。
5. **卸载**：计数留痕 → Remove OK + 'i'×N → Remove 后新 'h' 即刻停止 → 'S'×N（SVME 回读=0）→ 泄漏掩码 0 → NPT 释放页数账目 → FreeMemory → 完成。
6. **Release 崩溃无环**：任何 Release 构建的崩溃，先换 Debug 构建复现再判读。

### 10.3 崩溃取证

Debug 构建崩溃 → `MEMORY.DMP` → WinDbg `!analyze -v` + `k`；判例速查 §11 对照。**异常地址反解**（小端→UTF-16/ASCII）是传参类型错的秒杀技：地址内容恰是字符串片段 = 结构体被字符串冒充。

---

## 11. 蓝屏判例速查表（历史事故 → 根因 → 修复）

判读 DMP 时按症状定位（本表供理解"为什么铁律长这样"）：

| 症状 | 根因 | 判例教训 |
|---|---|---|
| 两核"接管(vmrun循环就绪)"后**整机无声冻结**（无蓝屏无日志推进, 'W'/'Q' 零出现） | NPT 树 PML4[0] 顶层链接丢失 → guest 首条取指即 NPF 且无 hook 可查 → exit/vmrun 活锁 | RL-13（M3.4） |
| 0x7E (C0000005)，读地址内容恰为 UTF-16 字符串片段（如 "ose"="NtClose" 第二 qword） | `MmGetSystemRoutineAddress(L"...")` 传 PWSTR 而非 PUNICODE_STRING——字符串被当结构体解析 | RL-03（M3.7）；C4133 被禁用故编译器静默 |
| C4819 + C2143/C2065/C1075 连锁，报错行号比实际小 2 | .c 整文件重写丢 UTF-8 BOM → cl 按 CP936 撕裂中文注释 | RL-28（M3.5） |
| C2146/C2061 于函数签名行 + C4013 未定义 | typedef 漏指针别名（`} NPT_TREE, *PNPT_TREE;`） | RL-30（M3.3） |
| A2022 操作数尺寸 | ml64 `lsl ecx, ax` 混用 32/16 位 | RL-31 |
| C2440 PHYSICAL_ADDRESS 转换 | MmAllocateContiguousMemorySpecifyCache 参数不全（Lowest/Ceiling/Boundary） | svm.c 已正确，勿回退 |
| LNK2019 未解析符号 | vcxproj 缺 .c 条目（本地工程文件未同步） | 整目录同步 workspace 包，勿单文件拷贝 |
| 启动横幅版本号与源码不符 | 本地跑旧二进制 / 单文件同步错位 | RL-29；整目录同步 |
| 0x1E，任意进程；心跳 r70(PUSHF/POPF exit) 指数爆炸（实测 44→2542/s） | 单步窗口泄漏：步进指令为 syscall/sysret/iret 清 TF 类 → #DB 永不到达 → 窗口拦截位+EXEC 视图永久泄漏；0x70/0x71 兜底"推进"跳过 pushfq/popfq 的栈/标志效应 → guest 状态破坏 | 每 exit LeakCheck 收口 + 0x70/0x71 兜底改重执行（M5.8） |
| 0x3B Arg1=0x8000004（STATUS_SINGLE_STEP），nt!KiServiceInternal+4 取指 | int 2E 硬件帧压入活 RFLAGS（含注入 TF）→ 帧清洗被 bs 门控跳过（嵌套环境以 BS=0 投递 TF 陷阱）→ iretq 弹回 TF 复活 → 影子投毒 → 窗口外 guest 可见 #DB | #DB 拦截常驻 + IDLE 吞清 TF；int 帧清洗不门控 bs（M5.9） |

---

## 12. 已知边界与残余臂（勿当 bug 修）

| 项 | 状态 | 说明 |
|---|---|---|
| NPF=0 判据 | 物理机定案项 | 嵌套形态 r400=核数恒定已获证（26081 次零增长）；物理机复核待硬件 |
| ASID 免 flush 切换 | 物理机定案项 | bring-up 恒 TlbControl=3；嵌套下切换频率 2 次/80s 无评估价值 |
| 方案 B 临时 RW 跨核窗口 | 已知臂（M4） | SvmNptSetPte 操作全局共享 Secondary 树——单步窗口内其它核对同页读不 fault（读 CodePage 字节，非崩溃）；窗口=1 指令，概率≈0；物理机多核扫描竞争评估 |
| 无 Enumerate API | 未实现 | GeptHooks 有, 本项目按需后补 |
| 无 MSR hook/CPUID 伪装/TSC 时间轴/时钟域/NPT 自我隐蔽 | M5 剩余/M6-M7 路线 | 读透明（TRANSPARENT）已实现并 E2E 毕业（v0.7d）；其余勿"顺手实现" |
| PG 长浸泡 | 待办 | v0.7d 驻留 265s 无 0x109；1h+ 浸泡待做 |
| 嵌套环境 #DB 投递失真 | 已知项 | TF 陷阱以 DR6.BS=0 投递；int 2E 窗口的 #DB 以"TF 已失"形态到达（走 'L' 收口而非 'I' 路径）——物理机应走 'I'；防线 2 已兜底验证 |
| VMware 嵌套 SVM 特性失真 | 已知项 | 异常先物理机复现再定性 |
| 拆分 PT 页不释放 | 交付语义 | 每视图每 2MB 区 1 页, 上限 16 区/树 |
| 回调线程迁移 | 理论臂 | 每核 g_curHook 上下文, 嵌套实测未出现 'w' 留痕 |

---

## 13. 编码与提交规范

- **编码铁律**：RL-28（.c/.h=UTF-8 BOM+CRLF，.asm=无 BOM+CRLF，全 GBK 可表示；工具改写后字节级验证）。
- **代码注释**：中文；契约/不变式/判例教训写在紧邻代码处（§2/§3 的条目大多在源码有对应注释——修改行为时同步注释）。注释精简纪律：保留功能叙述、契约与硬件语义；修复史/过程叙述不进源码。
- **每次代码改动**：同步 `GNPT_BUILD_TAG` + 日志判据（§10.2）。
- **不引入**：运行时日志开关/注册表配置（静态签名风险）、任何"方便调试"的 exit 上下文阻塞调用、Intel 语义的想当然平移（RL-02）。

---

## 14. 用户工作流与沙箱环境（理解你能得到什么反馈）

- 用户只做：VS 编译 → 部署 → sc start/stop → 传日志/转储。用户不读代码。
- 给用户的报错清单里 "未找到 XXX 函数定义" = IntelliSense 噪音（不解析 .asm/跨翻译单元），**不是构建错误**；只看 ml64/cl/Link 退出码。
- 期望输出：中文，先结论后细节，附行动清单。
- 沙箱无编译器——笔误不可自愈，新增代码发布前 grep 核对标识符拼写。
- /workspace 唯一持久区（关键代码必须保存在 /workspace，环境重置即清空）；传输走 4275.com 中转（tools/upload_4275.py / download_4275.sh——tools/ 已 gitignore，本地工具不入公开仓）。
- 里程碑状态与设计裁决全史：本地私有判例库（NOTES.md/HANDOFF.md，均已 gitignore，不入公开仓——与 GeptHooks 仓库形态对齐）；仓库内的权威即本文档 + 源码注释。

---

*本文档随代码演进同步维护。若你（Agent）发现文档与代码冲突：以代码为准，并在你的修改说明中指出文档偏差。*
