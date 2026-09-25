# GnptHooks

简体中文 | [English](README.md) | [AI 协作文档](README_AGENT.md)

## 📖 介绍

**GnptHooks** 是一个面向 **AMD** 平台的隐藏式 Windows NPT 钩子框架（Windows 10 x64）。

它通过 AMD SVM 虚拟化正在运行的系统，利用**每核双 NPT 视图（Primary / Secondary）**拦截函数执行——让你的驱动可以钩取任意内核函数，**不修改原始内存的任何一个字节，且稳态下每次钩子命中不产生任何 VM-Exit**。

执行流的重定向完全由嵌套页表翻译完成：*Primary* 视图恒等映射、钩子页置为不可执行（数据读写完全正常）；*Secondary* 视图把钩子页改译到影子副本（目标偏移处是一条绝对跳转）。钩子页上的**首次取指**触发一次 NPF（#VMEXIT 0x400），引擎在该核上切入 Secondary 视图——此后该核上的每次命中都是纯客户机态 detour，**一次 exit 都没有**。实测：26081 次 NtClose 拦截全程 NPF 计数器钉在每核一例（2 核虚拟机 = 2）。

> **使用 AI 助手（Copilot / Claude / GPT 等）参与本项目的二次开发？** 请先阅读 [README_AGENT.md](README_AGENT.md)——它专为 AI 编写，包含本项目大量**反直觉的安全设计与红线约束**（含全部蓝屏判例）。跳过它直接改代码极可能引入蓝屏级缺陷。

> **Intel 机器？** 本项目是 GeptHooks（Intel VT-x/EPT）的 AMD/SVM 姊妹项目。两者为独立项目、零符号交集；设计互相参照，代码不共享。

## ✨ 功能特性

- **双 NPT 视图稳态零 VM-Exit detour**
  每个核心持有两套 NPT 视图：*Primary*（恒等映射，钩子页 NX——读写完全透明）与 *Secondary*（钩子页改译到影子 CodePage）。命中 = 翻译直达，而不是陷入：**每核只在首次命中时付出一次 NPF exit，此后永远零 exit**。实测：嵌套虚拟机会话中累计 **26081 次** NtClose 拦截，NPF exit 计数器全程恒定为每核一例。

- **detour 完整控制权**
  回调收到原始参数，可以调用原函数（`GnptCallOriginal`）、修改参数或返回值、或整体吞掉这次调用。钩取时刻没有 prologue 重放——影子页携带重定位后的序言；原始页从未被写入。

- **第 5+ 栈参数转发**
  安装时通过 `GNPT_HOOK.StackArgs` 声明目标函数栈参数个数（最多 32 个），回调即收到指向触发栈上实参的 `StackArgs` 指针（可读**可写**，改写后的值随 `GnptCallOriginal` 一并转发）——多参数内核函数的钩取不再有参数缺口。

- **版本无关的运行时跳板**
  跳板由 LDE 重定位引擎在运行时生成——逐指令解码、RIP-relative 重定位（近距目标直接重算 disp32；超 ±2GB 的远距目标改写为等价的 `mov reg, imm64` 绝对直存，Zw 桩类 prologue 不再因距离被拒）、相对分支拒绝、生成后按 CPU 视角回扫自检。没有绑定某个 Windows 构建的硬编码 prologue：钩子可跨 Windows 版本安装；不可重定位的 prologue 在安装时即被拒绝。另配有执行级单元测试（`DbgTools/test_reloc.c`，用户态 x64）在真实 CPU 上运行生成的跳板验证语义等价。

- **构造即写透明**
  Secondary 视图把钩子页映射为只读：任何对该页的写访问触发 NPF，引擎转发回 Primary 视图——写操作落在真实的原始页上——调用者永远观察不到影子副本，钩子簿记页保持一致。

- **TRANSPARENT 模式：面向扫描器级隐匿的读透明**
  以 `HOOK_TRANSPARENT` 安装时，引擎布防**四棵静态 NPT 视图**（P / HOOKS / HIDE / EXEC，各配一个 ASID——视图切换是纯 NCR3+ASID 写：零 PTE 写、零 TLB flush）。潜伏态下钩子页**不存在**（P=0）：任何外部读取（PatchGuard、扫描器）触发 fault，经单步窗口读到**原始字节**——AMD 没有 MTF，引擎注入 TF、认领 #DB、随即重新潜伏。目标执行则打开一条指令宽的 EXEC 窗口进入 detour，随后再潜伏。一套泄漏防御网（每 exit 窗口活性检查、#DB 拦截常驻、中断帧 TF 清洗）保证单步机制永远不会向 guest 暴露可见 #DB。适合低频目标——每条被单步的指令付出 2 次 VM-Exit。

- **观测体系与交付形态构建统辖**
  整套观测设施（写盘线程、二进制事件环、蓝屏黑匣子看门狗）由构建配置统辖：**Debug 构建 = 完整观测**（权威日志写入 `C:\Windows\Temp\gnpt_log.txt`，桌面镜像；日志停滞 30 秒看门狗主动蓝屏抓取内存转储——调试设施，不进交付产物）；**Release 构建 = 零日志代码进产物**。刻意不用运行期/注册表开关：注册表值既是可以被 AV/EDR 静态签名的特征，也会在目标机上留下配置痕迹。

- **干净的交付形态**
  驱动入口只执行框架生命周期（资源分配 → 逐核启动虚拟化 → 常驻）与一个演示钩子（`main.c` 可替换为你自己的逻辑）。框架以源码形态集成——把源文件加入你自己的驱动工程即可。

## 📐 零 VM-Exit 钩子的工作原理

```
                Primary 视图                  Secondary 视图
                ┌────────────┐               ┌────────────┐
                │ 恒等映射,   │               │ 钩子页 PTE │
                │ 钩子页 NX  │               │ → CodePage │
                │  (X=0)     │               │ (X=1, W=0) │
                └─────┬──────┘               └─────┬──────┘
                      │ 数据读写透明                │ → 影子副本(CodePage)
   guest ─────────────┴────────────────────────────┴─────────────────
        钩子页首次取指: NPF → 引擎切该核到 Secondary(TLB冲净)
        —— 此后每次命中都是纯翻译, 零陷入
```

钩子触发链（全程客户机态，零 VM-Exit）：

```
调用者 → 目标函数(Secondary视图=CodePage, 目标偏移处14字节绝对跳转)
  → 本hook独享的跳板槽(mov r10,条目; jmp GnptStubEntry)
  → GnptStubEntry: SAVE_ALL → 分发你的回调
      (可 GnptCallOriginal: 经LDE重定位跳板调用原函数——视图无关,
        回调内调用的其他钩子目标正常触发=标准detour语义)
    → RESTORE_ALL
  ← 调用者(RAX = 你回调的返回值)
```

视图切换引擎（`GnptHookNpfEngine`）：Primary 态钩子页取指 NPF → 切入 Secondary；Secondary 态对影子页写 NPF → 切回 Primary（写随即落在真实页上）。常态下核心 simply **留在** Secondary——实测会话中 NPF 计数器钉在每核一例，而拦截计数无界增长。

## 🚀 快速开始

安装并启动驱动：

```
sc create GnptHooks type= kernel start= demand binPath= "C:\path\to\GnptHooks.sys"
sc start GnptHooks
```

停止并卸载（全部钩子先被干净移除，随后经 STOP 桥在全部核心关闭 SVM）：

```
sc stop GnptHooks
sc delete GnptHooks
```

调试日志无需任何开关：直接用 **Debug 构建**即获得完整观测（文件日志 + 事件环 + 黑匣子看门狗）；**Release 构建**产物零日志代码。

## 🧩 API 使用

```c
#include "hook.h"

// 你的detour回调: 运行在原函数的线程与IRQL上下文,
// 返回值即钩子函数的返回值。
// StackArgs: 第5+个参数(栈参数)数组, 可读可写——
// 改写后的值随GnptCallOriginal一并转发; 未声明StackArgs时为NULL。
static ULONG64 OnNtClose(PVOID Context,
    ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3, ULONG64 Arg4,
    ULONG64* StackArgs)
{
    ULONG64 status = GnptCallOriginal(Arg1, Arg2, Arg3, Arg4);
    return status;   // 也可以伪造——你拥有完整控制权
}

// 安装 / 移除
UNICODE_STRING name;
RtlInitUnicodeString(&name, L"NtClose");
GNPT_HOOK Hook = { 0 };
Hook.Target    = MmGetSystemRoutineAddress(&name);  // 参数是PUNICODE_STRING!
Hook.Callback  = OnNtClose;
Hook.Context   = NULL;
Hook.StackArgs = 0;   // 目标函数第5+栈参数个数(0=不转发; 见下方示例)

GnptHookInstall(&Hook);
// ... 钩子已在全部核心生效 ...
GnptHookRemove(Hook.Target);
```

钩取 6 参数以上（含栈参数）的函数——声明个数即可：

```c
// 目标原型: ULONG64 F(ULONG64 A1..A4, ULONG64 A5, ULONG64 A6);
GNPT_HOOK Hook = { 0 };
Hook.Target    = (PVOID)F;
Hook.Callback  = OnF;
Hook.StackArgs = 2;               // A5/A6 两个栈参数

static ULONG64 OnF(PVOID Ctx, ULONG64 A1, ULONG64 A2,
    ULONG64 A3, ULONG64 A4, ULONG64* StackArgs)
{
    StackArgs[0] ^= 1;            // 改写第5参——转发时生效
    return GnptCallOriginal(A1, A2, A3, A4);  // 栈参数自动转发
}
```

**回调上下文约定**：

1. 回调运行在原函数的线程与 IRQL 上下文（可达 DISPATCH 级）——回调内只应执行 IRQL 安全的操作（原子操作、无锁环事件、`GnptCallOriginal`）。
2. 调用本钩子的原函数**必须**经 `GnptCallOriginal`——它经版本无关的重定位跳板调用原函数并自动转发栈参数（直接调用原入口会在 Secondary 视图下撞入跳转码）。
3. 嵌套语义（标准 detour）：回调内调用的其他钩子目标**正常触发**。

卸载时须在关闭 SVM **之前**移除全部钩子（`GnptHookRemoveAll`——在途回调安全完成），关闭 SVM **之后**再释放内存（`GnptHookFreeMemory`）——参考 `main.c` 的 `DriverUnload` 标准序列。

## ⚙️ 环境要求

- **CPU**：支持 SVM + 嵌套分页（NPT）+ NRIPS 的 AMD 处理器（启动时检测；缺特性 = 干净拒绝，绝不半接管）
- **操作系统**：Windows 10 x64（Zen 3 基线；其他 AMD 世代预期可用——请在你的硬件上验证）
- **虚拟化冲突**：需关闭 Hyper-V、基于虚拟化的安全（VBS）、内存完整性（核心隔离）与 WHP——GnptHooks 必须作为根 hypervisor 运行
- **嵌套测试**：开发期在 VMware 嵌套 SVM 下运行；嵌套环境会失真部分特性位——虚拟机内观察到的异常须先在物理机上复现，再当作 bug 处理
- **测试签名**：执行 `bcdedit /set testsigning on` 开启测试签名，或对驱动进行正式签名
- **构建**：Visual Studio 2022 + Windows Driver Kit（WDK）
- **运行**：管理员权限

## 🧪 能力验证矩阵

核心路径已在嵌套 AMD SVM（VMware 客户机，Windows 10 x64）完成实测——基础引擎 v0.3c（2 核），单步与隐匿套件 v0.7d（4 核）：

| 能力 | 实测证据 |
|---|---|
| 全核 SVM 接管 | 逐核 vmrun → 探针自证（'W'/'Q' 环）→ 干净卸载，多轮稳定（2 核与 4 核） |
| 多视图 NPT 构建 | 静态恒等树（4 视图），覆盖 512GB，横幅打印全部 NCR3 |
| 稳态零 exit 拦截 | 26081 次 NtClose 命中；NPF exit 计数器全程恒为每核一例 |
| NPF 视图切换引擎 | 各核在钩子页首次取指时切入钩子视图（错误码 0x100000015 = P+ID 位，与布防形态精确吻合）；此后零 NPF |
| detour 完整控制权 | 分发/CallOriginal/demo 计数经环面包屑（'V'/'H'/'h'/'O'）全链确认 |
| 版本无关跳板 | LDE 回扫自检通过；超 ±2GB 远距目标（ZwPowerInformation 桩）经 `mov reg, imm64` 改写成功重定位；执行级单测全绿 |
| TRANSPARENT 读透明 | v0.7d：ZwPowerInformation 桩 demo——自触发 3 次 + 真实内核调用者 17 次（dwm/dxgkrnl 路径）全拦截；外部访问一律读原始字节；零 guest 可见 #DB |
| 单步窗口泄漏防御 | v0.7d：265 秒浸泡约 680 窗口/秒（18 万窗口）全部正常收口；泄漏面包屑（'L'/'D'）自愈零影响；r70/r41 exit 比 ≈0.11（修复前风暴形态为 0.8） |
| 干净移除 | CodePage 字节还原 + 视图 PTE 恒等还原 + 全核 TLB 同步；Remove 后新命中即刻停止 |
| 原子卸载 | 全核 STOP 桥 SVME 回读 = 0；泄漏核为零；NPT 页全额释放（账目精确） |
| Release 交付形态 | 无日志构建编译干净（Fl\* 宏整体空操作） |

物理机终验（NPF 计数判据、ASID 免 flush 切换）在路线上——见项目状态。

## ⚠️ 项目状态

里程碑 M0（骨架 + 观测体系）、M1（SVM 世界开关）、M2（NPT 恒等映射）、M3（双 NPT 钩子引擎）、M4（TF+#DB 单步原语）与 M5（四视图 TRANSPARENT 隐匿套件 + 泄漏防御体系）已在**嵌套虚拟化**上分阶段实测毕业——v0.7d 构建通过了完整端到端验收：265 秒浸泡中 20 次真实拦截、全部单步窗口正常收口、干净卸载零泄漏核。剩余待办：PatchGuard 长浸泡、物理机终验、M6 时钟域、M7 root 加固与发布。本框架为研究级质量：hypervisor 层的缺陷仍可能导致蓝屏——**请务必在可弃置的测试机上运行**。

## 🚫 非商业声明

本项目由开发者出于个人兴趣与技术研究目的发起，具有**非商业**性质：

- **永久免费**：
本项目完全免费，**没有任何付费功能、会员、订阅或内购**。所有功能对所有用户完全开放。

- **无赞助渠道**：
作者**从未开设任何赞助渠道**，也**不接受任何形式的金钱捐赠**——以保持项目的中立性与纯粹性。

- **非营利目的**：
本项目不涉及任何商业运营，作者不会从中获取任何直接或间接的经济利益。

- **研究导向**：
本项目始终定位于**安全研究、驱动开发与软件测试**——为社区提供研究工具，而非商业产品。任何对本项目的商业使用均为使用者个人行为，与本项目无关。

- **禁止转售**：
严禁转售、以营利为目的的再分发或商业使用。请仅从本仓库（GitHub）或其他官方指定渠道获取。开发者对非官方渠道产生的任何问题概不负责。

## ⚖️ 免责声明

- **用途限制**：
本项目仅供**安全研究、驱动开发、软件测试与学习交流**使用。
请勿将本项目用于任何非法用途（包括但不限于恶意软件开发、反作弊绕过、数据窃取与系统入侵）。

- **后果警示**：
使用本框架进行钩取**可能违反第三方软件的服务条款及你所在司法辖区的法律**。
使用前请自行评估风险。开发者与贡献者**对由此产生的任何账号封禁、法律责任或其他后果概不负责**。

- **系统稳定性**：
hypervisor 级驱动运行在机器的最高特权层。**一个 bug 即可导致系统蓝屏或数据损坏。**请务必在虚拟机或可弃置的机器上测试，并做好备份。

- **无担保**：
本软件按其许可证条款提供，**不附带任何明示或默示的担保**，包括但不限于适销性、特定用途适用性与非侵权性。

- **兼容性免责**：
本软件**不保证与所有 Windows 版本、CPU 型号或固件完全兼容**。开发者对因系统更新、微码变更或其他不可控因素导致的功能异常或损失概不负责。

- **责任限制**：
在适用法律允许的最大范围内，**无论是否被告知可能性，作者或贡献者均不对因使用或无法使用本软件而产生的任何直接、间接、附带、特殊或后果性损害承担责任**。

- **用户责任**：
使用者须自行承担使用本项目所产生的一切法律责任。

- **最终解释权**：
本免责声明的最终解释权归本项目作者所有。

## 💬 联系方式

欢迎通过 GitHub Issues 提交问题、建议与 bug 报告。

## ⭐ 支持项目

如果你觉得本项目对你有帮助，或认可它在技术研究上的价值，欢迎在 GitHub 上点一个 ⭐。

你的支持能让更多人发现这个项目，也能让作者感受到持续维护的意义。

感谢你的认可。
