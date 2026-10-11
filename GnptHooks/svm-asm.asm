EXTERN	SvmExitHandler:PROC		;exit handler实体(svm.c)
EXTERN	SvmRootXcpt:PROC		;root异常取证器(svm.c, 不归点)
EXTERN	g_svmRootIdtr:QWORD		;root IDT伪描述符(svm.c建)
EXTERN	g_svmRootCr3Pa:QWORD		;root树PML4物理页(svm.c建)
.CODE
;=====================================================================
; GnptHooks SVM世界开关
; 契约(与svm.h GNPT_VCPU_SVM同步):
;
; 物理图景(type-2接管): 发起线程T_i钉核调CmSvmEnter。vmrun加载VMCB
; (RIP=CmGuestProbe, RSP=T_i的探针栈)——T_i无缝变成guest线程继续跑,
; vmrun循环冻结于HSAVE; 每次#VMEXIT物理核回host上下文(VMM栈上的
; 循环点), exit handler以"exit时刻guest当前线程"身份执行(type-2下
; host=guest同一OS, 段/MSR一致)。
;
; VMM栈布局(每核2页16KB, 栈底=VmmStackTop向下生长):
;   [Top-0x08] = VmcbPa
;   [Top-0x10] = VCPU指针(VA)
;   向下: exit帧 = homing(0x20) + xmm0-5(0x60) + GUEST_REGS(0x80)
;   即call handler时: rcx=[rsp+0x108](VCPU), rdx=rsp+0x80(Regs)
;
; GUEST_REGS帧布局(common.h结构序): [rsp+0x00]=rax ... [rsp+0x78]=r15
;   exit stub push序(倒): r15..r8,rdi,rsi,rbp,占位,rbx,rdx,rcx,rax
;   rax槽exit时为垃圾(host vmcbPa)——handler从VMCB.5F8读真值覆盖
;
; 卸载协议(STOP): vmmcall(1)由发起线程T_i在guest内自发(从shutdown
; 事件醒来)。handler填GUEST_REGS桥: r10=VMCB.RSP, r11=VMCB.RIP(已
; 推进), rax=VMCB.RAX——asm STOP分支pop后 mov rsp,r10; stgi; jmp r11 =
; T_i在裸机模式从vmmcall下一条继续(桥经易失r10/r11, 非易失GPR全保真, ABI零牺牲)。
;=====================================================================

;----- 段selector读取 -----
CmGetSegCs PROC
    mov ax, cs
    ret
CmGetSegCs ENDP
CmGetSegSs PROC
    mov ax, ss
    ret
CmGetSegSs ENDP
CmGetSegDs PROC
    mov ax, ds
    ret
CmGetSegDs ENDP
CmGetSegEs PROC
    mov ax, es
    ret
CmGetSegEs ENDP

;----- 段limit(lsl语义: 目标=字节粒度段限) -----
CmGetSegLimitCs PROC
    xor eax, eax
    mov ax, cs
    lsl eax, eax                    ;selector零扩展驻eax(lsl要求同尺寸)
    ret
CmGetSegLimitCs ENDP
CmGetSegLimitSs PROC
    xor eax, eax
    mov ax, ss
    lsl eax, eax                    ;selector零扩展驻eax(lsl要求同尺寸)
    ret
CmGetSegLimitSs ENDP
CmGetSegLimitDs PROC
    xor eax, eax
    mov ax, ds
    lsl eax, eax                    ;selector零扩展驻eax(lsl要求同尺寸)
    ret
CmGetSegLimitDs ENDP
CmGetSegLimitEs PROC
    xor eax, eax
    mov ax, es
    lsl eax, eax                    ;selector零扩展驻eax(lsl要求同尺寸)
    ret
CmGetSegLimitEs ENDP

;----- RFLAGS读取(VMCB.State.Rflags源; pushfq全宽) -----
CmGetRflags PROC
    pushfq
    pop rax
    ret
CmGetRflags ENDP

;----- IDTR装载(停泊序列用; x64无MSVC intrinsic) -----
; rcx=伪描述符地址(u16 limit+u64 base, VCPU.RootOsIdtr内存形态)
CmLidt PROC
    lidt fword ptr [rcx]
    ret
CmLidt ENDP

;----- GDTR/IDTR读取(10字节伪描述符: u16 limit + u64 base) -----
CmGetGdtBase PROC
    sub rsp, 10h
    sgdt [rsp]
    mov rax, [rsp+2]
    add rsp, 10h
    ret
CmGetGdtBase ENDP
CmGetGdtLimit PROC
    sub rsp, 10h
    sgdt [rsp]
    movzx eax, word ptr [rsp]
    add rsp, 10h
    ret
CmGetGdtLimit ENDP
CmGetIdtBase PROC
    sub rsp, 10h
    sidt [rsp]
    mov rax, [rsp+2]
    add rsp, 10h
    ret
CmGetIdtBase ENDP
CmGetIdtLimit PROC
    sub rsp, 10h
    sidt [rsp]
    movzx eax, word ptr [rsp]
    add rsp, 10h
    ret
CmGetIdtLimit ENDP

;----- 世界开关 -----
; CmSvmEnter(rcx = PGNPT_VCPU_SVM): 发起接管; 返回=本核已guest化
CmSvmEnter PROC
    mov r9, rcx                     ;r9 = VCPU
    ;--- 发起线程GPR保存到T_i栈(探针栈基础): 16 push, GUEST_REGS内存序 ---
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rbp
    push 0                          ;rsp槽占位
    push rbx
    push rdx
    push rcx
    push rax
    sub rsp, 28h                    ;对齐+影子(16push=128B, 入口%16=8,
                                    ;128后仍8, -28h(40)后%16=0)
    ;--- 填VMCB探针入口: RIP=探针, RSP=当前探针栈 ---
    mov rax, [r9+10h]               ;rax = VmcbVa
    lea rcx, CmGuestProbe
    mov [rax+578h], rcx             ;VMCB.RIP = 探针
    mov [rax+5D8h], rsp             ;VMCB.RSP = 探针栈
    ;--- 切VMM栈, 栈底预置{VmcbPa, VCPU} ---
    mov rcx, [r9+58h]               ;rcx = VmmStackTop
    mov rdx, [r9+18h]               ;rdx = VmcbPa
    mov [rcx-8], rdx                ;[Top-8] = VmcbPa
    mov [rcx-10h], r9               ;[Top-16] = VCPU
    lea rsp, [rcx-10h]              ;rsp = Top-16
    ;--- GIF纪律: vmrun前clgi(原子状态切换, §15.5) ---
    clgi
    ;--- 私有root IDT接管(M17-E): 一次lidt=恒在——§15.4"VMRUN
    ;    saves host state: IDTR, GDTR"入HSAVE, 每个后续#VMEXIT硬件
    ;    恢复该值=root IDT自动生效, 零per-exit成本; guest侧IDTR由
    ;    VMCB独立装载(两轴互扰为零)。clgi后做=GIF=0窗口无中断,
    ;    存根前无故障指令(lidt→vmrun间纯mov) ---
    lidt	fword ptr [g_svmRootIdtr]
    ;--- 私有root CR3接管: 一次切换→VMRUN保存host CR3入HSAVE
    ;    (§15.25.4)→每#VMEXIT硬件恢复=root窗口恒走私有翻译域
    ;    (零per-exit软件成本, 与上方lidt同窗同型: GIF=0无中断,
    ;    mov cr3后取指走root树; guest侧CR3由VMCB独立装载两轴
    ;    互扰为零)
    mov rcx, [g_svmRootCr3Pa]
    mov cr3, rcx
CmSvmLoop:
    mov rax, [rsp+8]                ;rax = VmcbPa ([Top-8])
    ;vmload/vmsave剥除: 本对指令在type-2(host=guest同OS)下为纯自反
    ;往返——VMRUN加载集(§15.5)不含FS/GS/TR/LDTR/KernelGsBase/
    ;SYSCALL/SYSENTER, #VMEXIT也不保存/重载它们(exit后硬件保持
    ;guest运行值=host=guest同值, 无需切换); 指令对的VMCB往返
    ;恒等。保留=每exit两次额外执行, 且Zen4+客户SoC上该指令对
    ;为随机host复位诱因(AMD勘误, Linux对Zen4清特性位绕过),
    ;高频exit下剂量累积=平台衰减态主嫌。初始化时的一次性
    ;__svm_vmsave保留(VMCB段快照=S1故事面HSAVE影子契约)
    vmrun rax                       ;进guest; #VMEXIT回到下一条
    ;===== #VMEXIT: GIF=0, RIP/RSP/RAX=host值, 其余GPR=guest值 =====
    ;--- guest GPR入帧(GUEST_REGS序; rax槽=垃圾, handler从VMCB覆盖) ---
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rbp
    push 0                          ;rsp槽(handler需要时从VMCB.5D8填)
    push rbx
    push rdx
    push rcx
    push rax
    ;--- xmm0-5易失保存(0x60) + homing(0x20) ---
    sub rsp, 80h
    movaps xmmword ptr [rsp+20h], xmm0
    movaps xmmword ptr [rsp+30h], xmm1
    movaps xmmword ptr [rsp+40h], xmm2
    movaps xmmword ptr [rsp+50h], xmm3
    movaps xmmword ptr [rsp+60h], xmm4
    movaps xmmword ptr [rsp+70h], xmm5
    ;--- 调handler: rcx=VCPU, rdx=GUEST_REGS ---
    ;   帧高: rsp+0x80=Regs基, +0x100=Top-16(VCPU槽)
    mov rdx, rsp
    add rdx, 80h                    ;rdx = GUEST_REGS
    mov rcx, [rsp+100h]             ;rcx = VCPU
    push rcx                        ;VCPU暂存栈上(rdtsc要毁rax/rdx;
    rdtsc                           ;  rcx虽幸存但栈序无关, 干净)
    shl rdx, 20h                    ;edx:eax -> 64位T0
    or rdx, rax                     ;rdx = T0全宽
    mov rax, rdx                    ;rax = T0
    pop rcx                         ;rcx = VCPU(还原)
    mov [rcx+80h], rax              ;VCPU->WdTsc = T0
    mov rdx, rsp
    add rdx, 80h                    ;rdx = GUEST_REGS(重装载——
                                    ;push/pop已抵消, rsp回原位)
    call SvmExitHandler
    ;--- 恢复xmm ---
    movaps xmm5, xmmword ptr [rsp+70h]
    movaps xmm4, xmmword ptr [rsp+60h]
    movaps xmm3, xmmword ptr [rsp+50h]
    movaps xmm2, xmmword ptr [rsp+40h]
    movaps xmm1, xmmword ptr [rsp+30h]
    movaps xmm0, xmmword ptr [rsp+20h]
    add rsp, 80h
    test al, al
    jnz CmSvmStop
    ;--- 普通路径: 恢复GPR(rax槽丢弃——vmrun将被VMCB.RAX覆盖) ---
    add rsp, 8                      ;跳rax槽
    pop rcx
    pop rdx
    pop rbx
    add rsp, 8                      ;跳rsp槽
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    jmp CmSvmLoop
CmSvmStop:
    ;--- root IDT还原: 本核OS IDTR(FillVmcb钉核预捕,
    ;    Windows每核独立IDT)。须先于GPR pop(rcx为暂存)与stgi
    ;    (stgi后中断可达, 此刻必须已是OS IDT) ---
    mov rcx, [rsp+80h]              ;rcx = VCPU(栈帧代数契约: 此刻
                                    ;rsp=Top-0x90, VCPU槽[Top-0x10]=
                                    ;+0x80; +0x100是handler调用点
                                    ;rsp=Top-0x110的位移, 两处rsp差
                                    ;0x80——此处若沿用+0x100即读
                                    ;[Top+0x70]栈顶外野页(未映射
                                    ;系统VA)=STOP桥必#PF)
    lidt	fword ptr [rcx+88h]        ;+0x88 RootOsIdtr伪描述符(硬契约)
    ;--- 卸载: handler已填桥(r10=VMCB.RSP, r11=VMCB.RIP推进值,
    ;    rax=VMCB.RAX)。恢复全部GPR后切guest栈跳guest RIP——
    ;    此刻物理CPU=裸机模式(不再vmrun), T_i从vmmcall(1)下一条继续 ---
    pop rax                         ;桥: VMCB.RAX
    pop rcx                         ;桥: VMCB.RSP
    pop rdx                         ;guest真值
    pop rbx                         ;桥: VMCB.RIP
    add rsp, 8                      ;跳rsp槽
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15                         ;16槽耗尽: rsp=Top-0x10
    ;--- root CR3还原: VCPU槽[Top-0x10]在16 pops后幸存
    ;    (栈底预备槽从未被pop)。先切CR3后切栈——此后VMM栈等
    ;    root树内VA不可再访问, mov rsp/stgi/jmp取指全走OS树 ---
    mov rcx, [rsp]                  ;rcx = VCPU
    mov rcx, [rcx+98h]              ;rcx = 本核OS轴CR3(+0x98硬契约)
    mov cr3, rcx
    mov rsp, r10                    ;切guest栈(桥: r10=VMCB.RSP)
    stgi                            ;GIF=1: #VMEXIT清了GIF, 裸机续跑必须
                                    ;先开中断(线程IF=1随HSAVE回读, 只欠GIF)
    jmp r11                         ;裸机模式继续guest代码(桥: r11=推进后RIP)
CmSvmEnter ENDP

;----- 落地探针: VMCB.RIP首指处。vmrun后guest执行的第一段代码。
;全程不碰RSP(探针栈=CmSvmEnter保存的T_i现场), 不依赖GPR语义
;(r10/r11/rcx重装, 其余在探针栈里)。
;  (1)vmmcall(6BEE)'W': 自证世界开关全链路(exit+签名门+RIP推进+vmrun回)
;  (2)vmmcall(3)KEEP: 置bInGuest(接管确认)
;  (3)jmp CmGuestResume: 恢复T_i现场, CmSvmEnter"返回" -----
CmGuestProbe PROC
    mov rcx, 6BEEh                  ;GNPT_PROBE_MAGIC(与common.h同步)
    mov r10, 8F3C1D7A9E2B5461h      ;SIG0(与common.h同步)
    mov r11, 3A7C5E1F9B2D8467h      ;SIG1(与common.h同步)
    vmmcall
    mov rcx, 3                      ;GNPT_VMCALL_KEEP
    mov r10, 8F3C1D7A9E2B5461h
    mov r11, 3A7C5E1F9B2D8467h
    vmmcall
    jmp CmGuestResume
CmGuestProbe ENDP

;----- 探针恢复序列: 从CmSvmEnter保存的T_i栈恢复, "返回"发起线程 -----
CmGuestResume PROC
    add rsp, 28h
    pop rax
    pop rcx
    pop rdx
    pop rbx
    add rsp, 8                      ;跳rsp槽
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    ret
CmGuestResume ENDP

;=====================================================================
; 私有root IDT异常存根(M17-E): 32门向量0-31(门本体svm.c建)
; 检测/鲁棒双面: root窗口异常不再经OS IDT(内核可观测路由+VMM栈
; 上的内核异常分发=0x139类fail-fast)——全部改道SvmRootXcpt取证
; bugcheck。GIF=0只蔽中断不蔽异常(§15.6
; "Disables interrupts by clearing the GIF"), 异常照常向量化=
; 本IDT到达面。门=中断门type14/DPL0/P=1/IST=0(异常时刻RSP=VMM
; 栈=已知良栈, 无需IST切换)。
; CPU帧两族: 无错误码向量[存根push vec]后=RIP; 有错误码向量
; (8/10/11/12/13/14/17)后=错误码, 再=RIP——两族归一入口换算后
; 调C取证器(四寄存器参: vec/rip/err/frame, 不归点)
;=====================================================================
RootXcpt0:  push 0
            jmp RootXcptCommon
RootXcpt1:  push 1
            jmp RootXcptCommon
RootXcpt2:  push 2
            jmp RootXcptCommon
RootXcpt3:  push 3
            jmp RootXcptCommon
RootXcpt4:  push 4
            jmp RootXcptCommon
RootXcpt5:  push 5
            jmp RootXcptCommon
RootXcpt6:  push 6
            jmp RootXcptCommon
RootXcpt7:  push 7
            jmp RootXcptCommon
RootXcpt8:  push 8                       ;#DF(有错误码族)
            jmp RootXcptCommonErr
RootXcpt9:  push 9
            jmp RootXcptCommon
RootXcpt10: push 10                      ;#TS(有错误码族)
            jmp RootXcptCommonErr
RootXcpt11: push 11                      ;#NP(有错误码族)
            jmp RootXcptCommonErr
RootXcpt12: push 12                      ;#SS(有错误码族)
            jmp RootXcptCommonErr
RootXcpt13: push 13                      ;#GP(有错误码族; M16.44主形态)
            jmp RootXcptCommonErr
RootXcpt14: push 14                      ;#PF(有错误码族; CR2由取证器读)
            jmp RootXcptCommonErr
RootXcpt15: push 15
            jmp RootXcptCommon
RootXcpt16: push 16
            jmp RootXcptCommon
RootXcpt17: push 17                      ;#AC(有错误码族)
            jmp RootXcptCommonErr
RootXcpt18: push 18                      ;#MC(尽力取证; 双错环境不保证)
            jmp RootXcptCommon
RootXcpt19: push 19
            jmp RootXcptCommon
RootXcpt20: push 20
            jmp RootXcptCommon
RootXcpt21: push 21
            jmp RootXcptCommon
RootXcpt22: push 22
            jmp RootXcptCommon
RootXcpt23: push 23
            jmp RootXcptCommon
RootXcpt24: push 24
            jmp RootXcptCommon
RootXcpt25: push 25
            jmp RootXcptCommon
RootXcpt26: push 26
            jmp RootXcptCommon
RootXcpt27: push 27
            jmp RootXcptCommon
RootXcpt28: push 28
            jmp RootXcptCommon
RootXcpt29: push 29
            jmp RootXcptCommon
RootXcpt30: push 30
            jmp RootXcptCommon
RootXcpt31: push 31
            jmp RootXcptCommon

RootXcptCommon:                          ;无错误码帧: [rsp]=RIP
    pop rcx                              ;rcx = 向量号
    mov rdx, [rsp]                       ;rdx = 故障RIP
    xor r8d, r8d                         ;r8 = 错误码=0
    jmp RootXcptGo
RootXcptCommonErr:                       ;有错误码帧: [rsp]=错误码
    pop rcx                              ;rcx = 向量号
    mov r8, [rsp]                        ;r8 = CPU错误码
    mov rdx, [rsp+8]                     ;rdx = 故障RIP
RootXcptGo:
    mov r9, rsp                          ;r9 = 异常帧基(取证第4参)
    and rsp, -10h                       ;16对齐(帧指针已存r9, 下移无损)
    sub rsp, 20h                         ;影子区(call后callee入栈%16=8)
    call SvmRootXcpt                     ;不归点: 取证([F]入环)+停泊序列
                                         ;(切OS轴+唤醒T1+OS IDT还原+stgi)
    sti                                  ;OS可中断休眠(v0.10s停泊保活形态:
                                         ;STI;HLT=标准idle对——中断唤醒→
                                         ;OS IDT→IRET→回hlt, 时钟tick照常
                                         ;推进=看门狗不叫, T1排水落盘窗口
                                         ;从<100ms扩展到∞。旧cli形态=GIF=0
                                         ;+IF=0时钟永久悬挂→100ms后他核
                                         ;CLOCK_WATCHDOG(0x101)/IPI→INIT
                                         ;exit→0xDEADDEAD, [F]全灭)
RootXcptHalt:
    hlt
    jmp RootXcptHalt

; 门目标表(svm.c建门引用; dq=存根地址, 与向量号同序)
PUBLIC	g_svmRootStubTab
g_svmRootStubTab LABEL QWORD
    dq RootXcpt0, RootXcpt1, RootXcpt2, RootXcpt3
    dq RootXcpt4, RootXcpt5, RootXcpt6, RootXcpt7
    dq RootXcpt8, RootXcpt9, RootXcpt10, RootXcpt11
    dq RootXcpt12, RootXcpt13, RootXcpt14, RootXcpt15
    dq RootXcpt16, RootXcpt17, RootXcpt18, RootXcpt19
    dq RootXcpt20, RootXcpt21, RootXcpt22, RootXcpt23
    dq RootXcpt24, RootXcpt25, RootXcpt26, RootXcpt27
    dq RootXcpt28, RootXcpt29, RootXcpt30, RootXcpt31

END
