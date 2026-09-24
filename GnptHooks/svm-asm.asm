EXTERN	SvmExitHandler:PROC		;exit handler实体(svm.c)
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
CmSvmLoop:
    mov rax, [rsp+8]                ;rax = VmcbPa ([Top-8])
    vmload rax                      ;guest段/MSR集同步(FS/GS/TR/LDTR/
                                    ;KernelGsBase/SYSCALL/SYSENTER)
    vmrun rax                       ;进guest; #VMEXIT回到下一条
    ;===== #VMEXIT: GIF=0, RIP/RSP/RAX=host值, 其余GPR=guest值 =====
    vmsave rax                      ;guest段/MSR集存回VMCB(不碰RIP/RSP/
                                    ;RAX——§15.5.2指令集)
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
    pop r15
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

END
