.CODE
;C侧内部vmmcall统一入口: rcx=功能码(rax=同rcx), rdx/r8/r9=参数。
;返回值=rax(exit handler改写GuestRegs->rax即透传; 不写的功能码
;rax=功能码本身)。r10/r11=vmmcall签名(GNPT_VMMCALL_SIG0/1, 与
;common.h同步), 校验在exit handler的VMMCALL case
CmVmmCall PROC
mov rax,rcx
mov r10, 8F3C1D7A9E2B5461h    ;GNPT_VMMCALL_SIG0(与common.h同步)
mov r11, 3A7C5E1F9B2D8467h    ;GNPT_VMMCALL_SIG1(与common.h同步)
vmmcall
ret
CmVmmCall ENDP

;shutdown park(永不返回): 去虚拟化+清债后跳入此循环。sti+hlt下被
;中断(IPI/时钟)唤醒->ISR在本核VMM栈运行->返回继续hlt: 本核退出
;虚拟化但持续服务中断, 发送核的TLB-flush等IPI广播得以完成, 切断
;级联冻结。
;必须IF=1(关中断停核=IPI永不处理=发送核自旋持锁=全机冻结)。
;约束: 代码页/VMM栈不得释放(卸载守卫在SvmShutdownAllCpus拒绝卸载)
CmShutdownPark PROC
    sti
    hlt
    jmp CmShutdownPark
CmShutdownPark ENDP
END
