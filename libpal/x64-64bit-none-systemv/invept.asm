bits 64
default rel

section .text

global pal_execute_invept
pal_execute_invept :
    invept rdi, [rsi]
    ret
