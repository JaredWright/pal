bits 64
default rel

section .text

global read_ds_x64_64bit_none_systemv 
read_ds_x64_64bit_none_systemv :
    xor rax, rax
    mov ax, ds
    ret
