bits 64
default rel

section .text

global write_cr4_x64_64bit_none_systemv 
write_cr4_x64_64bit_none_systemv :
    mov cr4, rdi
    ret
