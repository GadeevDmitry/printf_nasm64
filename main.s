%include "my_printf.s"

section .text

extern printf

global main
main:
        mov rdi, test_format
        mov rsi, -1
        mov rdx, love_str
        mov rcx, 3802d
        mov r8 , 100d
        mov r9 , 33d
        push    127d

        call My_printf_stderr
        call printf

        add  rsp, 8h

;---------------------------;

        mov rax, 3Ch        ; exit(err_code)
        xor rdi, rdi        ; rdi = 0
        syscall

section .data

test_format db  "-What should you love?", 0Ah,  \
                "%d %s %x %d%%%c%b"     , 0Ah,  \
                0h

love_str db "love"  , 0h