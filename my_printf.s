global _start

section .data
;                         %b,             %c,             %d
JMP_LESS    dq Printf_binary, Printf_char   , Printf_decimal
JMP_MORE    dq Printf_octal , Printf_default, Printf_default, Printf_default, Printf_string
;                         %o,             %p,             %q,             %r,            %s
DIGIT_TABLE db "0123456789ABCDEF"

mask_binary equ  8000000000000000h  ; mask of highest binary digit
mask_octal  equ 0E000000000000000h  ; mask of highest octal  digit
mask_hex    equ 0F000000000000000h  ; mask of highest hex    digit

section .bss

printf_buff_size equ 1024d
PRINTF_BUFF      db (printf_buff_size + 1) dup (0h)

;======================================================================
; Если буфер вывода полный, пишет его содержимое в файл.
; После этого выполняет переход по аргументу
;======================================================================
; Entry: %1  - jmp addr
; Stack:  _____________________________________________________
;        |_...__VA_ARGS___|_format_|_fd_|_ret_addr_|_saved RBP_|...
;                                                              ^
;                                                              RBP
;----------------------------------------------------------------------
; Expects:  RCX - printf_buff size left
;----------------------------------------------------------------------
; Exit:     none
; Destroys: RAX, RCX, RDX, RDI, R9
;======================================================================

%macro Is_full_buff 1

        cmp rcx, 0h
        jne %1

        sub  rdi, PRINTF_BUFF   ; rdi = number of characters to write
        mov  r9 , rsi           ; save rsi

        mov rax, 1h             ; write(fd, buf, count)
        mov rdx, rdi            ; rdx = count
        mov rdi, [rbp + 10h]    ; rdi = fd
        lea rsi, PRINTF_BUFF    ; rsi = buf
        syscall

        mov rsi, r9
        mov rdi, PRINTF_BUFF
        mov rcx, printf_buff_size

        jmp %1

%endmacro

;======================================================================
; Сохраняет символ из AL в буфер вывода. Уменьшает RCX на 1.
;======================================================================
; Entry:    AL - character to store
;----------------------------------------------------------------------
; Expects:  RDI -> printf_buff index for next character
;           RCX  - printf_buff size left
;           DF   = 0
;----------------------------------------------------------------------
; Exit:     none
; Destroys: RCX, RDI
;======================================================================

%macro Just_stos

        stosb
        dec rcx

%endmacro

;======================================================================
; Сохраняет символ из AL в буфер вывода и делает переход по аргументу.
;======================================================================
; Entry:    AL - character to store
;           %1 - 
;----------------------------------------------------------------------
; Expects:  RDI -> printf_buff index for next character
;           RCX  - printf_buff size left
;           DF   = 0
;----------------------------------------------------------------------
; Exit:     none
; Destroys: RAX, RCX, RDX, RDI, R9
;======================================================================

%macro Stos_continue 1

        Just_stos
        Is_full_buff %1

%endmacro

;======================================================================
; Преобразует и пишет строку в файл под управлением format
;======================================================================
; Entry:  ______________________________
;        |_...__VA_ARGS___|_format_|_fd_|
;                                       ^
;                                       top
;        fd          - дескриптор файла
;        format      - управляющая строка
;        __VA_ARGS__ - аргументы format (cdecl calling convention)
;----------------------------------------------------------------------
; Expects: DF = 0
;----------------------------------------------------------------------
; Exit:
; Destroys:
;======================================================================

section.text
My_printf:

        push rbp
        mov  rbp, rsp
        mov  rsi, [rbp + 18h]       ; rsi := format + format_shift
        lea  r8 , [rbp + 20h]       ; r8  -> cur_arg
        mov  rdi, PRINTF_BUFF       ; rdi := PRINTF_BUFF + buff_shift
        mov  rcx,  printf_buff_size ; rcx := printf_buff size left

        xor  rax, rax
Scan_format:
        lodsb

        cmp al, 0h
        je .Exit                    ; if (al == '\0') jmp .Exit

        cmp al, '%'
        je .Switch                  ; if (al == '%') jmp .Switch

.Stos_continue_scan:
        Stos_continue Scan_format

.Switch:

.Cmp_octal:
        cmp al, 'o'
        jb .Cmp_binary                  ; if (al < 'o') jmp .Cmp_binary

        cmp al, 's'
        ja .Cmp_hexadecimal             ; if (al > 's') jmp .Cmp_hex

        jmp [JMP_MORE + 8*(rax - 'o')]

.Cmp_binary:
        cmp al, 'b'
        Just_stos
        jb .Stos_continue_scan          ; if (al < 'b') jmp .Stos_continue_scan

        cmp al, 'd'
        ja .Stos_continue_scan          ; if (al > 'd') jmp .Stos_continue_scan

        jmp [JMP_LESS + 8*(rax 0 'b')]

.Cmp_hexadecimal:
        cmp al, 'x'
        jne .Stos_continue_scan         ; if (al != 'x') jmp .Stos_continue_scan

        jmp [JMP_MORE + 8*('x' - 'o')]

;----------------------------------------------------------------------

.Exit:
        sub  rdi, PRINTF_BUFF       ; rdi = number of characters to write

        mov  rax, 1h                ; write(fd, buf, count)
        mov  rdx, rdi               ; rdx  = count
        mov  rdi, [rbp + 10h]       ; rdi  = fd
        mov  rsi, PRINTF_BUFF       ; rsi -> PRINTF_BUFF
        syscall

        pop rbp
        ret
