%ifndef MY_PRINTF_S
%define MY_PRINTF_S

section .data
;                         %b,             %c,             %d
JMP_LESS    dq Printf_binary, Printf_char   , Printf_decimal
JMP_MORE    dq Printf_octal , Printf_default, Printf_default, Printf_default, Printf_string
;                         %o,             %p,             %q,             %r,            %s
DIGIT_TABLE db "0123456789ABCDEF"

mask_binary         equ 01h                 ; mask of lowest binary digit
mask_octal          equ 07h                 ; mask of lowest octal  digit
mask_hex            equ 0Fh                 ; mask of lowest hex    digit
mask_highest_byte   equ 8000000000000000h   ; mask of hihest byte of 64bit number (to determine the sign)

section .bss

printf_buff_size equ 1024d
PRINTF_BUFF      db (printf_buff_size + 1) dup (?)

;======================================================================
; Если буфер вывода полный, пишет его содержимое в файл.
; После этого выполняет переход по аргументу
;======================================================================
; Entry: %1 - jmp addr
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

%macro Just_stos 0

        stosb
        dec rcx

%endmacro

;======================================================================
; Сохраняет символ из AL в буфер вывода и делает переход по аргументу.
;======================================================================
; Entry:    AL - character to store
;           %1 - addr to jump
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
; Exit:     none
; Destroys: RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11
;======================================================================

section .text
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
        lodsb

.Cmp_null:
        cmp al, 0h
        je .Exit                        ; if (al == '\0') jmp .Cmp_binary

.Cmp_octal:
        cmp al, 'o'
        jb .Cmp_binary                  ; if (al < 'o') jmp .Cmp_binary

        cmp al, 's'
        ja .Cmp_hexadecimal             ; if (al > 's') jmp .Cmp_hex

        jmp [JMP_MORE + 8*(rax - 'o')]

.Cmp_binary:
        cmp al, 'b'
        jb .Stos_continue_scan          ; if (al < 'b') jmp .Stos_continue_scan

        cmp al, 'd'
        ja .Stos_continue_scan          ; if (al > 'd') jmp .Stos_continue_scan

        jmp [JMP_LESS + 8*(rax - 'b')]

.Cmp_hexadecimal:
        cmp al, 'x'
        jne .Stos_continue_scan         ; if (al != 'x') jmp .Stos_continue_scan

        jmp Printf_hex

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

;----------------------------------------------------------------------
; HANDLERS
;----------------------------------------------------------------------
; RCX -  printf_buff size left
; RSI -  format + format_shift
; RDI -  PRINTF_BUFF + buff_shift
; R8  -> cur_arg
;----------------------------------------------------------------------

;======================================================================
; %b, %o, %x handler
;======================================================================
; Entry:    %1 - bit mask of lowest digit
;           %2 - log(base of number system)
;           %3 - suffix character to determine the number sustem
;----------------------------------------------------------------------
; Expects:  R8  -> number to print
;           RCX =  printf_buff size left
;           RDI -> free byte in printf_buff for the next character
;           RBP =  RSP
;----------------------------------------------------------------------
; Exit:     none
; Destroys: RAX, RCX, RDI, R8, R10, R11
;======================================================================

%macro Printf_2power_number_system 3

        mov r10,  r8                ; save r8
        mov r8 , [r8]               ; r8 = number to print

        mov  r9, mask_highest_byte  ; r9 = mask of highest byte (to determine the sign)
        test r9, r8
        jz  .Printf_abs             ; if (r8 >= 0) jmp .Printf_abs

.Negative_num:
        mov byte [rdi], '-'         ;
        inc rdi                     ; <=> stosb ('-' -> [rdi])
        dec rcx                     ; printf_buff_size left --

        not r8                      ;
        inc r8                      ; r8 = abs(r8)
        Is_full_buff .Printf_abs

.Printf_abs:
        mov r11, %1                 ; r11 = mask of last digit

.Digit_in_stack:
        and  r11 , r8
        mov  r11b, DIGIT_TABLE[r11] ; r11b = ASCII(r11)
        push r11                    ; store in stack

        mov r11, %1                 ; r11 = mask of last digit
        shr r8 , %2                 ; r8 >> log(base)
        cmp r8 , 0h
        jne .Digit_in_stack         ; if (r8 != 0) jmp .Digit_in_stack

.Digit_in_buff:
        pop rax                     ; rax = highest digit
        Just_stos                   ; store rax in the buff
        cmp rsp, rbp
        je .Next_arg_buff_check     ; if (rsp == rbp) jmp .Next_arg_buff_check
        Is_full_buff .Digit_in_buff ; <- else 

.Next_arg_buff_check:
        Is_full_buff .Next_arg
.Next_arg:
        lea r8, [r10 + 8h]          ; r8 -> next_arg

        mov byte [rdi], %3          ;
        inc rdi                     ; <=> stosb (%3 -> [rdi])
        dec rcx                     ; printf_buff_size left --

        Is_full_buff Scan_format

%endmacro

;======================================================================

;----------------------------------------------------------------------
; %b
;----------------------------------------------------------------------

section .text
Printf_binary: Printf_2power_number_system mask_binary, 1h, 'b'

;----------------------------------------------------------------------
; %o
;----------------------------------------------------------------------

section .text
Printf_octal: Printf_2power_number_system mask_octal, 3h, 'q'

;----------------------------------------------------------------------
; %h
;----------------------------------------------------------------------

section .text
Printf_hex: Printf_2power_number_system mask_hex, 4h, 'h'

;----------------------------------------------------------------------
; %d
;----------------------------------------------------------------------

Printf_decimal:
        xor rdx, rdx
        mov rax, [r8]               ; rdx:rax = number to print
        mov r10, 10d

        mov  r9, mask_highest_byte  ; r9 = mask of highest byte
        test r9, rax
        jz  .Printf_abs             ; if (rax >= 0) jmp .Printf_abs

.Negative_num:
        mov byte [rdi], '-'         ;
        inc rdi                     ; <=> stosb ('-' -> [rdi])
        dec rcx                     ; printf_buff_size left --

        not rax                     ;
        inc rax                     ; rax = abs(rax)
        Is_full_buff .Printf_abs

.Printf_abs:
.Digit_in_stack:
        div  r10                    ; rdx = num % 10d, rax = num / 10d
        mov  dl, DIGIT_TABLE[rdx]   ; dl = ASCII(rdx)
        push rdx                    ; store in stack

        xor rdx, rdx                ; rdx:rax = number // 10d
        cmp rax, 0h
        jne .Digit_in_stack         ; if (rax != 0) jmp .Digit_in_stack

.Digit_in_buff:
        pop rax                     ; rax = highest digit
        Just_stos                   ; store rax in the buff
        cmp rsp, rbp
        je .Next_arg_buff_check     ; if (rsp == rbp) jmp .Next_arg_buff_check
        Is_full_buff .Digit_in_buff ; <- else

.Next_arg_buff_check:
        Is_full_buff .Next_arg
.Next_arg:
        lea r8, [r8 + 8h]           ; r8 -> next_arg

        mov byte [rdi], 'd'         ;
        inc rdi                     ; <=> stosb ('d' -> [rdi])
        dec rcx                     ; printf_buff_size left --

        Is_full_buff Scan_format

;----------------------------------------------------------------------
; %c
;----------------------------------------------------------------------

Printf_char:
        mov al, [r8]        ; al = character to print
        lea r8, [r8 + 8h]   ; r8 -> next_arg

        Stos_continue Scan_format

;----------------------------------------------------------------------
; %s
;----------------------------------------------------------------------

Printf_string:
        mov r10, rsi                ; save rsi
        mov rsi, [r8]               ; rsi -> string to print

.Printf_value:
        lodsb                       ; [rsi] -> al
        cmp al, 0h
        je .String_end              ; if (al == '\0') Is_full_buff Scan_format

        Stos_continue .Printf_value

.String_end:
        lea r8 , [r8 + 8h]           ; r8 -> next arg
        mov rsi, r10

        Is_full_buff Scan_format

;----------------------------------------------------------------------
; default
;----------------------------------------------------------------------

Printf_default: Stos_continue Scan_format

%endif