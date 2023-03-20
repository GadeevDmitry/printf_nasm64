%ifndef MY_PRINTF_S
%define MY_PRINTF_S

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
; RAX -  conversion specifier
; RCX -  printf_buff size left
; RSI -  format + format_shift
; RDI -  PRINTF_BUFF + buff_shift
; R8  -> cur_arg
;----------------------------------------------------------------------

;----------------------------------------------------------------------
; %b
;----------------------------------------------------------------------

section .text
Printf_binary:
        mov r10,  r8                ; save r8
        mov r8 , [r8]               ; r8  = number to print
        mov r11, mask_binary        ; r11 = mask

        mov rcx, 1h
        cmp r8 , 0h
        je .Printf_value            ; if (r8 == 0) { rcx = 1; jmp .Printf_value }

        mov rcx, 64d / 1            ; else         { rcx = number of hex-digits in 64bit register }
.Skip_front_zero:
        test r8, r11
        jnz .Printf_value           ; if (highest_bit(r8) != 0) jmp .Printf_value

        shl r8, 1h                  ; r8 = r8 << log(2)
        loop .Skip_front_zero

.Printf_value:
        and r11, r8                 ; highest_bit(r11) =  highest_bit(r8)
        shr r11, 63d                ; highest_bit(r11) -> smallest_bit(r11)

        mov  r11b, DIGIT_TABLE[r11]
        mov [rdi], r11b             ;
        inc  rdi                    ; <=> stosb (r11 -> [rdi])
        dec  rcx                    ; printf_buff size left --

        shl r8, 1h                  ; r8 = r8 << log(2)
        mov r11, mask_binary        ; r11 = mask

        cmp rcx, 0h
        je .Printf_suffix           ; if (rcx == 0) jmp .Printf_suffix
        Is_full_buff .Printf_value  ; else Is_full_buff .Printf_value

.Printf_suffix:
        Is_full_buff .Suffix_only
.Suffix_only:
        mov r8, r10                 ; r8 -> cur_arg
        lea r8, [r8 + 8h]           ; r8 -> next_arg

        mov byte [rdi], 'b'         ;
        inc  rdi                    ; <=> stosb ('b' -> [rdi])
        dec  rcx                    ; printf_buff size left --

        pop rcx
        jmp Scan_format

;----------------------------------------------------------------------
; %o (only 63 bits)
;----------------------------------------------------------------------

section .text
Printf_octal:
        push rcx                    ; save rcx
        mov r10,  r8                ; save r8
        mov r8 , [r8]               ; r8 = number to print
        shl r8 , 1h                 ; skip first bit
        mov r11, mask_octal         ; r11 = mask

        mov rcx, 1h
        cmp r8 , 0h
        je .Printf_value            ; if (r8 == 0) { rcx = 1; jmp .Printf_value }

        mov rcx, 63d / 3            ; else         { rcx = number of hex-digits in 64bit register }
.Skip_front_zero:
        test r8, r11
        jnz .Printf_value           ; if (highest_octal_digit(r8) != 0) jmp .Printf_value

        shl r8, 3h                  ; r8 = r8 << log(8)
        loop .Skip_front_zero

.Printf_value:
        and r11, r8                 ; highest_octal_digit(r11) =  highest_hex_digit(r8)
        shr r11, 61d                ; highest_octal_digit(r11) -> smallest_hex_digit(r11)

        mov  r11b, DIGIT_TABLE[r11]
        mov [rdi], r11b             ;
        inc  rdi                    ; <=> stosb (r11 -> [rdi])
        dec  rcx                    ; printf_buff size left --

        shl r8, 3h                  ; r8 = r8 << log(8)
        mov r11, mask_hex           ; r11 = mask

        cmp rcx, 0h
        je .Printf_suffix           ; if (rcx == 0) jmp .Printf_suffix
        Is_full_buff .Printf_value  ; else Is_full_buff .Printf_value

.Printf_suffix:
        Is_full_buff .Suffix_only
.Suffix_only:
        mov r8, r10                 ; r8 -> cur_arg
        lea r8, [r8 + 8h]           ; r8 -> next_arg

        mov byte [rdi], 'q'         ;
        inc  rdi                    ; <=> stosb ('l' -> [rdi])
        dec  rcx                    ; printf_buff size left --

        pop rcx
        jmp Scan_format

;----------------------------------------------------------------------
; %h
;----------------------------------------------------------------------

section .text
Printf_hex:
        push rcx                    ; save rcx
        mov  r10,  r8               ; save r8
        mov  r8 , [r8]              ; r8  = number to print
        mov  r11, mask_hex          ; r11 = mask

        mov rcx, 1h
        cmp r8 , 0h
        je .Printf_value            ; if (r8 == 0) { rcx = 1; jmp .Printf_value }

        mov rcx, 64d / 4            ; else         { rcx = number of hex-digits in 64bit register }
.Skip_front_zero:
        test r8, r11
        jnz .Printf_value           ; if (highest_hex_digit(r8) != 0) jmp .Printf_value

        shl r8, 4h                  ; r8 = r8 << log(16)
        loop .Skip_front_zero

.Printf_value:
        and r11, r8                 ; highest_hex_digit(r11) =  highest_hex_digit(r8)
        shr r11, 60d                ; highest_hex_digit(r11) -> smallest_hex_digit(r11)

        mov  r11b, DIGIT_TABLE[r11]
        mov [rdi], r11b             ;
        inc  rdi                    ; <=> stosb (r11 -> [rdi])
        dec  rcx                    ; printf_buff size left --

        shl r8 , 4h                 ; r8 = r8 << log(16)
        mov r11, mask_hex           ; r11 = mask

        cmp rcx, 0h
        je .Printf_suffix           ; if (rcx == 0) jmp .Printf_suffix
        Is_full_buff .Printf_value  ; else Is_full_buff .Printf_value

.Printf_suffix:
        Is_full_buff .Suffix_only
.Suffix_only:
        mov r8, r10                 ; r8 -> cur_arg
        lea r8, [r8 + 8h]           ; r8 -> next_arg

        mov byte [rdi], 'h'         ;
        inc  rdi                    ; <=> stosb ('h' -> [rdi])
        dec  rcx                    ; printf_buff size left --

        pop rcx
        jmp Scan_format

;----------------------------------------------------------------------
; %d
;----------------------------------------------------------------------

Printf_decimal: jmp Printf_default

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

        Is_full_buff .Printf_value

.String_end:
        lea r8 , [r8 + 8h]           ; r8 -> next arg
        mov rsi, r10

        Is_full_buff Scan_format

;----------------------------------------------------------------------
; default
;----------------------------------------------------------------------

Printf_default: Stos_continue Scan_format

%endif