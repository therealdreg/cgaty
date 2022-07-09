; By Dreg

.386 
.model flat,stdcall 
option casemap:none 
include \masm32\include\windows.inc 
include \masm32\include\kernel32.inc 
includelib \masm32\lib\kernel32.lib 
include \masm32\include\user32.inc 
includelib \masm32\lib\user32.lib

CALL_FAR MACRO sel, _offset, rpl
    db 9ah
    dd offset _offset
    dw offset sel + rpl
ENDM

.data 
    MsgBoxCaption  db "Press OK to execute call gate",0 
    MsgBoxText       db "Press OK to execute call gate",0

.code 
start: 
    invoke MessageBox, NULL, addr MsgBoxText, addr MsgBoxCaption, MB_OK 

    invoke GetCurrentThread
    invoke SetThreadAffinityMask, eax, 1
    invoke Sleep, 1

    ;int 3
    mov eax, 69696969h
    mov ebx, 69696969h
    mov ecx, 69696969h
    mov edx, 69696969h
    mov esi, 69696969h
    mov edi, 69696969h
    push 69696969h
    push 69696969h
    push 69696969h
    push 69696969h
    push 69696969h
    push 69696969h
    push 69696969h
    loopez:
    
    CALL_FAR 320h, 0, 0
    nop
    nop
    nop
    ;jmp loopez
    
    invoke ExitProcess, NULL 
end start