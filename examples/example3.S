[bits 32]
db 0x33
db 0xee
db 0xae
push eax
push ebx
some_label:
add eax, ebx
sub ecx, [eax + 4]
call some_label
mov [ecx + 0x405], eax
mov eax, eax
mov eax, ecx
pop eax
pop ebx
pop ecx

db 0x77
db 0xaa
db 0x77
push eax
push ebx
some_label2:
add eax, ebx
sub ecx, [eax + 4]
call some_label
mov [ecx + 0x405], eax
mov eax, eax
mov eax, ecx
mov [ecx + 0x405], eax
mov eax, eax
mov eax, ecx
mov [ecx + 0x405], eax
mov eax, eax
mov eax, ecx
mov [ecx + 0x405], eax
mov eax, eax
mov eax, ecx
mov [ecx + 0x405], eax
mov eax, eax
mov eax, ecx
pop eax
pop ebx
pop ecx
ret

