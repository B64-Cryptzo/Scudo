extrn KiUserExceptionDispatcher : qword
extrn topLevelHandler : proc

.code  

instrument PROC
	cmp	r10, KiUserExceptionDispatcher
	jne	exit

	; backup volatile registers
	sub 	rsp, 8h
	push	rax
	push	rcx
	push	rdx
	push	r8
	push	r9
	push 	r10
	push 	r11
	sub 	rsp, 60h
	movaps	[rsp], xmm0
	movaps	[rsp+10h], xmm1
	movaps	[rsp+20h], xmm2
	movaps	[rsp+30h], xmm3
	movaps	[rsp+40h], xmm4
	movaps	[rsp+50h], xmm5

	mov	rcx, rsp
	add	rcx, 590h ; ExceptionRecord
	mov	rdx, rsp
	add	rdx, 0A0h ; ContextRecord
	call	topLevelHandler

	; restore volatile registers
	movaps	xmm0, [rsp]
	movaps	xmm1, [rsp+10h]
	movaps	xmm2, [rsp+20h]
	movaps	xmm3, [rsp+30h]
	movaps	xmm4, [rsp+40h]
	movaps	xmm5, [rsp+50h]
	add 	rsp, 60h
	pop 	r11
	pop 	r10
	pop 	r9
	pop 	r8
	pop 	rdx
	pop 	rcx
	pop 	rax
	add 	rsp, 8h

exit:
	mov	rcx, r10
	mov	r10, 0

	jmp	rcx
	int	3
instrument ENDP

END