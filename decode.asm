.486
.MODEL FLAT, STDCALL
OPTION CASEMAP:NONE

OPTION PROC:PRIVATE	;<-----All Procedures of these modules are private unless otherwise stated

Include windows.inc
Include user32.inc
Include kernel32.inc
include msvcrt.inc

include decode.inc

.const
strSuccess db "Success", 0
suffix db '*'
prefix db 'M'

.data?
suffixOffset dd ?
suffixCounter db ?
extension db ?
fileNameLen dd ?
aBuf dd ?

contentSize dd ?
halfSize dd ?
quarterSize dd ?

keyContent dd ?
keyLen dd ?

.code

CStrLen proc PUBLIC uses edi String:DWORD,MaxStringLen:DWORD
	mov ecx, MaxStringLen ; MAX_STRING_LEN
	mov edi, String
	xor eax,eax
	mov al, 0
	cld
	repne scasb
	mov eax, String
	sub edi, eax
	mov eax, edi
	Ret
CStrLen EndP

CStrCmp proc String1:DWORD,String2
	push esi
	push edi
	mov esi, String1
	mov edi, String2
	
	check_next:
	mov al, byte ptr [esi]
	mov ah,byte ptr [edi]
	.if al != ah
		xor eax,eax ;False
	.elseif al == 0 ;finished
		mov ax,1  ;True
	.else
		inc esi
		inc edi
		jmp check_next
	.endif
	pop edi
	pop esi
	Ret
CStrCmp EndP

GetAlgorithmId proc PUBLIC Filename:DWORD
	invoke CStrLen,Filename,512
	mov edi, Filename
	add edi, eax
	sub edi, 5
	
	mov al, byte ptr [edi]
	.if al != '.'
		mov eax, -1
		Ret
	.endif
	
	inc edi
	invoke CStrCmp,edi, offset R4A_ext
	.if eax == 1
		mov eax, alg_R4A
		Ret
	.endif
	
	invoke CStrCmp,edi, offset R5A_ext
	.if eax == 1
		mov eax, alg_R5A
		Ret
	.endif
	mov eax,alg_none
	Ret
GetAlgorithmId EndP

_DecodeWithXorKey proc fMap:DWORD, fSize:DWORD, xorKey:DWORD, outBuf:DWORD
	mov edi, outBuf ; output
	mov esi, fMap
	mov ecx, fSize
	mov edx, xorKey
	
	@decode_next:
	.if ecx == 0
		jmp @finish_decoding
	.endif

	mov al, byte ptr[esi]
	mov ah, byte ptr[edx]
	.if ah == 0
		mov edx, xorKey
		mov ah, byte ptr[edx]
	.endif
	xor al,ah
	mov byte ptr[edi], al
	inc edi
	inc esi
	inc edx
	dec ecx
	jmp @decode_next
	
	@finish_decoding:
	mov eax, outBuf
	Ret
_DecodeWithXorKey EndP

_DecodeWithXorBuffer proc uses edi esi ecx edx ioBuf:DWORD, ioBufSize:DWORD, kBuf:DWORD, kLen:DWORD, rolLen:DWORD
	mov esi, ioBuf
	mov ecx, ioBufSize

	mov edi, kBuf
	xor edx, edx
	xor ebx, ebx
	
	@decode_next:
	.if ecx == 0
		jmp @finish_decoding
	.endif
	.if edx == kLen ; reset
		mov edi, kBuf
		xor edx, edx
	.endif
	.if ebx == rolLen ; reset
		mov edi, kBuf
		xor edx, edx
		xor ebx,ebx
	.endif
	xor eax,eax
	mov al, byte ptr[edi] ; next from key
	xor byte ptr[esi], al
	inc esi
	inc edi
	inc edx ; keyLen
	inc ebx ; rolCounter
	dec ecx ; bufLen
	jmp @decode_next
	
	@finish_decoding:
	mov eax, ioBuf
	Ret
_DecodeWithXorBuffer EndP

ProcessQuarter1 proc PUBLIC uses edi esi ecx qStart:DWORD, qSize:DWORD,bufStart:DWORD
	xor ecx,ecx
	
	mov esi, qStart
	add esi, bufStart
	mov edi, esi
	add edi, quarterSize ; get next quarter
	
	@loop_top:
	.if ecx == qSize
		jmp @finish
	.endif
	xor eax,eax
	mov al, byte ptr[esi]
	xor al, byte ptr[edi]
	mov  byte ptr[esi], al
	inc esi
	inc edi
	inc ecx
	jmp @loop_top
	@finish:
	mov eax, ecx
	Ret
ProcessQuarter1 EndP

ProcessQuarter2 proc PUBLIC uses esi ecx qStart:DWORD, qSize:DWORD,bufStart:DWORD
	xor ecx,ecx
	mov esi, qStart
	add esi, bufStart
	
	@loop_top:
	.if ecx == qSize
		jmp @finish
	.endif
	
	xor eax,eax
	xor edx,edx
	mov ebx,255
	mov eax, qStart
	add eax, ecx ; <- index in buffer
	div ebx

	xor byte ptr[esi], dl
	inc esi
	inc ecx
	jmp @loop_top
	@finish:
	mov eax, ecx
	Ret
ProcessQuarter2 EndP

_PreprocessUniqueID proc uniqueID:DWORD, uniqueIDLen:DWORD
	mov esi, uniqueID
	xor ecx, ecx
	@next:
	.if ecx == uniqueIDLen
	   Ret
	.endif
	inc ecx
	.if ecx == uniqueIDLen
	   Ret
	.endif
	mov byte ptr [esi+ecx],0
	inc ecx
	jmp @next
	Ret
	Ret
_PreprocessUniqueID EndP

DecodeFileR5A proc PUBLIC fileMap:DWORD, fileSize:DWORD, origPath:DWORD, uniqueID:DWORD
	LOCAL uniqueIDLen:DWORD
    
	mov esi, fileMap
	.if esi == NULL
		xor eax,eax
		Ret
	.endif
	;check content prefix:
	mov al, byte ptr [esi]
	.if al != prefix
		xor eax,eax
		Ret
	.endif
	
	mov eax, offset R5A_key
	mov keyContent, eax
	invoke crt_strlen, addr R5A_key
	mov keyLen, eax ;eax = strlen(R5A_key)
	
	mov uniqueIDLen, 0
	.if uniqueID != 0
		invoke crt_strlen, uniqueID
		mov uniqueIDLen, eax
	.endif
	
	invoke VirtualAlloc,0,fileSize, MEM_COMMIT, PAGE_READWRITE
	.if eax == 0
		Ret
	.endif
	mov aBuf, eax
	invoke crt_memset,aBuf,0,fileSize
	
	mov esi, fileMap
	inc esi ; skip prefix
	mov ecx, fileSize
	dec ecx ; skip prefix
	mov contentSize, ecx
	
	invoke crt_memcpy,aBuf,esi,contentSize
	
	mov ebx, contentSize
	sar ebx,2
	mov quarterSize, ebx
	add ebx,ebx
	mov halfSize, ebx
	
	;decode even quarters:
	;quarter 2
	mov ebx, quarterSize
	invoke ProcessQuarter2, ebx, quarterSize, aBuf
	;quarter 4
	mov ebx, quarterSize
	add ebx, halfSize
	invoke ProcessQuarter2, ebx, quarterSize,aBuf
	
	;decode odd quarters:
	; quarter 1	
	invoke ProcessQuarter1, 0, quarterSize,aBuf
 	; quarter3
 	mov ebx,halfSize
	invoke ProcessQuarter1, ebx, quarterSize,aBuf
	.if need_orig_path !=0
		invoke crt_strlen,origPath
		invoke _DecodeWithXorBuffer,aBuf,contentSize, origPath, eax, keyLen
	.endif
	.if need_unique_id  !=0
		;.if is_variant_c == TRUE:
		invoke crt_memcpy, addr processedId, uniqueID, uniqueIDLen
		invoke _PreprocessUniqueID, addr processedId, uniqueIDLen
		;.endif
		invoke _DecodeWithXorBuffer, aBuf, contentSize, addr processedId, uniqueIDLen, keyLen
	.endif
	invoke _DecodeWithXorBuffer, aBuf, contentSize, keyContent, keyLen, keyLen
	mov eax, aBuf
	Ret
DecodeFileR5A EndP

DecodeFileR4A proc PUBLIC fileMap:DWORD, fileSize:DWORD
	mov esi, fileMap
	mov al, byte ptr [esi]
	.if al != prefix
		xor eax,eax
		Ret
	.endif
	
	invoke VirtualAlloc,0,fileSize, MEM_COMMIT, PAGE_READWRITE
	.if eax == 0
		Ret
	.endif
	mov aBuf, eax
	
	mov esi, fileMap
	inc esi ; skip prefix
	mov ecx, fileSize
	dec ecx ; skip prefix
	
	invoke _DecodeWithXorKey,esi,ecx,offset R4A_key,aBuf
	mov eax, aBuf
	Ret
DecodeFileR4A EndP

_DecodeName proc fileMap:DWORD, fileSize:DWORD, Suffix:DWORD, xorKey:DWORD, decodedName:DWORD
	mov esi, Suffix
	mov ecx,fileSize
	add ecx, fileMap
	sub ecx, esi
	mov edx, xorKey
	mov edi, decodedName
	xor eax,eax
	process_next:
	.if ecx == 0
		jmp finish_decoding
	.endif

	invoke _DecodeWithXorKey,esi,ecx,xorKey,decodedName
	.if edi > decodedName
		dec edi
	.endif
	xor al, al
	mov byte ptr[edi], al
	finish_decoding:
	Ret
_DecodeName EndP


DecodeName proc PUBLIC fileMap:DWORD, fileSize:DWORD, Suffix:DWORD, variant:DWORD, decodedName:DWORD
	.if variant==alg_R5A
		invoke _DecodeName,fileMap, fileSize, suffixOffset, offset R5A_key,decodedName
	.elseif variant==alg_R4A
		invoke _DecodeName,fileMap, fileSize, suffixOffset, offset R4A_key,decodedName
	.endif
	Ret
DecodeName EndP


FindSuffix proc PUBLIC fileMapping:DWORD,fileSize:DWORD
	.if fileMapping == NULL
		xor eax, eax
		Ret
	.endif
	mov esi, fileMapping
	mov al, byte ptr [esi]
	.if al != prefix
		xor eax,eax
		Ret
	.endif
	add esi, fileSize
	
	xor eax,eax
	mov suffixCounter, al
	
	search_suffix:
	mov al, byte ptr [esi]
	.if al == suffix
		jmp found
	.else
		mov  suffixCounter, 0
		dec esi
		jmp search_suffix
	.endif
	
	found:
	.if suffixCounter == 0
		inc suffixCounter
		dec esi
		jmp search_suffix
	.endif
	add esi, 2 ; suffix_size
	mov suffixOffset, esi
	mov eax,suffixOffset
	Ret
FindSuffix EndP

End