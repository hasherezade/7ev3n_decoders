.486
.model	flat, stdcall
option	casemap :none   ; case sensitive

include		base.inc
include		decode.inc
include		scandir.inc

.data
strCannotOpen db "Cannot open the file", 0
strCannotMap db "Cannot map the file", 0
strCannotRecognize db "Cannot recognize the algorithm", 0
strWrongParams db "This algorithm requires filling additional parameters", 0
strCannotAllocate db "Cannot allocate memory",0
strScanningStarted db "Scanning local directory",0
strSuccess db "Success", 0
strFileSaved db "File saved under it's original name", 0
decodedBuf dd 0

.data?
fileMap dd ?
fileSize dd ?
algId dd ?
filePtr dd ?
writternCntr dd ?

.code
start:
	invoke	GetModuleHandle, NULL
	mov	hInstance, eax
	invoke	DialogBoxParam, hInstance, 101, 0, ADDR DlgProc, 0
	invoke	ExitProcess, eax
; -----------------------------------------------------------------------

SaveFile proc Filename:DWORD,fileBuffer:DWORD,bufSize:DWORD
	invoke CreateFile,Filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
	.if eax == INVALID_HANDLE_VALUE
		invoke MessageBox, 0, addr strCannotOpen, addr strCannotOpen, MB_ICONERROR
		Ret
	.endif
	mov filePtr, eax
	invoke WriteFile,filePtr,fileBuffer,bufSize, offset writternCntr,0
	invoke CloseHandle,filePtr
	mov filePtr,0
	mov eax, writternCntr
	.if bufSize == eax
		mov eax,1 ;success
	.else
		xor eax,eax ; failure
	.endif
	Ret
SaveFile EndP

FreeFileHandles proc
	.if fileMap !=0
		invoke UnmapViewOfFile, fileMap
	.endif
	invoke CloseHandle,fileMap
	invoke CloseHandle, fileHandle
	mov fileMap,0
	mov fileHandle,0
	mov fileSize, 0
	Ret
FreeFileHandles EndP

MapFile proc Filename:DWORD
	invoke FreeFileHandles ;ensure that previous handles are closed
	invoke CreateFile, Filename, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
	.if eax == INVALID_HANDLE_VALUE
		;invoke MessageBox, 0, addr strCannotOpen, addr strTitle, MB_ICONERROR
		xor eax,eax ; mappedSize = 0
		Ret
	.endif
	mov fileHandle, eax
	invoke GetFileSize,eax,0
	mov fileSize, eax
	invoke CreateFileMapping,fileHandle,0,PAGE_READONLY,0,0,0
	invoke MapViewOfFile, eax, FILE_MAP_READ, 0, 0, 0
	mov fileMap, eax
	.if eax == 0
		invoke MessageBox, 0, addr strCannotMap, addr strTitle, MB_ICONERROR
		invoke CloseHandle, fileHandle
		mov fileHandle,0
		mov fileSize, 0
		xor eax, eax ; mappedSize = 0
		Ret
	.endif
	mov eax, fileSize
	Ret
MapFile EndP

ReadOriginalFilename proc
	invoke FindSuffix, fileMap, fileSize
	
	mov edi, offset decodedName
	xor eax,eax
	mov byte ptr [edi],al ; reset string
		
	invoke DecodeName, fileMap, fileSize, eax, algId, addr decodedName
	invoke CStrLen, addr decodedName,512
	.if eax!=0 
		sub fileSize, eax ;remove added filename
		sub fileSize, 2 ; remove suffix
	.endif
	Ret
ReadOriginalFilename EndP

MakeFullPath proc
	invoke crt_strlen, addr originalPath
	.if eax == 0
		Ret
	.endif
	add eax, offset originalPath
	mov esi, eax
	dec esi
	mov al, byte ptr[esi]
	.if al != '\' ;add separator
		inc esi
		mov byte ptr[esi],'\'
		inc esi
		mov byte ptr[esi],0
	.endif
	invoke crt_memcpy,addr fullOrigPath, addr originalPath,512
	invoke crt_strlen,addr decodedName
	invoke crt_strncat,addr fullOrigPath, addr decodedName,eax
	mov eax,1
	Ret
MakeFullPath EndP

DisplayAlgID proc hWin:DWORD, nameBuffer:DWORD
	invoke GetAlgorithmId, nameBuffer
	mov algId, eax
				
	.if eax == alg_none
		invoke SetDlgItemText, hWin, IDC_ALG_ID, addr empty_str
		invoke SetDlgItemText, hWin, IDC_EDITBOX2, addr empty_str
		invoke MessageBox, 0, addr strCannotRecognize, addr strCannotRecognize, MB_ICONERROR
	.else
		.if eax == alg_R5A
			invoke SetDlgItemText, hWin, IDC_ALG_ID, addr R5A_ext
		.elseif  eax == alg_R4A
			invoke SetDlgItemText, hWin, IDC_ALG_ID, addr R4A_ext
		.endif
	.endif
	Ret
DisplayAlgID EndP


LoadR5AParams proc hWin:DWORD
	invoke crt_memset,offset originalPath,0,512
	invoke crt_memset,offset uniqueId,0,512
	;validate params
	.if need_orig_path !=0
		invoke GetDlgItemText,hWin, ID_ORIGINAL_DIR, offset originalPath,512
		invoke MakeFullPath
		.if eax==0
			Ret ; failed
		.endif
	.endif
		
	.if need_unique_id !=0
		invoke GetDlgItemText,hWin, ID_UNIQUE, offset uniqueId,512	
		.if eax==0
			Ret ; failed
		.endif
	.endif
	mov eax,1 ;success
	Ret
LoadR5AParams EndP

ValidateDecodeParams proc algoId:DWORD
	.if algoId == alg_R4A
		mov eax,1; params OK
		Ret
	.elseif algoId == alg_R5A
		.if need_orig_path !=0
			invoke crt_strlen, offset originalPath
			.if eax==0
				Ret
			.endif
		.endif
		
		.if need_unique_id !=0
			invoke crt_strlen, offset uniqueId
			.if eax==0
				Ret
			.endif
		.endif
		mov eax,1 ;params OK
		Ret
	.endif
	xor eax,eax ;wrong params
	Ret
ValidateDecodeParams EndP

DecodeFileContent proc hWin:DWORD, nameBuffer:DWORD
	invoke GetAlgorithmId,nameBuffer
	mov algId, eax
	invoke ValidateDecodeParams, algId
	.if eax !=1
		mov eax, 0 ; failed
	.endif
	
	;free previous buffer
	.if decodedBuf != 0
		invoke VirtualFree,decodedBuf,fileSize,0
		mov decodedBuf,0
	.endif
	
	.if algId == alg_R4A
		invoke DecodeFileR4A,fileMap,fileSize
		mov decodedBuf, eax
		Ret
		
	.elseif algId == alg_R5A
		invoke MakeFullPath
		invoke DecodeFileR5A,fileMap,fileSize, addr fullOrigPath, addr uniqueId
		mov decodedBuf, eax
		Ret
	.endif
	
	xor eax, eax
	Ret ; failed

DecodeFileContent EndP

DecodeAndSave proc hWin, nameBuffer:DWORD
	mov decodingSuccess, 0

	invoke GetAlgorithmId, nameBuffer
	mov algId, eax		
	.if eax == alg_none
		mov eax, NULL
	.endif
	
	invoke MapFile, nameBuffer
	.if eax == 0
		invoke MessageBox, hWin, addr strCannotOpen, addr strTitle, MB_ICONERROR
	.endif
	
	invoke ReadOriginalFilename
	invoke DecodeFileContent, hWin, nameBuffer
	mov eax, decodedBuf
	.if eax == 0
		invoke SetDlgItemText, hWin, IDC_PREVIEW, addr empty_str
		invoke FreeFileHandles ; close input
		mov eax, NULL ;failed
		Ret
	.else
		mov eax, fileSize
		dec eax ; remove the size of prefix
		invoke SaveFile,addr decodedName, decodedBuf, eax
		invoke FreeFileHandles ; close input
		
		mov decodingSuccess, eax
		mov eax, offset decodedName ;success
	.endif
	Ret
DecodeAndSave EndP

HideNotNeededControls proc hWin: DWORD
	xor eax,eax
	.if need_orig_path ==0
		invoke GetDlgItem, hWin, ID_ORIGINAL_DIR
		invoke ShowWindow, eax, SW_HIDE
		invoke GetDlgItem, hWin, IDC_ORIGINAL_DIR_LABEL
		invoke ShowWindow, eax, SW_HIDE
	.endif
	.if need_unique_id ==0
		invoke GetDlgItem, hWin, ID_UNIQUE
		invoke ShowWindow, eax, SW_HIDE
		invoke GetDlgItem, hWin, IDC_UNIQE_LABEL
		invoke ShowWindow, eax, SW_HIDE
	.endif
	Ret
HideNotNeededControls EndP

DlgProc	proc	hWin	:DWORD,
		uMsg	:DWORD,
		wParam	:DWORD,
		lParam	:DWORD
	.if uMsg == WM_INITDIALOG
		invoke LoadIcon, hInstance, favicon
		invoke SendMessage, hWin, WM_SETICON, 1, eax
		invoke HideNotNeededControls, hWin
		
	.endif
	.if	uMsg == WM_COMMAND
		.if	wParam == IDC_OPEN
			mov algId, alg_none
			
			mov openFileBuf.nMaxFile,512
			mov openFileBuf.lpstrFile, offset strBuffer
			mov openFileBuf.lStructSize, SIZEOF openFileBuf
			mov openFileBuf.lpstrFilter, offset strFilter
			mov openFileBuf.Flags, OFN_FILEMUSTEXIST
			invoke GetOpenFileName, addr openFileBuf
			.if eax==TRUE
				invoke SetDlgItemText, hWin, IDC_EDITBOX, addr strBuffer
				invoke DisplayAlgID, hWin, addr strBuffer
				invoke MapFile, addr strBuffer	
				invoke ReadOriginalFilename
				invoke FreeFileHandles
				invoke SetDlgItemText, hWin, IDC_EDITBOX2, addr decodedName		
			.endif
		.elseif wParam == IDC_DECODE_ALL
			; open another window:
			invoke	DialogBoxParam, hInstance, IDD_SCAN_DIR, hWin, ADDR ScanDlgProc, 0
			
		.elseif wParam == IDC_DECODE
			invoke GetAlgorithmId, addr strBuffer
			mov algId, eax	
			.if algId == alg_none
				invoke MessageBox, 0, addr strCannotRecognize, addr strCannotRecognize, MB_ICONERROR
			.else
				invoke LoadR5AParams, hWin
				.if eax != 1
					invoke MessageBox, 0, addr strWrongParams, addr strTitle, MB_ICONWARNING
				.else
					invoke DecodeAndSave, hWin, addr strBuffer
					.if decodingSuccess == 1
						invoke SetDlgItemText, hWin, IDC_PREVIEW, decodedBuf
						invoke MessageBox, 0, addr strFileSaved, addr strSuccess, MB_ICONINFORMATION
					.else
						invoke SetDlgItemText, hWin, IDC_PREVIEW, empty_str
					.endif
				.endif
			.endif
		.elseif	wParam == IDC_IDCANCEL
			invoke EndDialog,hWin,0
		.endif
	.elseif	uMsg == WM_CLOSE
		invoke	EndDialog,hWin,0
	.endif
	xor	eax,eax
	ret
DlgProc	endp

end start
