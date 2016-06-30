.486
.MODEL FLAT, STDCALL
OPTION CASEMAP:NONE

OPTION PROC:PRIVATE	;<-----All Procedures of these modules are private unless otherwise stated

include decode.inc
include base.inc
include scandir.inc

.data
decodedNamePtr	dd	0
strNotFound db "Not Found",0
strDecodingFailed db "Decoding Failed!",0
strInvalidParams db "Invalid params!",0
filter_R5A db "*.R5A",0
filter_R4A db "*.R4A",0

.data?
hFind dd ?
foundFileBuf    WIN32_FIND_DATA   <>

.code

DecodeNextFile proc hWin:DWORD, filename:DWORD
	invoke DecodeAndSave, hWin, filename
	.if eax == 0
		invoke MessageBox, hWin, addr strDecodingFailed, filename, MB_ICONINFORMATION
	.else
		mov decodedNamePtr, eax
		invoke GetDlgItem,hWin, IDC_FILES_LIST
		invoke SendMessage,eax, LB_ADDSTRING, 0,  decodedNamePtr
	.endif
	Ret
DecodeNextFile EndP

ScanDir proc hWin:DWORD, algoId:DWORD, filter:DWORD
	invoke GetCurrentDirectory,512, addr currentDirBuf
	invoke SetDlgItemText, hWin, IDC_SCANNED_DIR, addr currentDirBuf
	
	;check current algo params
	invoke ValidateDecodeParams, algoId
	.if eax == 0
		invoke MessageBox, hWin, addr strInvalidParams, addr strTitle, MB_ICONWARNING
		xor eax,eax ;failed
		Ret
	.endif

	invoke FindFirstFile, filter, addr foundFileBuf
	.if eax == INVALID_HANDLE_VALUE
		;invoke MessageBox, hWin, addr strNotFound, addr strTitle, MB_ICONINFORMATION
		Ret
	.endif
	mov hFind,eax
	invoke DecodeNextFile,hWin, addr foundFileBuf.cFileName

	@find_next:
	invoke FindNextFile,hFind, addr foundFileBuf
	.if eax == 0
		Ret
	.endif
	invoke DecodeNextFile,hWin, addr foundFileBuf.cFileName

	jmp @find_next
	Ret
ScanDir EndP

ScanDlgProc proc PUBLIC hWin	:DWORD,
		uMsg	:DWORD,
		wParam	:DWORD,
		lParam	:DWORD
	.if uMsg == WM_INITDIALOG
		invoke LoadIcon, hInstance, favicon
		invoke SendMessage, hWin, WM_SETICON, 1, eax
		invoke GetCurrentDirectory,512, addr currentDirBuf
		invoke SetDlgItemText, hWin, IDC_SCANNED_DIR, addr currentDirBuf
	.endif
	.if	uMsg == WM_COMMAND
		.if	wParam == IDC_START_SCAN
			invoke ScanDir, hWin, alg_R4A, addr filter_R4A
			invoke ScanDir, hWin, alg_R5A, addr filter_R5A
       	.elseif	wParam == IDC_IDCANCEL
			invoke EndDialog,hWin,0
		.endif
	.elseif	uMsg == WM_CLOSE
		invoke	EndDialog,hWin,0
	.endif
	xor	eax,eax
	ret
ScanDlgProc	endp

End