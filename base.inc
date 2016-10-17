include	windows.inc

uselib	MACRO	libname
	include		libname.inc
	includelib	libname.lib
ENDM

uselib	user32
uselib	kernel32
uselib	comdlg32
uselib	msvcrt

DlgProc		PROTO :DWORD,:DWORD,:DWORD,:DWORD
TestFile		PROTO:DWORD
FindSuffix	PROTO:DWORD,:DWORD
DecodeName	PROTO:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetAlgorithmId PROTO:DWORD
CStrLen		PROTO:DWORD,:DWORD
DecodeAndSave PROTO:DWORD, :DWORD

ReadOriginalFilename PROTO
MapFile PROTO :DWORD
FreeFileHandles PROTO

ValidateDecodeParams PROTO:DWORD

IDD_MAIN_WIN	equ 101
IDD_SCAN_DIR	equ 102

IDC_OPEN 			equ	1000
IDC_DECODE 			equ	1001
IDC_DECODE_ALL 			equ	1044
IDC_OK 			equ	1003
IDC_IDCANCEL 	equ	1004
IDC_EDITBOX		equ 200
IDC_EDITBOX2	equ 201
IDC_ALG_ID		equ 1013
ID_R5AKEY_FILE	equ 1015
IDC_OPEN_R5AKEY equ 1017
IDC_PREVIEW		equ 1018

ID_ORIGINAL_DIR	equ 1010
ID_UNIQUE	equ 1034

IDC_UNIQE_LABEL equ 1026 
IDC_ORIGINAL_DIR_LABEL equ 1033 

IDC_CREATE_R5AKEY	equ 1030
IDC_IS_OLD equ 1007

.const
favicon equ 10

.data
strFilter db "7ev3n encrypted files (*.R5A, *.R4A)" , 0, "*.R5A;*.R4A",0, "All files", 0, "*", 0, 0
r5kFilter db "R5A key (*.bin, *.key)" , 0, "*.bin;*.key",0, "All files", 0, "*", 0, 0
strTitle db "7ev3n decoder", 0

decodingSuccess dd 0

.data?
openFileBuf    OPENFILENAME   <>
;foundFileBuf    WIN32_FIND_DATA   <>
fileHandle dd ? 
hInstance		dd		?	;dd can be written as dword
strBuffer	db	MAX_PATH	dup (?)
decodedName	db	MAX_PATH	dup (?)
originalPath db MAX_PATH dup (?)
currentDirBuf db MAX_PATH dup (?)
