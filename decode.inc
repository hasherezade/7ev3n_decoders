DecodeFileR4A	PROTO:DWORD, :DWORD
DecodeFileR5A	PROTO:DWORD, :DWORD, :DWORD,:DWORD

.const
alg_none equ -1
alg_R5A equ 1
alg_R4A equ 2

.data
R4A_ext db "R4A",0
R5A_ext db "R5A",0
empty_str db 0

;configuration:
need_orig_path db 0
need_unique_id db 1

;keys:
R4A_key  db "ifgj5906jHg948f8g46hgkf054k6h0igjf45n9g5fj90g64g5", 0
R5A_key db "777EJfngmfiob5mvX5i4omgfogkthmgA7Jergth3ng5m896h65", \
"f34f55gtiyht4jfkdfvb5iy76h544uekdfi5otjg5k0i6h595fjk4f4lkjho6", \
"kitf84j4uhyg7th53f854fpl567iogj5fk4Xf777", 0

.data?
fullOrigPath  db 512 dup (?)
uniqueId db 512 dup (?)


