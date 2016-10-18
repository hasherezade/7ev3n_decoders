DecodeFileR4A	PROTO:DWORD, :DWORD
DecodeFileR5A	PROTO:DWORD, :DWORD, :DWORD, :DWORD, :DWORD

.const
alg_none equ -1
alg_R5A equ 1
alg_R4A equ 2

.data
R4A_ext db "R4A",0
R5A_ext db "R5A",0
empty_str db 0

;configuration:
need_orig_path db 1
need_unique_id db 1

;keys:
R4A_key  db "ANOASudgfjfirtj4k504iojm5io5nm59uh5vob5mho5p6gf2u43i5hojg4mf4i05j6g594cn9mjg6h", 0
R5A_key db "ASIBVbhciJ5hv6bjyuwetjykok7mbvtbvtiJ5h6jg54ifj0655iJ5hok7mbok7mbvtvtv6bjfib56j", \
"45fkmbvtiJ5hv6bokok7mbvt7mbvtj55nf4y8uhmvbi7knd4ium6iok7mbvtiiJ5hv6bjJ5hhigmubn56gfiok7mb", \
"vtjnmvu9bvtiJ5h6biok7mbvt7mbgi5fmuv65mg9fi4dm5v6iognfun5u6inguifbv5ibomlimmhnbjvfchbgnhug", \
"k5ybvtc3cty5", 0


.data?
fullOrigPath  db 512 dup (?)
uniqueId db 1024 dup (?)
processedId db 1024 dup (?)

