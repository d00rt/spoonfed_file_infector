;-----------------------------data types----------------------------------
%define BYTE                    1     ; byte
%define WORD                    2     ; word
%define DWORD                   4     ; dword
%define QWORD                   8     ; qword
%define ACHAR                   BYTE  ;ansi character
%define ATOM                    DWORD ;string atom
%define BOOL                    DWORD ;boolean variable
%define COLORREF                DWORD ;rgb color
%define DWORDLONG               QWORD ;long double word
%define GLOBALHANDLE            DWORD ;global handle
%define HACCEL                  DWORD ;accelerator handle
%define HANDLE                  DWORD ;unspecified handle
%define HBITMAP                 DWORD ;bitmap handle
%define HBRUSH                  DWORD ;brush handle
%define HCOLORSPACE             DWORD ;color space handle
%define HCURSOR                 DWORD ;cursor handle
%define HDC                     DWORD ;device context handle
%define HDWP                    DWORD ;defer win pos handle
%define HENHMETAFILE            DWORD ;enh. metafile handle
%define HFILE                   DWORD ;file handle
%define HFONT                   DWORD ;font handle
%define HGLOBAL                 DWORD ;global handle
%define HHOOK                   DWORD ;hook handle
%define HICON                   DWORD ;icon handle
%define HINSTANCE               DWORD ;instance handle
%define HINTERNET               DWORD ;internet handle
%define HLOCAL                  DWORD ;local handle
%define HMENU                   DWORD ;menu handle
%define HMETAFILE               DWORD ;metafile handle
%define HPALETTE                DWORD ;palette handle
%define HPEN                    DWORD ;pen handle
%define HRGN                    DWORD ;region handle
%define HRSRC                   DWORD ;resource handle
%define HSTR                    DWORD ;string handle
%define HTASK                   DWORD ;task handle
%define HTREEITEM               DWORD ;tree view item handle
%define HWND                    DWORD ;window handle
%define INTEGER                 DWORD ;standard integer
%define LOCALHANDLE             DWORD ;local handle
%define LONG                    DWORD ;long integer
%define LONGINT                 DWORD ;long integer
%define LPARAM                  DWORD ;long parameter
%define LPBOOL                  DWORD ;long ptr to boolean
%define LPBYTE                  DWORD ;long ptr to byte
%define LPCSTR                  DWORD ;long ptr to string
%define LPCTSTR                 DWORD ;long ptr to string
%define LPCVOID                 DWORD ;long ptr to buffer
%define LPDWORD                 DWORD ;long ptr to dword
%define LPFN                    DWORD ;long ptr to function
%define LPINT                   DWORD ;long ptr to integer
%define LPLONG                  DWORD ;long ptr to long int
%define LPMSG                   DWORD ;long pointer to message
%define LPPAINTSTRUCT           DWORD ;long pointer to paint structure
%define LPRECT                  DWORD ;long pointer to rectangle
%define LPSTR                   DWORD ;long ptr to string
%define LPTSTR                  DWORD ;long ptr to string
%define LPVOID                  DWORD ;long ptr to buffer
%define LPWORD                  DWORD ;long ptr to word
%define LRESULT                 DWORD ;long result
%define POINTER                 DWORD ;pointer to anything
%define PVOID                   DWORD ;pointer to buffer
%define SHORTINT                WORD  ;short integer
%define UINT                    DWORD ;unsigned integer
%define WCHAR                   WORD  ;unicode character
%define WNDPROC                 DWORD ;window procedure
%define WPARAM                  DWORD ;word parameter

;---------------------constants definitions-----------------------------------
MAX_PATH equ 32

;---------------------structure definitions-----------------------------------
STRUC PEB_PROCESS_ENVIRONMENT_BLOCK
.InheritedAddressSpace          RESB 1
.ReadImageFileExecOptions       RESB 1
.BeingDebugged                  RESB 1
.SpareBool                      RESB 1
.Mutant                         RESD 1
.ImageBaseAddress               RESD 1
.Ldr                            RESD 1
.ProcessParameters              RESD 1
.SubSystemData                  RESD 1
.ProcessHeap                    RESD 1
.FastPebLock                    RESD 1
.FastPebLockRoutine             RESD 1
.FastPebUnlockRoutine           RESD 1
.EnvironmentUpdateCount         RESD 1
.KernelCallbackTable            RESD 1
.SystemReserved1                RESD 1
.ExecuteOptions_SpareBits       RESD 1
.FreeList                       RESD 1
.TlsExpansionCounter            RESD 1
.TlsBitmap                      RESD 1
.TlsBitmapBits2                 RESD 2
.ReadOnlySharedMemoryBase       RESD 1
.ReadOnlySharedMemoryHeap       RESD 1
.ReadOnlyStaticServerData       RESD 1
.AnsiCodePageData               RESD 1
.OemCodePageData                RESD 1
.UnicodeCaseTableData           RESD 1
.NumberOfProcessors             RESD 1
.NtGlobalFlag                   RESD 1
.CriticalSectionTimeout         RESD 2
.HeapSegmentReserve             RESD 1
.HeapSegmentCommit              RESD 1
.HeapDeCommitTotalFreeThreshold RESD 1
.HeapDeCommitFreeBlockThreshold RESD 1
.NumberOfHeaps                  RESD 1
.MaximumNumberOfHeaps           RESD 1
.ProcessHeaps                   RESD 1
.GdiSharedHandleTable           RESD 1
.ProcessStarterHelper           RESD 1
.GdiDCAttributeList             RESD 1
.LoaderLock                     RESD 1
.OSMajorVersion                 RESD 1
.OSMinorVersion                 RESD 1
.OSBuildNumber                  RESW 1
.OSCSDVersion                   RESW 1
.OSPlatformId                   RESD 1
.ImageSubsystem                 RESD 1
.ImageSubsystemMajorVersion     RESD 1
.ImageSubsystemMinorVersion     RESD 1
.ImageProcessAffinityMask       RESD 1
.GdiHandleBuffer34              RESD 34
.PostProcessInitRoutine         RESD 1
.TlsExpansionBitmap             RESD 1
.TlsExpansionBitmapBits32       RESD 32
.SessionId                      RESD 1
.AppCompatFlags                 RESD 2
.AppCompatFlagsUser             RESD 2
.pShimData                      RESD 1
.AppCompatInfo                  RESD 1
.CSDVersion                     RESD 2
.ActivationContextData          RESD 1
.ProcessAssemblyStorageMap      RESD 1
.SystemDefaultActivationContextData		RESD 1
.SystemAssemblyStorageMap       RESD 1
.MinimumStackCommit             RESD 1
ENDSTRUC

STRUC _PEB_LDR_DATA
.Length                         RESD 1                                  ; Size of structure, used by ntdll.dll as structure version ID
.Initialized                    RESD 1                                  ; If set, loader data section for current process is initialized
.SsHandle                       RESD 1
.InLoadOrderModuleListNext      RESD 1                                  ; Pointer to LDR_DATA_TABLE_ENTRY/LDR_MODULE structure. Previous and next module in load order
.InLoadOrderModuleListPrev      RESD 1 
.InMemoryOrderModuleListNext    RESD 1                                  ; Pointer to LDR_DATA_TABLE_ENTRY/LDR_MODULE structure. Previous and next module in memory placement order 
.InMemoryOrderModuleListPrev    RESD 1
.InInitializationOrderModuleListNext	RESD 1                          ; Pointer to LDR_DATA_TABLE_ENTRY/LDR_MODULE structure. Previous and next module in initialization order
.InInitializationOrderModuleListPrev	RESD 1
ENDSTRUC

STRUC LDR_MODULE
.InLoadOrderModuleListNext      RESD 1                                  ; Pointer to LDR_DATA_TABLE_ENTRY/LDR_MODULE structure. Previous and next module in load order
.InLoadOrderModuleListPrev      RESD 1 
.InMemoryOrderModuleListNext    RESD 1                                  ; Pointer to LDR_DATA_TABLE_ENTRY/LDR_MODULE structure. Previous and next module in memory placement order 
.InMemoryOrderModuleListPrev    RESD 1
.InInitializationOrderModuleListNext	RESD 1                          ; Pointer to LDR_DATA_TABLE_ENTRY/LDR_MODULE structure. Previous and next module in initialization order
.InInitializationOrderModuleListPrev	RESD 1
.DllBase 						RESD 1
.EntryPoint 					RESD 1
.Reserverd 						RESD 1
.FullDllNameLength				RESW 1						            ; Names in UNICODE format
.FullDllNameMaxLength		    RESW 1						            ; Names in UNICODE format
.FullDllNamePointer			    RESD 1						            ; Names in UNICODE format
.BaseDllNameLength				RESW 1						            ; Names in UNICODE format
.BaseDllNameMaxLength		    RESW 1						            ; Names in UNICODE format
.BaseDllNamePointer			    RESD 1						            ; Names in UNICODE format
ENDSTRUC

STRUC IMAGE_FILE_HEADER
.Signature                      RESD 1
.Machine                        RESW 1
.NumberOfSections               RESW 1
.TimeDateStamp                  RESD 1
.PointerToSymbolTable           RESD 1
.NumberOfSymbols                RESD 1
.SizeOfOptionalHeader           RESW 1
.Characteristics                RESW 1
ENDSTRUC

STRUC IMAGE_EXPORT_DIRECTORY
.Characteristics                RESD 1
.TimeDateStamp                  RESD 1
.MajorVersion                   RESW 1
.MinorVersion                   RESW 1
.nName                          RESD 1
.nBase                          RESD 1
.NumberOfFunctions              RESD 1
.NumberOfNames                  RESD 1
.AddressOfFunctions             RESD 1
.AddressOfNames                 RESD 1
.AddressOfNameOrdinals          RESW 1
ENDSTRUC

STRUC IMAGE_DOS_HEADER
.e_magic                        RESW 1
.e_cblp                         RESW 1
.e_cp                           RESW 1
.e_crlc                         RESW 1
.e_cparhdr                      RESW 1
.e_minalloc                     RESW 1
.e_maxalloc                     RESW 1
.e_ss                           RESW 1
.e_sp                           RESW 1
.e_csum                         RESW 1
.e_ip                           RESW 1
.e_cs                           RESW 1
.e_lfarlc                       RESW 1
.e_ovno                         RESW 1
.e_res4                         RESW 4
.e_oemid                        RESW 1
.e_oeminfo                      RESW 1
.e_res2                         RESW 10
.e_lfanew                       RESD 1
ENDSTRUC

STRUC IMAGE_DATA_DIRECTORY
.VirtualAddress                 RESD 1
.isize                          RESD 1
ENDSTRUC

STRUC IMAGE_OPTIONAL_HEADER
.Magic                          RESW 1
.MajorLinkerVersion             RESB 1
.MinorLinkerVersion             RESB 1
.SizeOfCode                     RESD 1
.SizeOfInitializedData          RESD 1
.SizeOfUninitializedData        RESD 1
.AddressOfEntryPoint            RESD 1
.BaseOfCode                     RESD 1
.BaseOfData                     RESD 1
.ImageBase                      RESD 1
.SectionAlignment               RESD 1
.FileAlignment                  RESD 1
.MajorOperatingSystemVersion    RESW 1
.MinorOperatingSystemVersion    RESW 1
.MajorImageVersion              RESW 1
.MinorImageVersion              RESW 1
.MajorSubsystemVersion          RESW 1
.MinorSubsystemVersion          RESW 1
.Reserved1                      RESD 1
.SizeOfImage                    RESD 1
.SizeOfHeaders                  RESD 1
.CheckSum                       RESD 1
.Subsystem                      RESW 1
.DllCharacteristics             RESW 1
.SizeOfStackReserve             RESD 1
.SizeOfStackCommit              RESD 1
.SizeOfHeapReserve              RESD 1
.SizeOfHeapCommit               RESD 1
.LoaderFlags                    RESD 1
.NumberOfRvaAndSizes            RESD 1
.ExportDirectory                RESB IMAGE_DATA_DIRECTORY_size       ; The following is a list of the data directories. 
.ImportDirectory                RESB IMAGE_DATA_DIRECTORY_size       ; Offsets are relative to the beginning of the optional header.
.ResourceDirectory              RESB IMAGE_DATA_DIRECTORY_size
.ExceptionDirectory             RESB IMAGE_DATA_DIRECTORY_size
.SecurityDirectory              RESB IMAGE_DATA_DIRECTORY_size
.BaseRelocationTable            RESB IMAGE_DATA_DIRECTORY_size
.DebugDirectory                 RESB IMAGE_DATA_DIRECTORY_size
.ArchitectureSpecificData       RESB IMAGE_DATA_DIRECTORY_size
.RVAofGP                        RESB IMAGE_DATA_DIRECTORY_size
.TLSDirectory                   RESB IMAGE_DATA_DIRECTORY_size
.LoadConfigurationDirectory     RESB IMAGE_DATA_DIRECTORY_size
.BoundImportDirectoryinheaders  RESB IMAGE_DATA_DIRECTORY_size
.ImportAddressTable             RESB IMAGE_DATA_DIRECTORY_size
.DelayLoadImportDescriptors     RESB IMAGE_DATA_DIRECTORY_size
.COMRuntimedescriptor           RESB IMAGE_DATA_DIRECTORY_size
.ArrayEnd                       RESB IMAGE_DATA_DIRECTORY_size
ENDSTRUC

STRUC FILETIME
.dwLowDateTime                  RESD 1
.dwHighDateTime                 RESD 1
ENDSTRUC

STRUC WIN32_FIND_DATA
.dwFileAttributes               RESD 1
.ftCreationTime                 RESB FILETIME_size
.ftLastAccessTime               RESB FILETIME_size
.ftLastWriteTime                RESB FILETIME_size
.nFileSizeHigh                  RESD 1
.nFileSizeLow                   RESD 1
.dwReserved0                    RESD 1
.dwReserved1                    RESD 1
.cFileName                      RESB MAX_PATH
.cAlternate                     RESB 14 
ENDSTRUC

STRUC SECTION_HEADER
.Name                           RESB 8
.VirtualSize                    RESD 1
.VirtualAddress                 RESD 1
.SizeOfRawData                  RESD 1
.PointerToRawData               RESD 1
.PointerToRelocations           RESD 1
.PointerToLineNumbers           RESD 1
.NumberOfRelocations            RESW 1
.NumberOfLineNumbers            RESW 1
.Characteristics                RESD 1
ENDSTRUC
