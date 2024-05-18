#ifndef WINDOWS_T_H
#define WINDOWS_T_H

#include "go_types.h"

/* 
* Documents:
* https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
* https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
* https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
* https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
* https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary
* https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
* https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache
* https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
*/

#ifndef _WINDOWS_
#define _WINDOWS_

typedef byte*   LPCSTR;
typedef uintptr HMODULE;
typedef uint    HANDLE;

#define MEM_COMMIT  0x00001000
#define MEM_RESERVE 0x00002000
#define MEM_RELEASE 0x00008000

#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80

#endif // _WINDOWS_

#define PE_FILE_HEADER_SIZE      24
#define PE_OPT_HEADER_SIZE_64    240
#define PE_OPT_HEADER_SIZE_32    224
#define PE_SECTION_HEADER_SIZE   40
#define PE_DATA_DIRECTORY_SIZE   8
#define PE_IMPORT_DIRECTORY_SIZE 20

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000

#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGHLOW  3 
#define IMAGE_REL_BASED_DIR64    10

typedef struct {
    uint32 VirtualAddress;
    uint32 SizeOfBlock;
} PE_ImageBaseRelocation;

typedef struct {
    uint32 OriginalFirstThunk;
    uint32 TimeDateStamp;
    uint32 ForwarderChain;
    uint32 Name;
    uint32 FirstThunk;
} PE_ImportDirectory;

typedef uintptr (*VirtualAlloc_t)
(
    uintptr lpAddress, uint dwSize, uint32 flAllocationType, uint32 flProtect
);

typedef bool (*VirtualFree_t)
(
    uintptr lpAddress, uint dwSize, uint32 dwFreeType
);

typedef bool (*VirtualProtect_t)
(
    uintptr lpAddress, uint dwSize, uint32 flNewProtect, uint32* lpflOldProtect
);

typedef HMODULE (*LoadLibraryA_t)
(
    LPCSTR lpLibFileName
);

typedef bool (*FreeLibrary_t)
(
    HMODULE hLibModule
);

typedef uintptr (*GetProcAddress_t)
(
    HMODULE hModule, LPCSTR lpProcName
);

typedef bool (*FlushInstructionCache_t)
(
    HANDLE hProcess, uintptr lpBaseAddress, uint dwSize
);

typedef HANDLE (*CreateThread_t)
(
    uintptr lpThreadAttributes, uint dwStackSize, uintptr lpStartAddress,
    uintptr lpParameter, uint32 dwCreationFlags, uint32* lpThreadId
);

#endif // WINDOWS_T_H
