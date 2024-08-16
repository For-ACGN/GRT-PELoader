#ifndef WINDOWS_T_H
#define WINDOWS_T_H

#include "c_types.h"

typedef uint8  BYTE;
typedef uint16 WORD;
typedef uint32 DWORD;
typedef uint64 QWORD;

typedef int8  CHAR;
typedef int16 SHORT;
typedef int32 LONG;
typedef int64 LONGLONG;

typedef uint UINT;
typedef bool BOOL;
typedef uint SIZE_T;

typedef void* POINTER;
typedef void* HMODULE;
typedef void* HANDLE;
typedef void* FARPROC;

typedef void*   LPVOID;
typedef uint8*  LPSTR;
typedef uint16* LPWSTR;
typedef HANDLE* LPHANDLE;

typedef const void*   LPCVOID;
typedef const uint8*  LPCSTR;
typedef const uint16* LPCWSTR;

#define CURRENT_PROCESS (HANDLE)(-1)

#define MEM_COMMIT  0x00001000
#define MEM_RESERVE 0x00002000
#define MEM_RELEASE 0x00008000

#define PAGE_NOACCESS          0x00000001
#define PAGE_READONLY          0x00000002
#define PAGE_READWRITE         0x00000004
#define PAGE_WRITECOPY         0x00000008
#define PAGE_EXECUTE           0x00000010
#define PAGE_EXECUTE_READ      0x00000020
#define PAGE_EXECUTE_READWRITE 0x00000040
#define PAGE_EXECUTE_WRITECOPY 0x00000080

#define INFINITE      0xFFFFFFFF
#define WAIT_OBJECT_0 0x00000000
#define WAIT_TIMEOUT  0x00000102
#define WAIT_FAILED   0xFFFFFFFF

#define MAX_PATH 260

#define PE_FILE_HEADER_SIZE      24
#define PE_OPT_HEADER_SIZE_64    240
#define PE_OPT_HEADER_SIZE_32    224
#define PE_SECTION_HEADER_SIZE   40
#define PE_DATA_DIRECTORY_SIZE   8
#define PE_IMPORT_DIRECTORY_SIZE 20

#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_DLL              0x2000

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000

#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGHLOW  3 
#define IMAGE_REL_BASED_DIR64    10

#define DLL_PROCESS_ATTACH 1
#define DLL_PROCESS_DETACH 0
#define DLL_THREAD_ATTACH  2
#define DLL_THREAD_DETACH  3

typedef struct {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
} PE_ImageBaseRelocation;

typedef struct {
    DWORD OriginalFirstThunk;
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} PE_ImportDirectory;

typedef BOOL (*DllMain_t)
(
    HMODULE hModule, DWORD dwReason, LPVOID lpReserved
);

typedef HMODULE (*LoadLibraryA_t)
(
    LPCSTR lpLibFileName
);

typedef FARPROC (*GetProcAddress_t)
(
    HMODULE hModule, LPCSTR lpProcName
);

typedef LPVOID (*VirtualAlloc_t)
(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect
);

typedef BOOL (*VirtualFree_t)
(
    LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType
);

typedef BOOL (*VirtualProtect_t)
(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect
);

typedef HANDLE (*CreateThread_t)
(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId
);

typedef BOOL (*FlushInstructionCache_t)
(
    HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize
);

typedef HANDLE (*CreateMutexA_t)
(
    POINTER lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName
);

typedef BOOL (*ReleaseMutex_t)
(
    HANDLE hMutex
);

typedef DWORD (*WaitForSingleObject_t)
(
    HANDLE hHandle, DWORD dwMilliseconds
);

typedef BOOL (*CloseHandle_t)
(
    HANDLE hObject
);

typedef LPSTR (*GetCommandLineA_t)();

typedef LPWSTR (*GetCommandLineW_t)();

typedef void (*ExitProcess_t)
(
    UINT uExitCode
);

#endif // WINDOWS_T_H
