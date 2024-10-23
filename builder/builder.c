#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "errno.h"
#include "boot.h"
#include "pe_loader.h"
#include "runtime.h"

// NOT using stdio is to ensure that no runtime instructions
// are introduced to avoid compiler optimization link errors
// that cause the extracted shellcode to contain incorrect
// relative/absolute memory addresses.

static LoadLibraryA_t LoadLibraryA;
static FreeLibrary_t  FreeLibrary;
static CreateFileA_t  CreateFileA;
static WriteFile_t    WriteFile;
static CloseHandle_t  CloseHandle;

typedef int (*printf_s_t)(const char* format, ...);
static printf_s_t printf_s;

bool saveShellcode();
bool testShellcode();

static void init()
{
    LoadLibraryA = FindAPI_A("kernel32.dll", "LoadLibraryA");
    FreeLibrary  = FindAPI_A("kernel32.dll", "FreeLibrary");
    CreateFileA  = FindAPI_A("kernel32.dll", "CreateFileA");
    WriteFile    = FindAPI_A("kernel32.dll", "WriteFile");
    CloseHandle  = FindAPI_A("kernel32.dll", "CloseHandle");

    HMODULE hModule = LoadLibraryA("msvcrt.dll");
    if (hModule == NULL)
    {
        return;
    }
    printf_s = FindAPI_A("msvcrt.dll", "printf_s");
}

#pragma comment(linker, "/ENTRY:EntryPoint")
int EntryPoint()
{
    init();
    if (!saveShellcode())
    {
        return 1;
    }
    if (!testShellcode())
    {
        return 2;
    }
    printf_s("build shellcode successfully\n");
    return 0;
}

bool saveShellcode()
{
    uintptr begin = (uintptr)(&Boot);
    uintptr end   = (uintptr)(&Argument_Stub);
    uintptr size  = end - begin;

    // check runtime option stub is valid
    end -= OPTION_STUB_SIZE;
    if (*(byte*)end != OPTION_STUB_MAGIC)
    {
        printf_s("invalid runtime option stub\n");
        return false;
    }
    for (uintptr i = 0; i < OPTION_STUB_SIZE - 1; i++)
    {
        end++;
        if (*(byte*)(end) != 0x00)
        {
            printf_s("invalid runtime option stub\n");
            return false;
        }
    }

    // extract shellcode and save to file
#ifdef _WIN64
    LPSTR path = "../dist/PELoader_x64.bin";
#elif _WIN32
    LPSTR path = "../dist/PELoader_x86.bin";
#endif
    HANDLE hFile = CreateFileA(
        path, GENERIC_WRITE, 0, NULL, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf_s("failed to create output file: 0x%X\n", GetLastErrno());
        return false;
    }
    if (!WriteFile(hFile, (byte*)begin, (DWORD)size, NULL, NULL))
    {
        printf_s("failed to write shellcode: 0x%X\n", GetLastErrno());
        return false;
    }
    if (!CloseHandle(hFile))
    {
        printf_s("failed to close file: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}

bool testShellcode()
{
    errno errno = Boot();
    if (errno != ERR_INVALID_LOAD_MODE)
    {
        printf_s("unexpected boot errno: 0x%X\n", errno);
        return false;
    }
    return true;
}
