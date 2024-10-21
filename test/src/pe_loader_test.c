#include <stdio.h>
#include "build.h"
#include "c_types.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "random.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "epilogue.h"
#include "test.h"

static void* copyShellcode();

bool TestInitPELoader()
{
    // read PE image file
#ifdef _WIN64
    // FILE* file = fopen("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "rb");
    // FILE* file = fopen("C:\\Windows\\System32\\cmd.exe", "rb");
    // FILE* file = fopen("test_x64.exe", "rb");
    // FILE* file = fopen("E:\\Temp\\go_amd64.exe", "rb");
    // FILE* file = fopen("E:\\Temp\\rust_x64.exe", "rb");
    // FILE* file = fopen("testdata\\rust_x64.exe", "rb");
    FILE* file = fopen("testdata\\go_amd64.exe", "rb");
    // FILE* file = fopen("E:\\Temp\\hash.exe", "rb");
#elif _WIN32
    FILE* file = fopen("testdata\\go_386.exe", "rb");
    // FILE* file = fopen("testdata\\rust_x86.exe", "rb");
#endif
    if (file == NULL)
    {
        printf_s("failed to open test pe file\n");
        return false;
    }
    // get file size
    fseek(file, 0, SEEK_END);
    uint fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    // read file
#ifdef _WIN64
    uint64 hash = 0xB6A1D0D4A275D4B6;
    uint64 key  = 0x64CB4D66EC0BEFD9;
#elif _WIN32
    uint32 hash = 0xC3DE112E;
    uint32 key  = 0x8D9EA74F;
#endif
    VirtualAlloc_t virtualAlloc = FindAPI(hash, key);
    LPVOID addr = virtualAlloc(0, fileSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    byte* buf = (byte*)addr;
    uint n = fread(buf, fileSize, 1, file);
    if (n != 1)
    {
        printf_s("failed to read test pe file\n");
        return false;
    }
    fclose(file);

    Runtime_Opts opts = {
        .BootInstAddress     = NULL,
        .NotEraseInstruction = false,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
    runtime = InitRuntime(&opts);
    if (runtime == NULL)
    {
        printf_s("failed to initialize runtime: 0x%X\n", GetLastErrno());
        return false;
    }

    LPSTR  cmdLineA =  "loader.exe -p1 123 -p2 \"test\"";
    LPWSTR cmdLineW = L"loader.exe -p1 123 -p2 \"test\"";

    PELoader_Cfg cfg = {
    #ifdef NO_RUNTIME
        .FindAPI = &FindAPI,
    #else
        .FindAPI = runtime->HashAPI.FindAPI,
    #endif // NO_RUNTIME

        .Image        = buf,
        .CommandLineA = cmdLineA,
        .CommandLineW = cmdLineW,
        .StdInput     = NULL,
        .StdOutput    = NULL,
        .StdError     = NULL,
        .WaitMain     = false,

        .NotEraseInstruction = true,
        .NotAdjustProtect    = false,
    };
#ifdef SHELLCODE_MODE
    typedef PELoader_M* (*InitPELoader_t)(PELoader_Cfg* cfg);
    InitPELoader_t initPELoader = copyShellcode();
    pe_loader = initPELoader(&cfg);
#else
    pe_loader = InitPELoader(&cfg);
#endif // SHELLCODE_MODE
    if (pe_loader == NULL)
    {
        printf_s("failed to initialize PE loader: 0x%X\n", GetLastErrno());
        return false;
    }
    // erase PE image after initialize
    RandBuffer(buf, fileSize);
    return true;
}

bool TestPELoader_Execute()
{
    if (pe_loader == NULL)
    {
        return false;
    }

    uint exitCode = pe_loader->Execute();
    if (exitCode != 0)
    {
        printf_s("unexpected exit code: 0x%zX\n", exitCode);
        return false;
    }
    runtime->Thread.Sleep(5000);

    errno errno = pe_loader->Exit(0);
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit PE loader: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}

bool TestPELoader_Exit()
{
    if (pe_loader == NULL)
    {
        return false;
    }

    uint exitCode = pe_loader->Execute();
    if (exitCode != 0)
    {
        printf_s("unexpected exit code: 0x%zX\n", exitCode);
        return false;
    }
    runtime->Thread.Sleep(5000);

    errno errno = pe_loader->Exit(0);
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit PE loader: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}

bool TestPELoader_Destroy()
{
    if (pe_loader == NULL)
    {
        return false;
    }

    uint exitCode = pe_loader->Execute();
    if (exitCode != 0)
    {
        printf_s("unexpected exit code: 0x%zX\n", exitCode);
        return false;
    }
    runtime->Thread.Sleep(5000);

    errno errno = pe_loader->Destroy();
    if (errno != NO_ERROR)
    {
        printf_s("failed to destroy PE loader: 0x%X\n", GetLastErrno());
        return false;
    }

    errno = runtime->Core.Exit();
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit runtime: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}

static void* copyShellcode()
{
    VirtualAlloc_t VirtualAlloc = FindAPI_A("kernel32.dll", "VirtualAlloc");

    uintptr begin = (uintptr)(&InitPELoader);
    uintptr end   = (uintptr)(&Epilogue);
    uintptr size  = end - begin;
    void* mem = VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem == NULL)
    {
        printf_s("failed to allocate memory: 0x%X\n", GetLastErrno());
        return NULL;
    }
    mem_copy(mem, (void*)begin, size);
    printf_s("shellcode: 0x%zX\n", (uintptr)mem);
    return mem;
}
