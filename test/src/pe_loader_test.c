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

    // read PE image file
#ifdef _WIN64
    LPSTR file = "testdata\\go_amd64.exe";
    // LPSTR file = "testdata\\rust_x64.exe";
    // LPSTR file = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe";
    // LPSTR file = "C:\\Windows\\System32\\cmd.exe";
    // LPSTR file = "E:\\Temp\\go_amd64.exe";
    // LPSTR file = "E:\\Temp\\rust_x64.exe";
    // LPSTR file = "E:\\Temp\\hash.exe";
#elif _WIN32
    LPSTR file = "testdata\\go_386.exe";
    // LPSTR file = "testdata\\rust_x86.exe";
#endif
    byte* buf; uint size;
    errno err = runtime->WinFile.ReadFileA(file, &buf, &size);
    if (err != NO_ERROR)
    {
        printf_s("failed to open test pe file: 0x%X\n", err);
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
        .WaitMain     = true,

        .NotEraseInstruction = true,
        .NotAdjustProtect    = false,
    };
#ifdef SHELLCODE_MODE
    typedef PELoader_M* (*InitPELoader_t)(Runtime_M* runtime, PELoader_Cfg* cfg);
    InitPELoader_t initPELoader = copyShellcode();
    pe_loader = initPELoader(runtime, &cfg);
#else
    pe_loader = InitPELoader(runtime, &cfg);
#endif // SHELLCODE_MODE
    if (pe_loader == NULL)
    {
        printf_s("failed to initialize PE loader: 0x%X\n", GetLastErrno());
        return false;
    }
    // erase PE image after initialize
    RandBuffer(buf, size);
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
