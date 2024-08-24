#include <stdio.h>
#include "c_types.h"
#include "hash_api.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "test.h"

bool TestInitPELoader()
{
    // read PE file
#ifdef _WIN64
    FILE* file = fopen("testdata\\go_amd64.exe", "rb"); 
#elif _WIN32
    FILE* file = fopen("testdata\\go_386.exe", "rb");
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
    Runtime_M* runtime = InitRuntime(&opts);
    if (runtime == NULL)
    {
        printf_s("failed to initialize runtime: 0x%lX\n", GetLastErrno());
        return false;
    }

    LPSTR cmdLine = "loader.exe -p1 123 -p2 \"test\"";

    PELoader_Cfg cfg = {
        .Image       = buf,
        .CommandLine = cmdLine,
        .StdInput    = NULL,
        .StdOutput   = NULL,
        .StdError    = NULL,
        .WaitMain    = true,

        .FindAPI       = FindAPI, // runtime->FindAPI
        .AdjustProtect = true,
    };
    pe_loader = InitPELoader(&cfg);
    if (pe_loader == NULL)
    {
        printf_s("failed to initialize PE loader: 0x%lX\n", GetLastErrno());
        return false;
    }
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
    return true;
}

bool TestPELoader_Exit()
{
    if (pe_loader == NULL)
    {
        return false;
    }

    errno errno = pe_loader->Exit();
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit PE loader: 0x%lX\n", GetLastErrno());
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

    errno errno = pe_loader->Destroy();
    if (errno != NO_ERROR)
    {
        printf_s("failed to destroy PE loader: 0x%lX\n", GetLastErrno());
        return false;
    }
    return true;
}
