#include <stdio.h>
#include "c_types.h"
#include "hash_api.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "boot.h"
#include "epilogue.h"

// reference from Gleam-RT/include/errno.h 
#define ERR_ARGUMENT_CHECKSUM (0x06000005)

bool saveShellcode();
bool testShellcode();

int __cdecl main()
{
    if (!saveShellcode())
    {
        return 1;
    }
    if (!testShellcode())
    {
        return 2;
    }
    printf_s("save shellcode successfully");
    return 0;
}

bool saveShellcode()
{
#ifdef _WIN64
    FILE* file = fopen("../dist/PELoader_x64.bin", "wb");
#elif _WIN32
    FILE* file = fopen("../dist/PELoader_x86.bin", "wb");
#endif
    if (file == NULL)
    {
        printf_s("failed to create shellcode output file");
        return false;
    }
    uintptr begin = (uintptr)(&Boot);
    uintptr end   = (uintptr)(&Epilogue);
    uintptr size  = end - begin;
    // skip 0xCC instructions at the tail
    uint num0xCC = 0;
    for (;;)
    {
        end--;
        if (*(byte*)end != 0xCC)
        {
            break;
        }
        num0xCC++;
    }
    size -= num0xCC;
    // write shellcode
    size_t n = fwrite((byte*)begin, (size_t)size, 1, file);
    if (n != 1)
    {
        printf_s("failed to save shellcode");
        return false;
    }
    fclose(file);
    return true;
}

bool testShellcode()
{
    // adjust memory protect to RWX
    errno errno = Boot();
    if (errno != ERR_ARGUMENT_CHECKSUM)
    {
        printf_s("unexpected errno: 0x%lX\n", errno);
        return false;
    }
    return true;
}
