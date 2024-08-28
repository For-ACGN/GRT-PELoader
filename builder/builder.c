#include <stdio.h>
#include "c_types.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "boot.h"
#include "epilogue.h"

int saveShellcode();
int testShellcode();

int __cdecl main()
{
    int ret = saveShellcode();
    if (ret != 0)
    {
        return ret;
    }
    ret = testShellcode();
    if (ret != 0)
    {
        return ret;
    }
    printf_s("save shellcode successfully");
    return 0;
}

int saveShellcode()
{
#ifdef _WIN64
    FILE* file = fopen("../dist/PELoader_x64.bin", "wb");
#elif _WIN32
    FILE* file = fopen("../dist/PELoader_x86.bin", "wb");
#endif
    if (file == NULL)
    {
        printf_s("failed to create output file");
        return 1;
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
        return 2;
    }
    fclose(file);
    return 0;
}

int testShellcode()
{
    // TODO test
    return 0;

    errno errno = Boot();
    if (errno != NO_ERROR)
    {
        return errno;
    }
    return 0;
}
