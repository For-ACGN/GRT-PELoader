#include <stdio.h>
#include "c_types.h"
#include "hash_api.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "boot.h"
#include "epilogue.h"

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
    printf_s("save shellcode successfully\n");
    return 0;
}

bool saveShellcode()
{
    uintptr begin = (uintptr)(&Boot);
    uintptr end   = (uintptr)(&Argument_Stub);
    uintptr size  = end - begin;

    // check option stub is valid
    end -= OPTION_STUB_SIZE;
    if (*(byte*)end != 0xFC)
    {
        printf_s("invalid runtime option stub\n");
        return false;
    }

    // conut 0xFF for check the shellcode tail is valid
    uint num0xFF = 0;
    for (int i = 0; i < 16; i++)
    {
        end--;
        if (*(byte*)end != 0xFF)
        {
            break;
        }
        num0xFF++;
    }
    if (num0xFF != 16)
    {
        printf_s("invalid shellcode tail\n");
        return false;
    }

    // write shellcode
#ifdef _WIN64
    FILE* file = fopen("../dist/PELoader_x64.bin", "wb");
#elif _WIN32
    FILE* file = fopen("../dist/PELoader_x86.bin", "wb");
#endif
    if (file == NULL)
    {
        printf_s("failed to create shellcode output file\n");
        return false;
    }
    size_t n = fwrite((byte*)begin, (size_t)size, 1, file);
    if (n != 1)
    {
        printf_s("failed to save shellcode\n");
        return false;
    }
    fclose(file);
    return true;
}

bool testShellcode()
{
    errno errno = Boot();
    if (errno != ERR_LOADER_PARSE_PE_IMAGE)
    {
        printf_s("unexpected boot errno: 0x%X\n", errno);
        return false;
    }
    return true;
}
