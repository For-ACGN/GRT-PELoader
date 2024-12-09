#include <stdio.h>

int wmain(int argc, wchar_t* argv[])
{
    printf("argv[0]: %ls\n", argv[0]);
    if (argc > 1)
    {
        printf("argv[1]: %ls\n", argv[1]);
    }
}
