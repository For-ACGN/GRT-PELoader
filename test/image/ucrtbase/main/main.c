#include <stdio.h>

__declspec(thread) int tls_var = 0x1234;

int main(int argc, char* argv[])
{
    printf("argv[0]: %s\n", argv[0]);
    if (argc > 1) 
    {
        printf("argv[1]: %s\n", argv[1]);
    }

    tls_var++;
    if (tls_var != 0x1235)
    {
        printf("tls: %d\n", tls_var);
        return 1;
    }
    return 0;
}
