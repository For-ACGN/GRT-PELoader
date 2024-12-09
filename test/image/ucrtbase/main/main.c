#include <stdio.h>

int main(int argc, char* argv[])
{
    printf("argv[0]: %s\n", argv[0]);
    if (argc > 1) 
    {
        printf("argv[1]: %s\n", argv[1]);
    }
}
