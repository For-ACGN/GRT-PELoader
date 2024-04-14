#include <stdio.h>
#include <windows.h>

#include "go_types.h"
#include "hash_api.h"
#include "pe_shelter.h"

#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain() 
{
    HANDLE hFile = CreateFileA("D:\\hash.exe", GENERIC_READ, 0, NULL, OPEN_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return -1;
    }
    DWORD dwSize;
    dwSize = GetFileSize(hFile, 0);

    LPVOID lpAddress = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpAddress == NULL)
    {
        CloseHandle(hFile);
        return -1;
    }
    DWORD dwRead;
    if (!ReadFile(hFile, lpAddress, dwSize, &dwRead, 0))
    {
        CloseHandle(hFile);
        return -1;
    }


    PEShelterCtx context = {
        .FindAPI  = FindAPI,
        .Hooks    = NULL,
        .NumHooks = 1,
    };
    uintptr entry = LoadPE(&context, lpAddress, dwSize);
    return entry;
}
