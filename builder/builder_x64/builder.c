// #include <windows.h>
// #include <stdio.h>
#include "c_types.h"
#include "hash_api.h"
#include "runtime.h"
#include "pe_shelter.h"


#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain() 
{
    // HANDLE hFile = CreateFileA("E:\\Temp\\go_amd64.exe", GENERIC_READ, 0, NULL, OPEN_ALWAYS, 0, NULL);
    // if (hFile == INVALID_HANDLE_VALUE)
    // {
    //     return -1;
    // }
    // DWORD dwSize = GetFileSize(hFile, 0);
    // LPVOID lpAddress = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    // if (lpAddress == NULL)
    // {
    //     CloseHandle(hFile);
    //     return -1;
    // }
    // DWORD dwRead;
    // if (!ReadFile(hFile, lpAddress, dwSize, &dwRead, 0))
    // {
    //     CloseHandle(hFile);
    //     return -1;
    // }
    // 

    Runtime_M* runtime = InitRuntime(NULL);

    uint           lpAddress = 0;
    PEShelter_Opts options = {
        .FindAPI        = runtime->FindAPI,
        .GetProcAddress = runtime->GetProcAddress,
    };
    uintptr entry = LoadPE((uintptr)lpAddress, &options);

    Epilogue();


    return entry;
}
