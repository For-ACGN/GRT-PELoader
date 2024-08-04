#ifndef PE_LOADER_H
#define PE_LOADER_H

#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"

typedef uint (*Execute_t)();

typedef struct {
    // PE image memory address
    void* Image;

    // is a DLL PE image
    bool IsDLL;

    // wait main thread exit
    bool WaitMainThread;

    // use custom FindAPI from Gleam-RT for hook
    FindAPI_t FindAPI;
} PELoader_Cfg;

typedef struct {
    void* EntryPoint;
    uint  ExitCode;

    // create a thread at EntryPoint.
    Execute_t Execute;
} PELoader_M;

// InitPELoader is used to initialize PE loader, it will load PE file
// from memory, but it will not run it, caller must use PELoader_M.
// If failed to initialize, use GetLastError to get error code.
PELoader_M* InitPELoader(PELoader_Cfg* cfg);

#endif // PE_LOADER_H
