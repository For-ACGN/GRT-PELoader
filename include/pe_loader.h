#ifndef PE_LOADER_H
#define PE_LOADER_H

#include "c_types.h"
#include "hash_api.h"
#include "errno.h"

typedef uint  (*Execute_t)();
typedef errno (*Exit_t)();
typedef errno (*Destroy_t)();

typedef struct {
    // PE image memory address
    void* Image;

    // wait main thread exit if it is a exe
    bool Wait;

    // use custom FindAPI from Gleam-RT for hook
    FindAPI_t FindAPI;
} PELoader_Cfg;

typedef struct {
    // absolute memory address about PE entry point
    void* EntryPoint;

    // main thread return value or argument about call ExitProcess
    uint ExitCode;

    // create a thread at EntryPoint, it can call multi times
    Execute_t Execute;

    // release all resource, it can call multi times
    Exit_t Exit;

    // destroy all resource about PE loader, it can only call one time
    Destroy_t Destroy;
} PELoader_M;

// InitPELoader is used to initialize PE loader, it will load PE file
// from memory, but it will not run it, caller must use PELoader_M.
// If failed to initialize, use GetLastError to get error code.
PELoader_M* InitPELoader(PELoader_Cfg* cfg);

#endif // PE_LOADER_H
