#ifndef PE_LOADER_H
#define PE_LOADER_H

#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"

typedef struct {
    // use custom FindAPI from Gleam-RT
    FindAPI_t FindAPI;

    // use custom GetProcAddress for IAT hook
    GetProcAddress_t GetProcAddress;

    // wait main thread until exit
    bool WaitThread;
} PELoader_Opts;


uintptr LoadPE(uintptr address, uint size, PELoader_Opts* opts);

#endif // PE_LOADER_H
