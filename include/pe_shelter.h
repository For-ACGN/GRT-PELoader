#ifndef PE_SHELTER_H
#define PE_SHELTER_H

#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"

typedef struct {
    // use custom FindAPI from Gleam-RT
    FindAPI_t FindAPI;

    // use custom GetProcAddress for IAT hook
    GetProcAddress_t GetProcAddress;
} PEShelter_Opts;

uintptr LoadPE(uintptr address, PEShelter_Opts* opts);

#endif // PE_SHELTER_H
