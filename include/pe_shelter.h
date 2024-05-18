#ifndef PE_SHELTER_H
#define PE_SHELTER_H

#include "go_types.h"
#include "windows_t.h"

typedef struct {
    // use custom GetProcAddress for IAT hook
    GetProcAddress_t GetProcAddress;
} PEShelter_Opts;

uintptr LoadPE(uintptr address, PEShelter_Opts* opts);

#endif // PE_SHELTER_H
