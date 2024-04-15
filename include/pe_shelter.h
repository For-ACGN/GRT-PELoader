#ifndef PE_SHELTER_H
#define PE_SHELTER_H

#include "go_types.h"

#ifdef _WIN64
typedef uintptr (*FindAPI_t)(uint64 hash, uint64 key);
#elif _WIN32
typedef uintptr (*FindAPI_t)(uint32 hash, uint32 key);
#endif

typedef struct {
    uintptr Original;
    uintptr Replace;
} Hook;

typedef struct {
	FindAPI_t FindAPI;
    Hook      (*Hooks)[];
    uint      NumHooks;
} PEShelterCtx;

uintptr LoadPE(PEShelterCtx* context, uintptr address);

#endif // PE_SHELTER_H
