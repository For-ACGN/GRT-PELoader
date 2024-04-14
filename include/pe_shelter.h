#ifndef PE_SHELTER_H
#define PE_SHELTER_H

#include "go_types.h"
#include "hash_api.h"

typedef struct {
    uintptr Original;
    uintptr Replace;
} Hook;

typedef struct {
	FindAPI_t FindAPI;
    Hook      (*Hooks)[];
    uint      NumHooks;
} PEShelterCtx;

uintptr LoadPE(PEShelterCtx *ctx, uintptr address, uint64 size);

#endif // PE_SHELTER_H
