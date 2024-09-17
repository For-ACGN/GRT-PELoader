#ifndef WIN_API_H
#define WIN_API_H

#include "c_types.h"
#include "windows_t.h"

uint16 GetModuleFileName(HMODULE hModule, byte* name, uint16 maxSize);

#endif // WIN_API_H
