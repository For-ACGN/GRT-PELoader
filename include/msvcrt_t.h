#ifndef MSVCRT_T_H
#define MSVCRT_T_H

#include "c_types.h"

typedef int (__cdecl *msvcrt_getmainargs_t)
(
    int* argc, byte*** argv, byte*** env, int doWildCard, void* startInfo
);

typedef int (__cdecl *msvcrt_wgetmainargs_t)
(
    int* argc, uint16*** argv, uint16*** env, int doWildCard, void* startInfo
);

#endif // MSVCRT_T_H
