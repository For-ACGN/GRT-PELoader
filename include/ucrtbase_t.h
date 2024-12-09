#ifndef UCRTBASE_T_H
#define UCRTBASE_T_H

#include "c_types.h"

typedef int* (__cdecl *ucrtbase_p_argc_t)();

typedef byte*** (__cdecl *ucrtbase_p_argv_t)();

typedef uint16*** (__cdecl *ucrtbase_p_wargv_t)();

#endif // UCRTBASE_T_H
