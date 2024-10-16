#ifndef BUILD_H
#define BUILD_H

// RELEASE_MODE: remove debug modules for generate shellcode
// NO_RUNTIME:   not include Gleam-RT for test and debug

// #define RELEASE_MODE
// #define NO_RUNTIME

// disable special warnings for NO_RUNTIME
#ifdef NO_RUNTIME
    #pragma warning(disable: 4100)
    #pragma warning(disable: 4189)
#endif

#endif // BUILD_H
