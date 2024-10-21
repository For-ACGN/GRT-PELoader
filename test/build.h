#ifndef BUILD_H
#define BUILD_H

// RELEASE_MODE:   remove debug modules for generate shellcode
// SHELLCODE_MODE: run unit tests under PE Loader shellcode
// NO_RUNTIME:     not include Gleam-RT for test and debug

// #define RELEASE_MODE
// #define SHELLCODE_MODE
// #define NO_RUNTIME

#ifdef SHELLCODE_MODE
    #define RELEASE_MODE
#endif // SHELLCODE_MODE

// disable special warnings for RELEASE_MODE
#ifdef RELEASE_MODE
    #pragma warning(disable: 4206)
#endif

// disable special warnings for NO_RUNTIME
#ifdef NO_RUNTIME
    #pragma warning(disable: 4100)
    #pragma warning(disable: 4189)
#endif

#endif // BUILD_H
