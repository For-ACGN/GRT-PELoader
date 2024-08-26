#ifndef PE_IMAGE_H
#define PE_IMAGE_H

#include "c_types.h"
#include "windows_t.h"

#define PE_FILE_HEADER_SIZE      24
#define PE_OPT_HEADER_SIZE_64    240
#define PE_OPT_HEADER_SIZE_32    224
#define PE_SECTION_HEADER_SIZE   40
#define PE_DATA_DIRECTORY_SIZE   8
#define PE_IMPORT_DIRECTORY_SIZE 20

#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_DLL              0x2000

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000

#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGHLOW  3 
#define IMAGE_REL_BASED_DIR64    10

typedef struct {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
} PE_ImageBaseRelocation;

typedef struct {
    DWORD OriginalFirstThunk;
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} PE_ImportDirectory;

#endif // PE_IMAGE_H
