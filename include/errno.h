#ifndef ERRNO_H
#define ERRNO_H

#include "c_types.h"

typedef uint32 errno;

void  SetLastErrno(errno errno);
errno GetLastErrno();

// 00，，，，，， module id
// ，，00，，，， error flags
// ，，，，00，， major error id
// ，，，，，，00 minor error id

#define NO_ERROR 0x00000000

#define ERR_FLAG_CAN_IGNORE 0x00010000

#define ERR_LOADER_INIT_DEBUGGER   (0x01000001)
#define ERR_LOADER_ALLOC_MEMORY    (0x01000002)
#define ERR_LOADER_INIT_API        (0x01000003)
#define ERR_LOADER_PARSE_PE_IMAGE  (0x01000004)
#define ERR_LOADER_MAP_SECTIONS    (0x01000005)
#define ERR_LOADER_FIX_RELOC_TABLE (0x01000006)
#define ERR_LOADER_PROCESS_IAT     (0x01000007)

#endif // ERRNO_H
