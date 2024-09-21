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

#define ERR_LOADER_INIT_DEBUGGER   (0x10000001)
#define ERR_LOADER_ALLOC_MEMORY    (0x10000002)
#define ERR_LOADER_INIT_API        (0x10000003)
#define ERR_LOADER_LOCK_MAIN_MEM   (0x10000004)
#define ERR_LOADER_ADJUST_PROTECT  (0x10000005)
#define ERR_LOADER_UPDATE_PTR      (0x10000006)
#define ERR_LOADER_RECOVER_PROTECT (0x10000007)
#define ERR_LOADER_FLUSH_INST      (0x10000008)
#define ERR_LOADER_CREATE_G_MUTEX  (0x10000009)
#define ERR_LOADER_CREATE_S_MUTEX  (0x1000000A)
#define ERR_LOADER_BACKUP_PE_IMAGE (0x1000000B)
#define ERR_LOADER_PARSE_PE_IMAGE  (0x10000101)
#define ERR_LOADER_MAP_SECTIONS    (0x10000102)
#define ERR_LOADER_FIX_RELOC_TABLE (0x10000103)
#define ERR_LOADER_PROCESS_IAT     (0x10000104)
#define ERR_LOADER_LOCK            (0x10000201)
#define ERR_LOADER_UNLOCK          (0x10000202)
#define ERR_LOADER_CREATE_THREAD   (0x10000203)
#define ERR_LOADER_CLEAN_G_MUTEX   (0x1000FF01)
#define ERR_LOADER_CLEAN_S_MUTEX   (0x1000FF02)
#define ERR_LOADER_UNLOCK_PE_IMAGE (0x1000FF03)
#define ERR_LOADER_UNLOCK_BACKUP   (0x1000FF04)
#define ERR_LOADER_UNLOCK_MAIN_MEM (0x1000FF05)
#define ERR_LOADER_CLEAN_FREE_PE   (0x1000FF06)
#define ERR_LOADER_CLEAN_FREE_BAK  (0x1000FF07)
#define ERR_LOADER_CLEAN_FREE_MEM  (0x1000FF08)
#define ERR_LOADER_RECOVER_INST    (0x1000FF09)

#endif // ERRNO_H
