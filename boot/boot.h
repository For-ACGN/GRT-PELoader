#ifndef BOOT_H
#define BOOT_H

#include "errno.h"

#define ARG_IDX_PE_IMAGE   0
#define ARG_IDX_CMDLINE_A  1
#define ARG_IDX_CMDLINE_W  2
#define ARG_IDX_STD_INPUT  3
#define ARG_IDX_STD_OUTPUT 4
#define ARG_IDX_STD_ERROR  5
#define ARG_IDX_WAIT_MAIN  6

#define ERR_INVALID_OPTION_STUB    0x7F000001
#define ERR_NOT_FOUND_PE_IMAGE     0x7F000002
#define ERR_EMPTY_PE_IMAGE_DATA    0x7F000003
#define ERR_NOT_FOUND_CMDLINE_A    0x7F000004
#define ERR_NOT_FOUND_CMDLINE_W    0x7F000005
#define ERR_COMMAND_LINE_TOO_LONG  0x7F000006
#define ERR_NOT_FOUND_STD_INPUT    0x7F000007
#define ERR_INVALID_STD_INPUT      0x7F000008
#define ERR_NOT_FOUND_STD_OUTPUT   0x7F000009
#define ERR_INVALID_STD_OUTPUT     0x7F00000A
#define ERR_NOT_FOUND_STD_ERROR    0x7F00000B
#define ERR_INVALID_STD_ERROR      0x7F00000C
#define ERR_NOT_FOUND_WAIT_MAIN    0x7F00000D
#define ERR_INVALID_WAIT_MAIN      0x7F00000E

errno Boot();

#endif // BOOT_H
