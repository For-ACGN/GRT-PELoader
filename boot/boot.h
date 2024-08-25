#ifndef BOOT_H
#define BOOT_H

#include "errno.h"

#define ARG_IDX_PE_IMAGE 0

#define ERR_NOT_FOUND_PE_IMAGE 0xFF000001
#define ERR_EMPTY_PE_IMAGE     0xFF000002

errno Boot();

#endif // BOOT_H
