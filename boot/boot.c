#include "c_types.h"
#include "rel_addr.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "boot.h"

errno loadPELoaderConfig(Runtime_M* runtime, PELoader_Cfg* config);

errno Boot()
{
    Runtime_Opts opts = {
        .BootInstAddress     = GetFuncAddr(&Boot),
        .NotEraseInstruction = false,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
    Runtime_M* runtime = InitRuntime(&opts);
    if (runtime == NULL)
    {
        return GetLastErrno();
    }

    PELoader_Cfg cfg = {
        .Image       = NULL,
        .CommandLine = NULL,
        .StdInput    = NULL,
        .StdOutput   = NULL,
        .StdError    = NULL,
        .WaitMain    = false,

        .FindAPI       = runtime->FindAPI,
        .AdjustProtect = false,
    };
    PELoader_M* loader;

    errno err = NO_ERROR;
    for (;;)
    {
        err = loadPELoaderConfig(runtime, &cfg);
        if (err != NO_ERROR)
        {
            break;
        }
        loader = InitPELoader(&cfg);
        if (loader == NULL)
        {
            err = GetLastErrno();
            break;
        }
        break;
    }

    if (err != NO_ERROR)
    {
        runtime->Exit();
        return err;
    }


    return NO_ERROR;
}

errno loadPELoaderConfig(Runtime_M* runtime, PELoader_Cfg* config)
{
    uint32 size;
    byte* image = NULL;
    if (!runtime->GetArgument(ARG_IDX_PE_IMAGE, &image, &size))
    {
        return ERR_NOT_FOUND_PE_IMAGE;
    }
    if (size == 0)
    {
        return ERR_EMPTY_PE_IMAGE;
    }


    //  
        


    return NO_ERROR;
}
