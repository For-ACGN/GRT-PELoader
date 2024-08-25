#include "c_types.h"
#include "rel_addr.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "boot.h"

static errno loadPELoaderConfig(Runtime_M* runtime, PELoader_Cfg* config);

errno Boot()
{
    // initialize Gleam-RT
    Runtime_Opts opts = {
        .BootInstAddress     = GetFuncAddr(&Boot),
        .NotEraseInstruction = false,
        .NotAdjustProtect    = true,
        .TrackCurrentThread  = false,
    };
    Runtime_M* runtime = InitRuntime(&opts);
    if (runtime == NULL)
    {
        return GetLastErrno();
    }

    // load config and initialize PE Loader
    PELoader_Cfg cfg = {
        .FindAPI = runtime->FindAPI,

        .Image       = NULL,
        .CommandLine = NULL,
        .StdInput    = NULL,
        .StdOutput   = NULL,
        .StdError    = NULL,
        .WaitMain    = false,

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
    runtime->EraseAllArgs();
    if (err != NO_ERROR)
    {
        runtime->Exit();
        return err;
    }

    // execute PE file




    return NO_ERROR;
}

static errno loadPELoaderConfig(Runtime_M* runtime, PELoader_Cfg* config)
{
    uint32 size;
    // load PE Image, it cannot be empty
    if (!runtime->GetArgument(ARG_IDX_PE_IMAGE, &config->Image, &size))
    {
        return ERR_NOT_FOUND_PE_IMAGE;
    }
    if (size == 0)
    {
        return ERR_EMPTY_PE_IMAGE_DATA;
    }
    // load command line, it can be empty
    if (!runtime->GetArgument(ARG_IDX_COMMAND_LINE, &config->CommandLine, &size))
    {
        return ERR_NOT_FOUND_COMMAND_LINE;
    }
    if (size > 4096)
    {
        return ERR_COMMAND_LINE_TOO_LONG;
    }
    // load STD_INPUT_HANDLE, it can be zero
    if (!runtime->GetArgument(ARG_IDX_STD_INPUT, &config->StdInput, &size))
    {
        return ERR_NOT_FOUND_STD_INPUT;
    }
    if (size != sizeof(HANDLE))
    {
        return ERR_INVALID_STD_INPUT;
    }
    // load STD_OUTPUT_HANDLE, it can be zero
    if (!runtime->GetArgument(ARG_IDX_STD_OUTPUT, &config->StdOutput, &size))
    {
        return ERR_NOT_FOUND_STD_OUTPUT;
    }
    if (size != sizeof(HANDLE))
    {
        return ERR_INVALID_STD_OUTPUT;
    }
    // load STD_ERROR_HANDLE, it can be zero
    if (!runtime->GetArgument(ARG_IDX_STD_ERROR, &config->StdError, &size))
    {
        return ERR_NOT_FOUND_STD_ERROR;
    }
    if (size != sizeof(HANDLE))
    {
        return ERR_INVALID_STD_ERROR;
    }
    // load wait main, it must be true of false
    if (!runtime->GetArgument(ARG_IDX_WAIT_MAIN, &config->WaitMain, &size))
    {
        return ERR_NOT_FOUND_WAIT_MAIN;
    }
    if (size != sizeof(bool))
    {
        return ERR_INVALID_WAIT_MAIN;
    }
    return NO_ERROR;
}
