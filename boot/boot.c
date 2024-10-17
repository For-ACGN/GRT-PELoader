#include "c_types.h"
#include "rel_addr.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "epilogue.h"
#include "boot.h"

static errno loadOption(Runtime_Opts* options);
static errno loadConfig(Runtime_M* runtime, PELoader_Cfg* config);

errno Boot()
{
    // initialize Gleam-RT for PE Loader
    Runtime_Opts options = {
        .BootInstAddress     = GetFuncAddr(&Boot),
        .NotEraseInstruction = false,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
    errno elo = loadOption(&options);
    if (elo != NO_ERROR)
    {
        return elo;
    }
    Runtime_M* runtime = InitRuntime(&options);
    if (runtime == NULL)
    {
        return GetLastErrno();
    }

    // byte  path[] = { '1', '.', 'e', 'x','e',0x00 };
    // byte* buf;
    // int64 size;
    // runtime->WinFile.ReadFileA(path, &buf, &size);

    // load config and initialize PE Loader
    PELoader_Cfg config = {
        .FindAPI = runtime->HashAPI.FindAPI,

        .Image        = NULL,
        .CommandLineA = NULL,
        .CommandLineW = NULL,
        .StdInput     = NULL,
        .StdOutput    = NULL,
        .StdError     = NULL,
        .WaitMain     = false,

        .NotEraseInstruction = options.NotEraseInstruction,
        .NotAdjustProtect    = options.NotAdjustProtect,
    };
    PELoader_M* loader = NULL;
    errno err = NO_ERROR;
    for (;;)
    {
        err = loadConfig(runtime, &config);
        if (err != NO_ERROR)
        {
            break;
        }
        loader = InitPELoader(&config);
        if (loader == NULL)
        {
            err = GetLastErrno();
            break;
        }
        break;
    }
    // runtime->Argument.EraseAll();
    if (err != NO_ERROR || loader == NULL)
    {
        runtime->Core.Exit();
        return err;
    }

    // execute PE file
    errno ele = loader->Execute();
    if (ele != NO_ERROR && err == NO_ERROR)
    {
        err = ele;
    }
    // TODO it
    if (!config.WaitMain)
    {
        return NO_ERROR;
    }
    // destroy pe loader and exit runtime
    errno eld = loader->Destroy();
    if (eld != NO_ERROR && err == NO_ERROR)
    {
        err = eld;
    }
    errno ere = runtime->Core.Exit();
    if (ere != NO_ERROR && err == NO_ERROR)
    {
        err = ere;
    }
    // set exit code from pe image
    // if (exitCode != 0 && err == NO_ERROR)
    // {
    //     err = (errno)exitCode;
    // }
    return err;
}

static errno loadOption(Runtime_Opts* options)
{
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    stub -= OPTION_STUB_SIZE;
    // check runtime option stub is valid
    if (*(byte*)stub != OPTION_STUB_MAGIC)
    {
        return ERR_INVALID_OPTION_STUB;
    }
    // load runtime options from stub
    options->NotEraseInstruction = *(bool*)(stub+OPT_OFFSET_NOT_ERASE_INSTRUCTION);
    options->NotAdjustProtect    = *(bool*)(stub+OPT_OFFSET_NOT_ADJUST_PROTECT);
    options->TrackCurrentThread  = *(bool*)(stub+OPT_OFFSET_NOT_TRACK_CURRENT_THREAD);
    return NO_ERROR;
}

static errno loadConfig(Runtime_M* runtime, PELoader_Cfg* config)
{
    uint32 size;
    // load PE Image, it cannot be empty
    if (!runtime->Argument.GetPointer(ARG_IDX_PE_IMAGE, &config->Image, &size))
    {
        return ERR_NOT_FOUND_PE_IMAGE;
    }
    if (size == 0)
    {
        return ERR_EMPTY_PE_IMAGE_DATA;
    }
    // load command line ANSI, it can be empty
    if (!runtime->Argument.GetPointer(ARG_IDX_CMDLINE_A, &config->CommandLineA, &size))
    {
        return ERR_NOT_FOUND_CMDLINE_A;
    }
    if (size > 4096)
    {
        return ERR_COMMAND_LINE_TOO_LONG;
    }
    // load command line Unicode, it can be empty
    if (!runtime->Argument.GetPointer(ARG_IDX_CMDLINE_W, &config->CommandLineW, &size))
    {
        return ERR_NOT_FOUND_CMDLINE_W;
    }
    if (size > 4096)
    {
        return ERR_COMMAND_LINE_TOO_LONG;
    }
    // load STD_INPUT_HANDLE, it can be zero
    if (!runtime->Argument.GetValue(ARG_IDX_STD_INPUT, &config->StdInput, &size))
    {
        return ERR_NOT_FOUND_STD_INPUT;
    }
    if (size != sizeof(HANDLE))
    {
        return ERR_INVALID_STD_INPUT;
    }
    // load STD_OUTPUT_HANDLE, it can be zero
    if (!runtime->Argument.GetValue(ARG_IDX_STD_OUTPUT, &config->StdOutput, &size))
    {
        return ERR_NOT_FOUND_STD_OUTPUT;
    }
    if (size != sizeof(HANDLE))
    {
        return ERR_INVALID_STD_OUTPUT;
    }
    // load STD_ERROR_HANDLE, it can be zero
    if (!runtime->Argument.GetValue(ARG_IDX_STD_ERROR, &config->StdError, &size))
    {
        return ERR_NOT_FOUND_STD_ERROR;
    }
    if (size != sizeof(HANDLE))
    {
        return ERR_INVALID_STD_ERROR;
    }
    // load wait main, it must be true of false
    if (!runtime->Argument.GetValue(ARG_IDX_WAIT_MAIN, &config->WaitMain, &size))
    {
        return ERR_NOT_FOUND_WAIT_MAIN;
    }
    if (size != sizeof(bool))
    {
        return ERR_INVALID_WAIT_MAIN;
    }
    return NO_ERROR;
}
