#include "c_types.h"
#include "windows_t.h"
#include "rel_addr.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "win_api.h"
#include "random.h"
#include "errno.h"
#include "pe_loader.h"
#include "debug.h"

#define MAIN_MEM_PAGE_SIZE 4096

typedef struct {
    // store config from argument
    PELoader_Cfg Config;

    // API addresses
    VirtualAlloc_t          VirtualAlloc;
    VirtualFree_t           VirtualFree;
    VirtualProtect_t        VirtualProtect;
    LoadLibraryA_t          LoadLibraryA;
    GetProcAddress_t        GetProcAddress;
    CreateThread_t          CreateThread;
    FlushInstructionCache_t FlushInstructionCache;
    CreateMutexA_t          CreateMutexA;
    ReleaseMutex_t          ReleaseMutex;
    WaitForSingleObject_t   WaitForSingleObject;
    CloseHandle_t           CloseHandle;
    GetCommandLineA_t       GetCommandLineA;
    GetCommandLineW_t       GetCommandLineW;
    GetStdHandle_t          GetStdHandle;
    ExitProcess_t           ExitProcess;

    // loader context
    void*  MainMemPage; // store all structures
    HANDLE hMutex;      // global mutex

    // store PE image information
    uintptr PEImage;
    uint32  PEOffset;
    uint16  NumSections;
    uint16  OptHeaderSize;
    uintptr DataDir;
    uintptr EntryPoint;
    uintptr ImageBase;
    uint32  ImageSize;
    uintptr ImportTable;
    bool    IsDLL;

    // write return value
    uint* ExitCode;
} PELoader;

// PE loader methods
uint  LDR_Execute();
errno LDR_Exit();
errno LDR_Destroy();

// hard encoded address in getPELoaderPointer for replacement
#ifdef _WIN64
    #define PE_LOADER_POINTER 0x7FABCDEF111111FF
#elif _WIN32
    #define PE_LOADER_POINTER 0x7FABCDFF
#endif
static PELoader* getPELoaderPointer();

static void* allocLoaderMemPage(PELoader_Cfg* cfg);
static bool  initLoaderAPI(PELoader* loader);
static bool  adjustPageProtect(PELoader* loader);
static errno loadPEImage(PELoader* loader);
static bool  parsePEImage(PELoader* loader);
static bool  mapSections(PELoader* loader);
static bool  fixRelocTable(PELoader* loader);
static bool  processIAT(PELoader* loader);
static bool  updatePELoaderPointer(PELoader* loader);
static errno initPELoaderEnvironment(PELoader* loader);
static bool  flushInstructionCache(PELoader* loader);

static void* ldr_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
static void* getPELoaderMethods(byte* module, LPCSTR lpProcName);
static void  set_exit_code(uint code);
static uint  get_exit_code();
static void  pe_entry_point();
static errno ldr_exit_process();

static LPSTR  hook_GetCommandLineA();
static LPWSTR hook_GetCommandLineW();
static HANDLE hook_GetStdHandle(DWORD nStdHandle);
static void   hook_ExitProcess(UINT uExitCode);

static void ldr_epilogue();

PELoader_M* InitPELoader(PELoader_Cfg* cfg)
{
    if (!InitDebugger())
    {
        SetLastErrno(ERR_LOADER_INIT_DEBUGGER);
        return NULL;
    }
    // alloc memory for store loader structure
    void* memPage = allocLoaderMemPage(cfg);
    if (memPage == NULL)
    {
        SetLastErrno(ERR_LOADER_ALLOC_MEMORY);
        return NULL;
    }
    // set structure address
    uintptr address = (uintptr)memPage;
    uintptr loaderAddr = address + 1000 + RandUintN(address, 128);
    uintptr moduleAddr = address + 2000 + RandUintN(address, 128);
    // initialize structure
    PELoader* loader = (PELoader*)loaderAddr;
    mem_clean(loader, sizeof(PELoader));
    // store config and context
    loader->Config = *cfg;
    loader->MainMemPage = memPage;
    // initialize loader
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initLoaderAPI(loader))
        {
            errno = ERR_LOADER_INIT_API;
            break;
        }
        if (!adjustPageProtect(loader))
        {
            errno = ERR_LOADER_ADJUST_PROTECT;
            break;
        }
        if (!updatePELoaderPointer(loader))
        {
            errno = ERR_LOADER_UPDATE_PTR;
            break;
        }
        errno = loadPEImage(loader);
        if (errno != NO_ERROR)
        {
            break;
        }
        errno = initPELoaderEnvironment(loader);
        if (errno != NO_ERROR)
        {
            break;
        }
        break;
    }
    if (errno == NO_ERROR && !flushInstructionCache(loader))
    {
        errno = ERR_LOADER_FLUSH_INST;
    }
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for loader
    PELoader_M* module = (PELoader_M*)moduleAddr;
    // process variables
    module->EntryPoint = (void*)(loader->EntryPoint);
    // loader module methods
    module->Execute = GetFuncAddr(&LDR_Execute);
    module->Exit    = GetFuncAddr(&LDR_Exit);
    module->Destroy = GetFuncAddr(&LDR_Destroy);
    // record return value pointer;
    loader->ExitCode = &module->ExitCode;
    return module;
}

static void* allocLoaderMemPage(PELoader_Cfg* cfg)
{
#ifdef _WIN64
    uint hash = 0xEFE2E03329515B77;
    uint key  = 0x81723B49C5827760;
#elif _WIN32
    uint hash = 0xE0C5DD0C;
    uint key  = 0x1057DA5A;
#endif
    VirtualAlloc_t virtualAlloc = cfg->FindAPI(hash, key);
    if (virtualAlloc == NULL)
    {
        return NULL;
    }
    LPVOID addr = virtualAlloc(0, MAIN_MEM_PAGE_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    RandBuf(addr, MAIN_MEM_PAGE_SIZE);
    dbg_log("[PE Loader]", "Main Page: 0x%zX\n", addr);
    return addr;
}

static bool initLoaderAPI(PELoader* loader)
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x21E5E7E61968BBF4, 0x38FC2BB8B9E8F0B1 }, // VirtualAlloc
        { 0x7DDAB5BF4E742736, 0x6E0D1E4F5D19BE67 }, // VirtualFree
        { 0x6CF439115B558DE1, 0x7CAC9554D5A67E28 }, // VirtualProtect
        { 0x90BD05BA72DD948C, 0x253672CEAE439BB6 }, // LoadLibraryA
        { 0xF4E6DE881A59F6A0, 0xBC2E958CCBE70AA2 }, // GetProcAddress
        { 0x62E83480AE0AAFC7, 0x86C0AECD3EF92256 }, // CreateThread
        { 0xE8CA42297DA7319C, 0xAC51BC3A630A84FC }, // FlushInstructionCache
        { 0x04A85D44E64689B3, 0xBB2834EF8BE725C9 }, // CreateMutexA
        { 0x5B84A4B6173E4B44, 0x089FC914B21A66DA }, // ReleaseMutex
        { 0x91BB0A2A34E70890, 0xB2307F73C72A83BD }, // WaitForSingleObject
        { 0xB23064DF64282DE1, 0xD62F5C65075FCCE8 }, // CloseHandle
        { 0xEF31896F2FACEC04, 0x0E670990125E8E48 }, // GetCommandLineA
        { 0x701EF754FFADBDC2, 0x6D5BE783B0AF5812 }, // GetCommandLineW
        { 0x599C793AB3F4599E, 0xBBBA4AE31D6A6D8F }, // GetStdHandle
        { 0x131A9BBD85CB5E0D, 0x5126E3CBD1E0DB9A }, // ExitProcess
    };
#elif _WIN32
    {
        { 0x28310500, 0x51C40B22 }, // VirtualAlloc
        { 0xBC28097D, 0x4483038A }, // VirtualFree
        { 0x7B578622, 0x6950410A }, // VirtualProtect
        { 0x3DAF1E96, 0xD7E436F3 }, // LoadLibraryA
        { 0xE971801A, 0xEC6F6D90 }, // GetProcAddress
        { 0xD1AFE117, 0xDA772D98 }, // CreateThread
        { 0x73AFF9EE, 0x16AA8D66 }, // FlushInstructionCache
        { 0xFF3A4BBB, 0xD2F55A75 }, // CreateMutexA
        { 0x30B41C8C, 0xDD13B99D }, // ReleaseMutex
        { 0x4DF94300, 0x85D5CD6F }, // WaitForSingleObject
        { 0x7DC545BC, 0xCBD67153 }, // CloseHandle
        { 0xA187476E, 0x5AF922F3 }, // GetCommandLineA
        { 0xC15EF07A, 0x47A945CE }, // GetCommandLineW
        { 0xAE68A468, 0xD611C7F0 }, // GetStdHandle
        { 0x0C5D0A6C, 0xDB58404D }, // ExitProcess
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        void* proc = loader->Config.FindAPI(list[i].hash, list[i].key);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }

    loader->VirtualAlloc          = list[0x00].proc;
    loader->VirtualFree           = list[0x01].proc;
    loader->VirtualProtect        = list[0x02].proc;
    loader->LoadLibraryA          = list[0x03].proc;
    loader->GetProcAddress        = list[0x04].proc;
    loader->CreateThread          = list[0x05].proc;
    loader->FlushInstructionCache = list[0x06].proc;
    loader->CreateMutexA          = list[0x07].proc;
    loader->ReleaseMutex          = list[0x08].proc;
    loader->WaitForSingleObject   = list[0x09].proc;
    loader->CloseHandle           = list[0x0A].proc;
    loader->GetCommandLineA       = list[0x0B].proc;
    loader->GetCommandLineW       = list[0x0C].proc;
    loader->GetStdHandle          = list[0x0D].proc;
    loader->ExitProcess           = list[0x0E].proc;
    return true;
}

// change memory protect for dynamic update pointer that hard encode.
static bool adjustPageProtect(PELoader* loader)
{
    if (!loader->Config.AdjustProtect)
    {
        return true;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&InitPELoader));
    uintptr end   = (uintptr)(GetFuncAddr(&ldr_epilogue));
    uint    size  = end - begin;
    uint32  old;
    return loader->VirtualProtect((void*)begin, size, PAGE_EXECUTE_READWRITE, &old);
}

static errno loadPEImage(PELoader* loader)
{
    if (!parsePEImage(loader))
    {
        return ERR_LOADER_PARSE_PE_IMAGE;
    }
    if (!mapSections(loader))
    {
        return ERR_LOADER_MAP_SECTIONS;
    }
    if (!fixRelocTable(loader))
    {
        return ERR_LOADER_FIX_RELOC_TABLE;
    }
    if (!processIAT(loader))
    {
        return ERR_LOADER_PROCESS_IAT;
    }
    dbg_log("[PE Loader]", "image: 0x%zX\n", loader->PEImage);
    return NO_ERROR;
}

static bool parsePEImage(PELoader* loader)
{
    uintptr imageAddr = (uintptr)(loader->Config.Image);
    uint32  peOffset  = *(uint32*)(imageAddr + 60);
    // parse FileHeader
    uint16 numSections     = *(uint16*)(imageAddr + peOffset + 6);
    uint16 optHeaderSize   = *(uint16*)(imageAddr + peOffset + 20);
    uint16 characteristics = *(uint16*)(imageAddr + peOffset + 22);
    // check PE file typee
    bool isDLL = (characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL;
    // parse OptionalHeader
#ifdef _WIN64
    uint16 ddOffset = PE_OPT_HEADER_SIZE_64 - 16 * PE_DATA_DIRECTORY_SIZE;
#elif _WIN32
    uint16 ddOffset = PE_OPT_HEADER_SIZE_32 - 16 * PE_DATA_DIRECTORY_SIZE;
#endif
    uintptr dataDir    = imageAddr + peOffset + PE_FILE_HEADER_SIZE + ddOffset;
    uint32  entryPoint = *(uint32*)(imageAddr + peOffset + 40);
#ifdef _WIN64
    uintptr imageBase = *(uintptr*)(imageAddr + peOffset + 48);
#elif _WIN32
    uintptr imageBase = *(uintptr*)(imageAddr + peOffset + 52);
#endif
    uint32  imageSize = *(uint32*)(imageAddr + peOffset + 80);
    // store result
    loader->PEOffset      = peOffset;
    loader->NumSections   = numSections;
    loader->OptHeaderSize = optHeaderSize;
    loader->DataDir       = dataDir;
    loader->EntryPoint    = entryPoint;
    loader->ImageBase     = imageBase;
    loader->ImageSize     = imageSize;
    loader->IsDLL         = isDLL;
    return true;
}

static bool mapSections(PELoader* loader)
{
    // allocate memory for write PE image
    uint32 size = loader->ImageSize;
    void* mem = loader->VirtualAlloc(0, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem == NULL)
    {
        return false;
    }
    uintptr peImage = (uintptr)mem;
    // map PE image sections to the memory
    uintptr imageAddr = (uintptr)(loader->Config.Image);
    uint32  peOffset  = loader->PEOffset;
    uint16  optHeaderSize = loader->OptHeaderSize;
    uintptr section = imageAddr + peOffset + PE_FILE_HEADER_SIZE + optHeaderSize;
    for (uint16 i = 0; i < loader->NumSections; i++)
    {
        uint32 virtualAddress   = *(uint32*)(section + 12);
        uint32 sizeOfRawData    = *(uint32*)(section + 16);
        uint32 pointerToRawData = *(uint32*)(section + 20);
        byte*  dst = (byte*)(peImage + virtualAddress);
        byte*  src = (byte*)(imageAddr + pointerToRawData);
        mem_copy(dst, src, sizeOfRawData);
        section += PE_SECTION_HEADER_SIZE;
    }
    // record image memory address
    loader->PEImage = peImage;
    // update EntryPoint
    loader->EntryPoint += peImage;
    return true;
}

static bool fixRelocTable(PELoader* loader)
{
    uintptr peImage = loader->PEImage;
    uintptr dataDir = loader->DataDir;
    uintptr offset = dataDir + (uintptr)(5 * PE_DATA_DIRECTORY_SIZE);
    uintptr relocTable = peImage + *(uint32*)(offset);
    uint32 tableSize = *(uint32*)(offset + 4);
    uint64  addressOffset = (int64)(loader->PEImage) - (int64)(loader->ImageBase);
    // check need relocation
    if (tableSize == 0)
    {
        return true;
    }
    PE_ImageBaseRelocation* baseReloc;
    for (;;)
    {
        baseReloc = (PE_ImageBaseRelocation*)(relocTable);
        if (baseReloc->VirtualAddress == 0)
        {
            break;
        }
        uintptr infoPtr = relocTable + 8;
        uintptr dstAddr = peImage + baseReloc->VirtualAddress;
        for (uint32 i = 0; i < (baseReloc->SizeOfBlock - 8) / 2; i++)
        {
            uint16 info   = *(uint16*)(infoPtr);
            uint16 type   = info >> 12;
            uint16 offset = info & 0xFFF;

            uint32* patchAddr32;
            uint64* patchAddr64;
            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                patchAddr32 = (uint32*)(dstAddr + offset);
                *patchAddr32 += (uint32)(addressOffset);
                break;
            case IMAGE_REL_BASED_DIR64:
                patchAddr64 = (uint64*)(dstAddr + offset);
                *patchAddr64 += (uint64)(addressOffset);
                break;
            default:
                return false;
            }
            infoPtr += 2;
        }
        relocTable += baseReloc->SizeOfBlock;
    }
    return true;
}

static bool processIAT(PELoader* loader)
{
    uintptr peImage = loader->PEImage;
    uintptr dataDir = loader->DataDir;
    uintptr offset  = dataDir + (uintptr)(1 * PE_DATA_DIRECTORY_SIZE);
    uintptr importTable = peImage + *(uint32*)(offset);
    // calculate the number of the library
    PE_ImportDirectory* importDir;
    uintptr table = importTable;
    uint32  numDLL = 0;
    for (;;)
    {
        importDir = (PE_ImportDirectory*)(table);
        if (importDir->Name == 0)
        {
            break;
        }
        numDLL++;
        table += PE_IMPORT_DIRECTORY_SIZE;
    }
    // load library and fix function address
    table = importTable;
    for (;;)
    {
        importDir = (PE_ImportDirectory*)(table);
        if (importDir->Name == 0)
        {
            break;
        }
        LPCSTR dllName = (LPCSTR)(peImage + importDir->Name);
        HMODULE hModule = loader->LoadLibraryA(dllName);
        if (hModule == NULL)
        {
            return false;
        }
        uintptr srcThunk;
        uintptr dstThunk;
        if (importDir->OriginalFirstThunk != 0)
        {
            srcThunk = peImage + importDir->OriginalFirstThunk;
        } else {
            srcThunk = peImage + importDir->FirstThunk;
        }
        dstThunk = peImage + importDir->FirstThunk;
        // fix function address
        for (;;)
        {
            uintptr value = *(uintptr*)srcThunk;
            if (value == 0)
            {
                break;
            }
            LPCSTR procName;
            #ifdef _WIN64
            if ((value & IMAGE_ORDINAL_FLAG64) != 0)
            #elif _WIN32
            if ((value & IMAGE_ORDINAL_FLAG32) != 0)
            #endif
            {
                procName = (LPCSTR)(value&0xFFFF);
            } else {
                procName = (LPCSTR)(peImage + value + 2);
            }
            void* proc = ldr_GetProcAddress(hModule, procName);
            if (proc == NULL)
            {
                return false;
            }
            *(uintptr*)dstThunk = (uintptr)proc;
            srcThunk += sizeof(uintptr);
            dstThunk += sizeof(uintptr);
        }
        table += PE_IMPORT_DIRECTORY_SIZE;
    }
    loader->ImportTable = importTable;
    return true;
}

static bool updatePELoaderPointer(PELoader* loader)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getPELoaderPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != PE_LOADER_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)loader;
        success = true;
        break;
    }
    return success;
}

static errno initPELoaderEnvironment(PELoader* loader)
{
    // create global mutex
    HANDLE hMutex = loader->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return ERR_LOADER_CREATE_MUTEX;
    }
    loader->hMutex = hMutex;
    // clean useless API functions in runtime structure
    RandBuf((byte*)(&loader->CreateMutexA), sizeof(uintptr));
    return NO_ERROR;
}

static bool flushInstructionCache(PELoader* loader)
{
    uintptr begin = (uintptr)(GetFuncAddr(&InitPELoader));
    uintptr end   = (uintptr)(GetFuncAddr(&ldr_epilogue));
    uint    size  = end - begin;
    return loader->FlushInstructionCache(CURRENT_PROCESS, (LPCVOID)begin, size);
}

// updatePELoaderPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updatePELoaderPointer will fail.
#pragma optimize("", off)
static PELoader* getPELoaderPointer()
{
    uint pointer = PE_LOADER_POINTER;
    return (PELoader*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static bool ldr_lock(PELoader* loader)
{
    uint32 event = loader->WaitForSingleObject(loader->hMutex, INFINITE);
    return event == WAIT_OBJECT_0;
}

__declspec(noinline)
static bool ldr_unlock(PELoader* loader)
{
    return loader->ReleaseMutex(loader->hMutex);
}

__declspec(noinline)
void* ldr_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    PELoader* loader = getPELoaderPointer();

    // use "mem_clean" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    byte module[MAX_PATH];
    mem_clean(&module, sizeof(module));
    // get module file name
    if (GetModuleFileName(hModule, &module[0], sizeof(module)) == 0)
    {
        return NULL;
    }
    // check is internal methods
    void* method = getPELoaderMethods(&module[0], lpProcName);
    if (method != NULL)
    {
        return method;
    }
    // generate key for calculate Windows API hash
    uint key  = RandUint((uint64)(hModule) + (uint64)(lpProcName));
    uint hash = HashAPI_W((uint16*)(&module[0]), (byte*)lpProcName, key);
    return loader->Config.FindAPI(hash, key);
}

static void* getPELoaderMethods(byte* module, LPCSTR lpProcName)
{
    PELoader* loader = getPELoaderPointer();

    typedef struct {
        uint hash; uint key; void* method;
    } method;
    method methods[] =
#ifdef _WIN64
    {
        { 0xA23FAC0E6398838A, 0xE4990D7D4933EE6A, GetFuncAddr(&hook_GetCommandLineA) },
        { 0xABD1E8F0D28E9F46, 0xAF34F5979D300C70, GetFuncAddr(&hook_GetCommandLineW) },
        { 0xC9C5D350BB118FAE, 0x061A602F681F2636, GetFuncAddr(&hook_ExitProcess) },
    };
#elif _WIN32
    {
        { 0xA23FAC0E6398838A, 0xE4990D7D4933EE6A, GetFuncAddr(&hook_GetCommandLineA) },
        { 0xABD1E8F0D28E9F46, 0xAF34F5979D300C70, GetFuncAddr(&hook_GetCommandLineW) },
        { 0xC9C5D350BB118FAE, 0x061A602F681F2636, GetFuncAddr(&hook_ExitProcess) },
    };
#endif
    for (int i = 0; i < arrlen(methods); i++)
    {
        uint hash = HashAPI_W((uint16*)module, (byte*)lpProcName, methods[i].key);
        if (hash != methods[i].hash)
        {
            continue;
        }
        return methods[i].method;
    }
    return NULL;
}

__declspec(noinline)
static LPSTR hook_GetCommandLineA()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "GetCommandLineA\n");

    // try to get it from config
    LPSTR cmdLine = loader->Config.CommandLine;
    if (cmdLine != NULL)
    {
        return cmdLine;
    }
    return loader->GetCommandLineA();
}

__declspec(noinline)
static LPWSTR hook_GetCommandLineW()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "GetCommandLineW\n");

    // try to get it from config
    LPWSTR cmdLine = loader->Config.CommandLine;
    if (cmdLine != NULL)
    {
        return cmdLine;
    }
    return loader->GetCommandLineW();
}

static HANDLE hook_GetStdHandle(DWORD nStdHandle)
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "GetStdHandle: %d\n", nStdHandle);

    // try to get it from config
    HANDLE hStdInput  = loader->Config.StdInput;
    HANDLE hStdOutput = loader->Config.StdOutput;
    HANDLE hStdError  = loader->Config.StdError;

    switch (nStdHandle)
    {
    case STD_INPUT_HANDLE:
        if (hStdInput != NULL)
        {
            return hStdInput;
        }
        break;
    case STD_OUTPUT_HANDLE:
        if (hStdOutput != NULL)
        {
            return hStdOutput;
        }
        break;
    case STD_ERROR_HANDLE:
        if (hStdError != NULL)
        {
            return hStdError;
        }
        break;
    }
    return loader->GetStdHandle(nStdHandle);
}

__declspec(noinline)
static void hook_ExitProcess(UINT uExitCode)
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "ExitProcess: %zu\n", uExitCode);

    set_exit_code(uExitCode);

    loader->ExitProcess(uExitCode);
}

__declspec(noinline)
static void pe_entry_point()
{
    PELoader* loader = getPELoaderPointer();

    uint exitCode = ((uint(*)())(loader->EntryPoint))();
    hook_ExitProcess(exitCode);
}

static void set_exit_code(uint code)
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock(loader))
    {
        return;
    }

    *loader->ExitCode = code;

    ldr_unlock(loader);
}

static uint get_exit_code()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock(loader))
    {
        return 1;
    }

    uint code = *loader->ExitCode;

    if (!ldr_unlock(loader))
    {
        return 1;
    }
    return code;
}

__declspec(noinline)
uint LDR_Execute()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock(loader))
    {
        return 0x1001;
    }

    bool success = true;
    for (;;)
    {
        // make callback about DLL_PROCESS_DETACH
        if (loader->IsDLL)
        {
            DllMain_t dllMain = (DllMain_t)(loader->EntryPoint);
            HMODULE hModule  = (HMODULE)(loader->PEImage);
            DWORD   dwReason = DLL_PROCESS_ATTACH;
            // call entry point
            uint exitCode;
            if (dllMain(hModule, dwReason, NULL))
            {
                exitCode = 0;
            } else {
                exitCode = 1;
            }
            set_exit_code(exitCode);
            break;
        }
        // create thread at entry point
        void* addr = GetFuncAddr(&pe_entry_point);
        HANDLE hThread = loader->CreateThread(NULL, 0, addr, NULL, 0, NULL);
        if (hThread == NULL)
        {
            success = false;
            break;
        }
        // wait main thread exit
        if (loader->Config.WaitMain)
        {
            loader->WaitForSingleObject(hThread, INFINITE);
        }
        loader->CloseHandle(hThread);
        break;
    }

    if (!ldr_unlock(loader))
    {
        return 0x1002;
    }

    if (!success)
    {
        return 0x1003;
    }
    return get_exit_code();
}

__declspec(noinline)
errno LDR_Exit()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock(loader))
    {
        return ERR_LOADER_LOCK;
    }

    errno errno = ldr_exit_process();

    if (!ldr_unlock(loader))
    {
        return ERR_LOADER_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
errno LDR_Destroy()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock(loader))
    {
        return ERR_LOADER_LOCK;
    }

    errno errno = ldr_exit_process();

    // close global mutex
    if (!loader->CloseHandle(loader->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_LOADER_CLOSE_MUTEX;
    }

    // release memory page for PE image
    void* peImage = (void*)(loader->PEImage);
    RandBuf(peImage, loader->ImageSize);
    if (!loader->VirtualFree(peImage, 0, MEM_RELEASE) && errno == NO_ERROR)
    {
        errno = ERR_LOADER_FREE_PE_IMAGE;
    }

    // must copy variables in PELoader before call RandBuf
    VirtualFree_t virtualFree = loader->VirtualFree;
    void* memPage = loader->MainMemPage;
    // release main memory page
    RandBuf(memPage, MAIN_MEM_PAGE_SIZE);
    if (!loader->VirtualFree(memPage, 0, MEM_RELEASE) && errno == NO_ERROR)
    {
        errno = ERR_LOADER_FREE_MAIN_PAGE;
    }
    return errno;
}

static errno ldr_exit_process()
{
    PELoader* loader = getPELoaderPointer();

    // make callback about DLL_PROCESS_DETACH
    if (loader->IsDLL)
    {
        DllMain_t dllMain = (DllMain_t)(loader->EntryPoint);
        HMODULE hModule  = (HMODULE)(loader->PEImage);
        DWORD   dwReason = DLL_PROCESS_DETACH;
        uint exitCode;
        if (dllMain(hModule, dwReason, NULL))
        {
            exitCode = 0;
        } else {
            exitCode = 1;
        }
        set_exit_code(exitCode);
    }

    // call ExitProcess for terminate all threads
    errno errno = NO_ERROR;
    for (;;)
    {
        // create a thread for call ExitProcess
        void*  addr = GetFuncAddr(&hook_ExitProcess);
        HANDLE hThread = loader->CreateThread(NULL, 0, addr, NULL, 0, NULL);
        if (hThread == NULL)
        {
            errno = ERR_LOADER_CREATE_THREAD;
            break;
        }
        // wait thread exit
        loader->WaitForSingleObject(hThread, INFINITE);
        loader->CloseHandle(hThread);
        break;
    }
    return errno;
}

// prevent it be linked to other functions.
#pragma optimize("", off)
static void ldr_epilogue()
{
    byte var = 10;
    return;
}
#pragma optimize("", on)
