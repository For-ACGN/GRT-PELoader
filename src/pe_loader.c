#include "c_types.h"
#include "windows_t.h"
#include "lib_memory.h"
#include "random.h"
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

    // loader context
    void* MainMemPage; // store all structures

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
} PELoader;

static void* allocLoaderMemPage(PELoader_Cfg* cfg);
static bool  initLoaderAPI(PELoader* loader);
static errno loadPEImage(PELoader* loader);
static bool  parsePEImage(PELoader* loader);
static bool  mapSections(PELoader* loader);
static bool  fixRelocTable(PELoader* loader);
static bool  processIAT(PELoader* loader);
static bool  callEntryPoint(PELoader* loader);

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
        if (!initLoaderAPI(&loader))
        {
            errno = ERR_LOADER_INIT_API;
            break;
        }
        errno = loadPEImage(&loader);
        if (errno != NO_ERROR)
        {
            break;
        }
        break;
    }
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for loader
    PELoader_M* module = (PELoader_M*)moduleAddr;
    // core variable and return value
    module->EntryPoint;
    // loader module methods
    module->Execute;
    module->Destroy;
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
    dbg_log("[loader]", "Main Page: 0x%zX\n", addr);
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
        { 0x21E5E7E61968BBF4, 0x38FC2BB8B9E8F0B1 },  // VirtualAlloc
        { 0x7DDAB5BF4E742736, 0x6E0D1E4F5D19BE67 },  // VirtualFree
        { 0x6CF439115B558DE1, 0x7CAC9554D5A67E28 },  // VirtualProtect
        { 0x90BD05BA72DD948C, 0x253672CEAE439BB6 },  // LoadLibraryA
        { 0xF4E6DE881A59F6A0, 0xBC2E958CCBE70AA2 },  // GetProcAddress
        { 0x62E83480AE0AAFC7, 0x86C0AECD3EF92256 },  // CreateThread
        { 0xE8CA42297DA7319C, 0xAC51BC3A630A84FC },  // FlushInstructionCache
        { 0x04A85D44E64689B3, 0xBB2834EF8BE725C9 },  // CreateMutexA
        { 0x5B84A4B6173E4B44, 0x089FC914B21A66DA },  // ReleaseMutex
        { 0x91BB0A2A34E70890, 0xB2307F73C72A83BD },  // WaitForSingleObject
        { 0xB23064DF64282DE1, 0xD62F5C65075FCCE8 },  // CloseHandle
    };
#elif _WIN32
    {
        { 0x28310500, 0x51C40B22 },  // VirtualAlloc
        { 0xBC28097D, 0x4483038A },  // VirtualFree
        { 0x7B578622, 0x6950410A },  // VirtualProtect
        { 0x3DAF1E96, 0xD7E436F3 },  // LoadLibraryA
        { 0xE971801A, 0xEC6F6D90 },  // GetProcAddress
        { 0xD1AFE117, 0xDA772D98 },  // CreateThread
        { 0x73AFF9EE, 0x16AA8D66 },  // FlushInstructionCache
        { 0xFF3A4BBB, 0xD2F55A75 },  // CreateMutexA
        { 0x30B41C8C, 0xDD13B99D },  // ReleaseMutex
        { 0x4DF94300, 0x85D5CD6F },  // WaitForSingleObject
        { 0x7DC545BC, 0xCBD67153 },  // CloseHandle
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
    return true;
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
    return NO_ERROR;
}

static bool parsePEImage(PELoader* loader)
{
    uintptr imageAddr = (uintptr)(loader->Config.Image);
    uint32  peOffset  = *(uint32*)(imageAddr + 60);
    // parse FileHeader
    uint16 numSections   = *(uint16*)(imageAddr + peOffset + 6);
    uint16 optHeaderSize = *(uint16*)(imageAddr + peOffset + 20);
    // parse OptionalHeader
#ifdef _WIN64
    uint16 ddOffset = PE_OPT_HEADER_SIZE_64 - 16 * PE_DATA_DIRECTORY_SIZE;
#elif _WIN32
    uint16 ddOffset = PE_OPT_HEADER_SIZE_32 - 16 * PE_DATA_DIRECTORY_SIZE;
#endif
    uintptr dataDir = imageAddr + peOffset + PE_FILE_HEADER_SIZE + ddOffset;
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
    return true;
}

static bool mapSections(PELoader* loader)
{
    // allocate memory for PE image
    uint32 imageSize = loader->ImageSize;
    uintptr peImage = loader->VirtualAlloc(0, imageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (peImage == NULL)
    {
        return false;
    }
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
    return true;
}

static bool fixRelocTable(PELoader* runtime)
{
    uintptr peImage = runtime->PEImage;
    uintptr dataDir = runtime->DataDir;
    uintptr relocTable = peImage + *(uint32*)(dataDir + 5*PE_DATA_DIRECTORY_SIZE);
    uint32  tableSize = *(uint32*)(dataDir + 5*PE_DATA_DIRECTORY_SIZE + 4);
    uint64  addressOffset = (int64)(runtime->PEImage) - (int64)(runtime->ImageBase);
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

static bool processIAT(PELoader* runtime)
{
    uintptr peImage = runtime->PEImage;
    uintptr dataDir = runtime->DataDir;
    uintptr importTable = peImage + *(uint32*)(dataDir + 1*PE_DATA_DIRECTORY_SIZE);
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
        HMODULE hModule = runtime->LoadLibraryA(dllName);
        if (hModule == NULL)
        {
            // TODO release loaded library
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
            uintptr proc = runtime->GetProcAddress(hModule, procName);
            if (proc == NULL)
            {
                return false;
            }
            *(uintptr*)dstThunk = proc;
            srcThunk += sizeof(uintptr);
            dstThunk += sizeof(uintptr);
        }
        table += PE_IMPORT_DIRECTORY_SIZE;
    }
    runtime->ImportTable = importTable;
    return true;
}

static bool callEntryPoint(PELoader* runtime)
{
    uintptr peImage    = runtime->PEImage;
    uint32  imageSize  = runtime->ImageSize;
    uintptr entryPoint = runtime->EntryPoint;
    // change image memory protect for execute
    uint32 oldProtect;
    if (!runtime->VirtualProtect(peImage, imageSize, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        return false;
    }
    // flush instruction cache
    if (!runtime->FlushInstructionCache(-1, peImage, imageSize))
    {
        return false;
    }
    runtime->ExitCode = ((uint(*)())(peImage + entryPoint))();
    return true;
}
