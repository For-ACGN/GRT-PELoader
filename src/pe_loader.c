#include "c_types.h"
#include "windows_t.h"
#include "msvcrt_t.h"
#include "ucrtbase_t.h"
#include "pe_image.h"
#include "rel_addr.h"
#include "lib_string.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "win_api.h"
#include "random.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "debug.h"

#define MAIN_MEM_PAGE_SIZE 4096

typedef struct {
    // store config from argument
    Runtime_M*   Runtime;
    PELoader_Cfg Config;

    // API addresses
    VirtualAlloc_t          VirtualAlloc;
    VirtualFree_t           VirtualFree;
    VirtualProtect_t        VirtualProtect;
    VirtualLock_t           VirtualLock;
    VirtualUnlock_t         VirtualUnlock;
    LoadLibraryA_t          LoadLibraryA;
    FreeLibrary_t           FreeLibrary;
    GetProcAddress_t        GetProcAddress;
    CreateThread_t          CreateThread;
    ExitThread_t            ExitThread;
    FlushInstructionCache_t FlushInstructionCache;
    CreateMutexA_t          CreateMutexA;
    ReleaseMutex_t          ReleaseMutex;
    WaitForSingleObject_t   WaitForSingleObject;
    CloseHandle_t           CloseHandle;
    GetCommandLineA_t       GetCommandLineA;
    GetCommandLineW_t       GetCommandLineW;
    LocalFree_t             LocalFree;
    GetStdHandle_t          GetStdHandle;
    ExitProcess_t           ExitProcess;

    // loader context
    void*  MainMemPage; // store all structures
    void*  PEBackup;    // PE image backup
    bool   IsRunning;   // execute flag
    HANDLE hMutex;      // global mutex
    HANDLE StatusMu;    // lock loader status

    // store PE image information
    uintptr PEImage;
    uintptr DataDir;
    uintptr ImportTable;
    uint32  ImportTableSize;
    uintptr EntryPoint;
    uintptr ImageBase;
    uint32  ImageSize;
    uintptr Section;

    // store PE image NT header
    Image_FileHeader FileHeader;
    OptionalHeader   OptHeader;

    // about characteristics
    bool IsDLL;
    bool IsFixed;

    // store TLS data template
    void* TLSBlock;
    uint  TLSLen;

    // store TLS callback list
    TLSCallback_t* TLSList;

    // about command line arguments
    int     argc;
    LPSTR*  argv_a;
    LPWSTR* argv_w;

    // write return value
    uint* ExitCode;
} PELoader;

// PE loader methods
errno LDR_Execute();
errno LDR_Exit(uint exitCode);
errno LDR_Destroy();

// hard encoded address in getPELoaderPointer for replacement
#ifdef _WIN64
    #define PE_LOADER_POINTER 0x7FABCDEF222222FF
#elif _WIN32
    #define PE_LOADER_POINTER 0x7FAB22FF
#endif
static PELoader* getPELoaderPointer();

static bool ldr_lock();
static bool ldr_unlock();

static void* allocPELoaderMemPage(PELoader_Cfg* cfg);
static bool  initPELoaderAPI(PELoader* loader);
static bool  lockMainMemPage(PELoader* loader);
static bool  adjustPageProtect(PELoader* loader, DWORD* old);
static bool  recoverPageProtect(PELoader* loader, DWORD protect);
static bool  updatePELoaderPointer(PELoader* loader);
static bool  recoverPELoaderPointer(PELoader* loader);
static errno initPELoaderEnvironment(PELoader* loader);
static errno loadPEImage(PELoader* loader);
static bool  parsePEImage(PELoader* loader);
static bool  checkPEImage(PELoader* loader);
static bool  mapSections(PELoader* loader);
static bool  fixRelocTable(PELoader* loader);
static bool  initDelayload(PELoader* loader);
static bool  initTLSDirectory(PELoader* loader);
static void  prepareImportTable(PELoader* loader);
static bool  backupPEImage(PELoader* loader);
static bool  flushInstructionCache(PELoader* loader);

static void  erasePELoaderMethods(PELoader* loader);
static errno cleanPELoader(PELoader* loader);

static void* ldr_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
static void* ldr_GetMethods(LPCWSTR module, LPCSTR lpProcName);
static errno ldr_init_mutex();
static bool  ldr_copy_image();
static bool  ldr_process_import();
static void  ldr_alloc_tls_block();
static void  ldr_free_tls_block();
static void  ldr_tls_callback(DWORD dwReason);
static errno ldr_exit_process(UINT uExitCode);
static void  ldr_epilogue();

static void pe_entry_point();
static bool pe_dll_main(DWORD dwReason, bool setExitCode);
static void set_exit_code(uint code);
static uint get_exit_code();
static void set_running(bool run);
static bool is_running();
static void clean_run_data();

// hooks about kernel32.dll
LPSTR   hook_GetCommandLineA();
LPWSTR  hook_GetCommandLineW();
LPWSTR* hook_CommandLineToArgvW(LPCWSTR lpCmdLine, int* pNumArgs);
HANDLE  hook_GetStdHandle(DWORD nStdHandle);
HANDLE  hook_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId
);
void stub_ExecuteThread(LPVOID lpParameter);
void hook_ExitThread(DWORD dwExitCode);
void hook_ExitProcess(UINT uExitCode);

// hooks about msvcrt.dll
int __cdecl hook_msvcrt_getmainargs(
    int* argc, byte*** argv, byte*** env, int doWildCard, void* startInfo
);
int __cdecl hook_msvcrt_wgetmainargs(
    int* argc, uint16*** argv, uint16*** env, int doWildCard, void* startInfo
);
void __cdecl hook_msvcrt_exit(int exitcode);

// hooks about ucrtbase.dll
int*      __cdecl hook_ucrtbase_p_argc();
byte***   __cdecl hook_ucrtbase_p_argv();
uint16*** __cdecl hook_ucrtbase_p_wargv();
void      __cdecl hook_ucrtbase_exit(int exitcode);

void loadCommandLineToArgv(PELoader* loader);

PELoader_M* InitPELoader(Runtime_M* runtime, PELoader_Cfg* cfg)
{
    if (!InitDebugger())
    {
        SetLastErrno(ERR_LOADER_INIT_DEBUGGER);
        return NULL;
    }
    // alloc memory for store loader structure
    void* memPage = allocPELoaderMemPage(cfg);
    if (memPage == NULL)
    {
        SetLastErrno(ERR_LOADER_ALLOC_MEMORY);
        return NULL;
    }
    // set structure address
    uintptr address = (uintptr)memPage;
    uintptr loaderAddr = address + 1000 + RandUintN(address, 128);
    uintptr moduleAddr = address + 3000 + RandUintN(address, 128);
    // initialize structure
    PELoader* loader = (PELoader*)loaderAddr;
    mem_init(loader, sizeof(PELoader));
    // store config and context
    loader->Runtime = runtime;
    loader->Config  = *cfg;
    loader->MainMemPage = memPage;
    // initialize loader
    DWORD oldProtect = 0;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initPELoaderAPI(loader))
        {
            errno = ERR_LOADER_INIT_API;
            break;
        }
        if (!lockMainMemPage(loader))
        {
            errno = ERR_LOADER_LOCK_MAIN_MEM;
            break;
        }
        if (!adjustPageProtect(loader, &oldProtect))
        {
            errno = ERR_LOADER_ADJUST_PROTECT;
            break;
        }
        if (!updatePELoaderPointer(loader))
        {
            errno = ERR_LOADER_UPDATE_PTR;
            break;
        }
        errno = initPELoaderEnvironment(loader);
        if (errno != NO_ERROR)
        {
            break;
        }
        errno = loadPEImage(loader);
        if (errno != NO_ERROR)
        {
            break;
        }
        if (!backupPEImage(loader))
        {
            errno = ERR_LOADER_BACKUP_PE_IMAGE;
            break;
        }
        break;
    }
    if (errno == NO_ERROR || errno > ERR_LOADER_ADJUST_PROTECT)
    {
        erasePELoaderMethods(loader);
    }
    if (oldProtect != 0)
    {
        if (!recoverPageProtect(loader, oldProtect) && errno == NO_ERROR)
        {
            errno = ERR_LOADER_RECOVER_PROTECT;
        }
    }
    if (errno == NO_ERROR && !flushInstructionCache(loader))
    {
        errno = ERR_LOADER_FLUSH_INST;
    }
    if (errno != NO_ERROR)
    {
        cleanPELoader(loader);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for loader
    PELoader_M* module = (PELoader_M*)moduleAddr;
    // process variables
    module->EntryPoint = (void*)(loader->EntryPoint);
    module->ExitCode   = 0;
    // loader module methods
    module->Execute = GetFuncAddr(&LDR_Execute);
    module->Exit    = GetFuncAddr(&LDR_Exit);
    module->Destroy = GetFuncAddr(&LDR_Destroy);
    // record return value pointer;
    loader->ExitCode = &module->ExitCode;
    return module;
}

static void* allocPELoaderMemPage(PELoader_Cfg* cfg)
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
    SIZE_T size = MAIN_MEM_PAGE_SIZE;
    size += (1 + RandUintN(0, 16)) * 4096;
    LPVOID addr = virtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    RandBuffer(addr, (int64)size);
    dbg_log("[PE Loader]", "Main Memory Page: 0x%zX", addr);
    return addr;
}

static bool initPELoaderAPI(PELoader* loader)
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
        { 0xFAC73FAE41C0C2C8, 0xE7A0EE8E5CBAB70B }, // VirtualLock
        { 0x17C8D1591CA0850F, 0x64458856130C1CE7 }, // VirtualUnlock
        { 0x90BD05BA72DD948C, 0x253672CEAE439BB6 }, // LoadLibraryA
        { 0x0322C392AB9AE610, 0x2CF3559162E79E91 }, // FreeLibrary
        { 0xF4E6DE881A59F6A0, 0xBC2E958CCBE70AA2 }, // GetProcAddress
        { 0x62E83480AE0AAFC7, 0x86C0AECD3EF92256 }, // CreateThread
        { 0xE0846C4ED5129CD3, 0x8C8C31D65FAFC1C4 }, // ExitThread
        { 0xE8CA42297DA7319C, 0xAC51BC3A630A84FC }, // FlushInstructionCache
        { 0x04A85D44E64689B3, 0xBB2834EF8BE725C9 }, // CreateMutexA
        { 0x5B84A4B6173E4B44, 0x089FC914B21A66DA }, // ReleaseMutex
        { 0x91BB0A2A34E70890, 0xB2307F73C72A83BD }, // WaitForSingleObject
        { 0xB23064DF64282DE1, 0xD62F5C65075FCCE8 }, // CloseHandle
        { 0xEF31896F2FACEC04, 0x0E670990125E8E48 }, // GetCommandLineA
        { 0x701EF754FFADBDC2, 0x6D5BE783B0AF5812 }, // GetCommandLineW
        { 0xFCB18A0B702E8AB9, 0x8E1D5AE1A2FD9196 }, // LocalFree
        { 0x599C793AB3F4599E, 0xBBBA4AE31D6A6D8F }, // GetStdHandle
        { 0x131A9BBD85CB5E0D, 0x5126E3CBD1E0DB9A }, // ExitProcess
    };
#elif _WIN32
    {
        { 0x28310500, 0x51C40B22 }, // VirtualAlloc
        { 0xBC28097D, 0x4483038A }, // VirtualFree
        { 0x7B578622, 0x6950410A }, // VirtualProtect
        { 0x54914D83, 0xA9606A64 }, // VirtualLock
        { 0xCEDF8C40, 0x6D73766F }, // VirtualUnlock
        { 0x3DAF1E96, 0xD7E436F3 }, // LoadLibraryA
        { 0x2BC5BE30, 0xC2B2D69A }, // FreeLibrary
        { 0xE971801A, 0xEC6F6D90 }, // GetProcAddress
        { 0xD1AFE117, 0xDA772D98 }, // CreateThread
        { 0xC4471F00, 0x6B6811C7 }, // ExitThread
        { 0x73AFF9EE, 0x16AA8D66 }, // FlushInstructionCache
        { 0xFF3A4BBB, 0xD2F55A75 }, // CreateMutexA
        { 0x30B41C8C, 0xDD13B99D }, // ReleaseMutex
        { 0x4DF94300, 0x85D5CD6F }, // WaitForSingleObject
        { 0x7DC545BC, 0xCBD67153 }, // CloseHandle
        { 0xA187476E, 0x5AF922F3 }, // GetCommandLineA
        { 0xC15EF07A, 0x47A945CE }, // GetCommandLineW
        { 0x36B1013C, 0x0852225B }, // LocalFree    
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
    loader->VirtualLock           = list[0x03].proc;
    loader->VirtualUnlock         = list[0x04].proc;
    loader->LoadLibraryA          = list[0x05].proc;
    loader->FreeLibrary           = list[0x06].proc;
    loader->GetProcAddress        = list[0x07].proc;
    loader->CreateThread          = list[0x08].proc;
    loader->ExitThread            = list[0x09].proc;
    loader->FlushInstructionCache = list[0x0A].proc;
    loader->CreateMutexA          = list[0x0B].proc;
    loader->ReleaseMutex          = list[0x0C].proc;
    loader->WaitForSingleObject   = list[0x0D].proc;
    loader->CloseHandle           = list[0x0E].proc;
    loader->GetCommandLineA       = list[0x0F].proc;
    loader->GetCommandLineW       = list[0x10].proc;
    loader->LocalFree             = list[0x11].proc;
    loader->GetStdHandle          = list[0x12].proc;
    loader->ExitProcess           = list[0x13].proc;
    return true;
}

static bool lockMainMemPage(PELoader* loader)
{
#ifndef NO_RUNTIME
    if (!loader->VirtualLock(loader->MainMemPage, 0))
    {
        return false;
    }
#endif // NO_RUNTIME
    return true;
}

// CANNOT merge updatePELoaderPointer and recoverPELoaderPointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

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

static bool recoverPELoaderPointer(PELoader* loader)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getPELoaderPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)loader)
        {
            target++;
            continue;
        }
        *pointer = PE_LOADER_POINTER;
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
        return ERR_LOADER_CREATE_G_MUTEX;
    }
    loader->hMutex = hMutex;
    return NO_ERROR;
}

static errno loadPEImage(PELoader* loader)
{
    if (!parsePEImage(loader))
    {
        return ERR_LOADER_PARSE_PE_IMAGE;
    }
    if (!checkPEImage(loader))
    {
        return ERR_LOADER_CHECK_PE_IMAGE;
    }
    if (!mapSections(loader))
    {
        return ERR_LOADER_MAP_SECTIONS;
    }
    if (!fixRelocTable(loader))
    {
        return ERR_LOADER_FIX_RELOC_TABLE;
    }
    if (!initDelayload(loader))
    {
        return ERR_LOADER_INIT_DELAYLOAD;
    }
    if (!initTLSDirectory(loader))
    {
        return ERR_LOADER_INIT_TLS_DIRECTORY;
    }
    prepareImportTable(loader);
    dbg_log("[PE Loader]", "PE Image: 0x%zX", loader->PEImage);
    return NO_ERROR;
}

static bool parsePEImage(PELoader* loader)
{
    uintptr imageAddr = (uintptr)(loader->Config.Image);
    // check image file header
    if (imageAddr == 0)
    {
        return false;
    }
    if ((*(byte*)(imageAddr+0)^0x7C) != ('M'^0x7C))
    {
        return false;
    }
    if ((*(byte*)(imageAddr+1)^0xA3) != ('Z'^0xA3))
    {
        return false;
    }
    // skip DOS stub
    uint32  peOffset = *(uint32*)(imageAddr + DOS_HEADER_SIZE - 4);
    uintptr peBase = imageAddr + peOffset + NT_HEADER_SIGNATURE_SIZE;
    // parse FileHeader
    Image_FileHeader* fileHeader = (Image_FileHeader*)(peBase);
    WORD characteristics = fileHeader->Characteristics;
    // check is a executable image
    if (!(characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
    {
        return false;
    }
    // parse OptionalHeader
    uintptr headerAddr = peBase + sizeof(Image_FileHeader);
#ifdef _WIN64
    OptionalHeader* optHeader = (OptionalHeader64*)(headerAddr);
#elif _WIN32
    OptionalHeader* optHeader = (OptionalHeader32*)(headerAddr);
#endif
    // calculate data directory offset
    uint16  ddOffset = arrlen(optHeader->DataDirectory) * sizeof(Image_DataDirectory);
    uintptr dataDir  = headerAddr + sizeof(OptionalHeader) - ddOffset;
    // calculate the address of the first Section
    uintptr section = headerAddr + sizeof(OptionalHeader);
    // store result
    loader->DataDir    = dataDir;
    loader->EntryPoint = optHeader->AddressOfEntryPoint;
    loader->ImageBase  = optHeader->ImageBase;
    loader->ImageSize  = optHeader->SizeOfImage;
    loader->Section    = section;
    loader->FileHeader = *fileHeader;
    loader->OptHeader  = *optHeader;
    loader->IsDLL   = characteristics & IMAGE_FILE_DLL;
    loader->IsFixed = characteristics & IMAGE_FILE_RELOCS_STRIPPED;
    return true;
}

static bool checkPEImage(PELoader* loader)
{
    Image_FileHeader* FileHeader = &loader->FileHeader;
    // check PE image architecture
#ifdef _WIN64
    uint16 arch = IMAGE_FILE_MACHINE_AMD64;
#elif _WIN32
    uint16 arch = IMAGE_FILE_MACHINE_I386;
#endif
    if (arch != FileHeader->Machine)
    {
        return false;
    }
    dbg_log("[PE Loader]", "Characteristics: 0x%X", FileHeader->Characteristics);
    return true;
}

static bool mapSections(PELoader* loader)
{
    // select the memory page address
    LPVOID base = NULL;
    if (loader->IsFixed)
    {
        base = (LPVOID)(loader->OptHeader.ImageBase);
    }
    // append random memory size to image tail
    uint64 seed = (uint64)(GetFuncAddr(&InitPELoader));
    uint32 size = loader->ImageSize;
    size += (uint32)((1 + RandUintN(seed, 128)) * 4096);
    // allocate memory for write PE image 
    void* mem = loader->VirtualAlloc(base, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem == NULL)
    {
        return false;
    }
    loader->PEImage = (uintptr)mem;
    // lock memory region with special argument for reuse PE image
#ifndef NO_RUNTIME
    if (!loader->VirtualLock(mem, 0))
    {
        return false;
    }
#endif // NO_RUNTIME
    // map PE image sections to the memory
    uintptr peImage   = (uintptr)mem;
    uintptr imageAddr = (uintptr)(loader->Config.Image);
    uintptr section   = loader->Section;
    for (uint16 i = 0; i < loader->FileHeader.NumberOfSections; i++)
    {
        uint32 virtualAddress   = *(uint32*)(section + 12);
        uint32 sizeOfRawData    = *(uint32*)(section + 16);
        uint32 pointerToRawData = *(uint32*)(section + 20);
        byte* dst = (byte*)(peImage + virtualAddress);
        byte* src = (byte*)(imageAddr + pointerToRawData);
        mem_copy(dst, src, sizeOfRawData);
        section += PE_SECTION_HEADER_SIZE;
    }
    // update EntryPoint absolute address
    loader->EntryPoint += peImage;
    return true;
}

static bool fixRelocTable(PELoader* loader)
{
    if (loader->IsFixed)
    {
        return true;
    }
    uintptr peImage = loader->PEImage;
    uintptr dataDir = loader->DataDir;
    uintptr ddAddr  = dataDir + IMAGE_DIRECTORY_ENTRY_BASERELOC * PE_DATA_DIRECTORY_SIZE;
    Image_DataDirectory dd = *(Image_DataDirectory*)(ddAddr);
    uintptr relocTable = peImage + dd.VirtualAddress;
    uint32  tableSize  = dd.Size;
    // check need relocation
    if (tableSize == 0)
    {
        return true;
    }
    void*  tableAddr  = (void*)relocTable; // for erase table after
    uint64 addrOffset = (int64)(loader->PEImage) - (int64)(loader->ImageBase);
    for (;;)
    {
        Image_BaseRelocation* baseReloc = (Image_BaseRelocation*)(relocTable);
        if (baseReloc->VirtualAddress == 0)
        {
            break;
        }
        uintptr relocPtr = relocTable + 8;
        uintptr dstAddr  = peImage + baseReloc->VirtualAddress;
        for (uint32 i = 0; i < (baseReloc->SizeOfBlock - 8) / 2; i++)
        {
            Image_Reloc reloc = *(Image_Reloc*)(relocPtr);
            uint32* patchAddr32;
            uint64* patchAddr64;
            switch (reloc.Type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                patchAddr32 = (uint32*)(dstAddr + reloc.Offset);
                *patchAddr32 += (uint32)(addrOffset);
                break;
            case IMAGE_REL_BASED_DIR64:
                patchAddr64 = (uint64*)(dstAddr + reloc.Offset);
                *patchAddr64 += (uint64)(addrOffset);
                break;
            default:
                return false;
            }
            relocPtr += sizeof(Image_Reloc);
        }
        relocTable += baseReloc->SizeOfBlock;
    }
    // destroy table for prevent extract raw PE image
    RandBuffer(tableAddr, tableSize);
    return true;
}

static bool initDelayload(PELoader* loader)
{
    Runtime_M* runtime = loader->Runtime;

    uintptr peImage = loader->PEImage;
    uintptr dataDir = loader->DataDir;
    uintptr ddAddr  = dataDir + IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT * PE_DATA_DIRECTORY_SIZE;
    Image_DataDirectory dd = *(Image_DataDirectory*)(ddAddr);
    uintptr dlTable   = peImage + dd.VirtualAddress;
    uint32  tableSize = dd.Size;
    // check need initialize delayload
    if (tableSize == 0)
    {
        return true;
    }
    void* tableAddr = (void*)dlTable; // for erase table after
    Image_DelayloadDescriptor* dld = (Image_DelayloadDescriptor*)(dlTable);
    for (;;)
    {
        if (dld->DllNameRVA == 0)
        {
            break;
        }
        // check the target DLL is loaded
        LPSTR  dllName  = (LPSTR)(peImage + dld->DllNameRVA);
        LPWSTR dllNameW = runtime->WinBase.ANSIToUTF16(dllName);
        if (dllNameW == NULL)
        {
            return false;
        }
        HMODULE hModule = GetModuleHandle(dllNameW);
        runtime->Memory.Free(dllNameW);
        if (hModule == NULL)
        {
            hModule = loader->LoadLibraryA(dllName);
            dbg_log("[PE Loader]", "Lazy LoadLibrary: %s", dllName);
        } else {
            dbg_log("[PE Loader]", "Already LoadLibrary: %s", dllName);
        }
        if (hModule == NULL)
        {
            return false;
        }
        Image_ThunkData* nameTable = (Image_ThunkData*)(peImage + dld->ImportNameTableRVA);
        Image_ThunkData* addrTable = (Image_ThunkData*)(peImage + dld->ImportAddressTableRVA);
        Image_ImportByName* ibn;
        for (;;)
        {
            if (nameTable->u1.AddressOfData == 0)
            {
                break;
            }
            void* proc;
            if (IMAGE_SNAP_BY_ORDINAL(nameTable->u1.Ordinal))
            {
                proc = ldr_GetProcAddress(hModule, (LPSTR)(nameTable->u1.Ordinal));
            } else {
                ibn = (Image_ImportByName*)(peImage + nameTable->u1.AddressOfData);
                proc = ldr_GetProcAddress(hModule, ibn->Name);
            }
            if (proc == NULL)
            {
                return false;
            }
            addrTable->u1.Function = (QWORD)proc;
            nameTable++;
            addrTable++;
        }
        dld++;
    }
    // destroy table for prevent extract raw PE image
    RandBuffer(tableAddr, tableSize);
    return true;
}

static bool initTLSDirectory(PELoader* loader)
{
    uintptr peImage = loader->PEImage;
    uintptr dataDir = loader->DataDir;
    uintptr ddAddr  = dataDir + IMAGE_DIRECTORY_ENTRY_TLS * PE_DATA_DIRECTORY_SIZE;
    Image_DataDirectory dd = *(Image_DataDirectory*)(ddAddr);
    uintptr tlsTable  = peImage + dd.VirtualAddress;
    uint32  tableSize = dd.Size;
    // check need initialize tls callback
    if (tableSize == 0)
    {
        return true;
    }
    Image_TLSDirectory* tls = (Image_TLSDirectory*)(tlsTable);

    // allocate memory for copy template data
    // the first 16 bytes for store original TLS address and align
    uint size  = tls->EndAddressOfRawData - tls->StartAddressOfRawData;
    uint total = 16 + size + tls->SizeOfZeroFill;
    // allocate memory for write PE image
    uint  pSize = total + (uint)((1 + RandUintN((uint64)tls, 8)) * 4096);
    void* block = loader->VirtualAlloc(NULL, pSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (block == NULL)
    {
        return false;
    }
    RandBuffer(block, (int64)size);
    loader->TLSBlock = block;
    loader->TLSLen   = total;
#ifndef NO_RUNTIME
    // lock memory region with special argument for reuse PE image
    if (!loader->VirtualLock(block, 0))
    {
        return false;
    }
#endif // NO_RUNTIME
    uintptr start = (uintptr)block + 16;
    mem_copy((void*)(start), (void*)(tls->StartAddressOfRawData), size);
    mem_init((void*)(start + size), tls->SizeOfZeroFill);
    dbg_log("[PE Loader]", "TLS block template: 0x%zX", block);

    // record tls callback list
    loader->TLSList = (TLSCallback_t*)(tls->AddressOfCallBacks);

    // destroy table for prevent extract raw PE image
    RandBuffer((byte*)tlsTable, tableSize);
    return true;
}

static void prepareImportTable(PELoader* loader)
{
    uintptr peImage = loader->PEImage;
    uintptr dataDir = loader->DataDir;
    uintptr ddAddr  = dataDir + IMAGE_DIRECTORY_ENTRY_IMPORT * PE_DATA_DIRECTORY_SIZE;
    Image_DataDirectory dd = *(Image_DataDirectory*)(ddAddr);

    loader->ImportTable     = peImage + dd.VirtualAddress;
    loader->ImportTableSize = dd.Size;
}

// backupPEImage is used to execute PE image multi times.
static bool backupPEImage(PELoader* loader)
{
    // append random memory size to tail
    uint64 seed = (uint64)(GetFuncAddr(&InitPELoader)) + 4096;
    uint32 size = loader->ImageSize;
    size += (uint32)((1 + RandUintN(seed, 128)) * 4096);
    // allocate memory for write PE image
    void* mem = loader->VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (mem == NULL)
    {
        return false;
    }
    RandBuffer(mem, (int64)size);
    loader->PEBackup = mem;
    // copy mapped PE image
    mem_copy(mem, (void*)(loader->PEImage), loader->ImageSize);
#ifndef NO_RUNTIME
    // lock memory region with special argument for reuse PE image
    if (!loader->VirtualLock(mem, 0))
    {
        return false;
    }
#endif // NO_RUNTIME
    return true;
}

static bool flushInstructionCache(PELoader* loader)
{
    uintptr begin = (uintptr)(GetFuncAddr(&InitPELoader));
    uintptr end   = (uintptr)(GetFuncAddr(&ldr_epilogue));
    uint    size  = end - begin;
    return loader->FlushInstructionCache(CURRENT_PROCESS, (LPCVOID)begin, size);
}

__declspec(noinline)
static void erasePELoaderMethods(PELoader* loader)
{
    if (loader->Config.NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&allocPELoaderMemPage));
    uintptr end   = (uintptr)(GetFuncAddr(&erasePELoaderMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

// ======================== these instructions will not be erased ========================

// change memory protect for dynamic update pointer that hard encode.
__declspec(noinline)
static bool adjustPageProtect(PELoader* loader, DWORD* old)
{
    if (loader->Config.NotAdjustProtect)
    {
        return true;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&InitPELoader));
    uintptr end   = (uintptr)(GetFuncAddr(&ldr_epilogue));
    uint    size  = end - begin;
    return loader->VirtualProtect((void*)begin, size, PAGE_EXECUTE_READWRITE, old);
}

__declspec(noinline)
static bool recoverPageProtect(PELoader* loader, DWORD protect)
{
    if (loader->Config.NotAdjustProtect)
    {
        return true;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&InitPELoader));
    uintptr end   = (uintptr)(GetFuncAddr(&ldr_epilogue));
    uint    size  = end - begin;
    DWORD   old;
    return loader->VirtualProtect((void*)begin, size, protect, &old);
}

static errno cleanPELoader(PELoader* loader)
{
    errno errno = NO_ERROR;

    CloseHandle_t   closeHandle   = loader->CloseHandle;
    FreeLibrary_t   freeLibrary   = loader->FreeLibrary;
    VirtualUnlock_t virtualUnlock = loader->VirtualUnlock;
    VirtualFree_t   virtualFree   = loader->VirtualFree;

    if (closeHandle != NULL)
    {
        // close global mutex
        if (loader->hMutex != NULL)
        {
            if (!closeHandle(loader->hMutex) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_CLEAN_G_MUTEX;
            }
        }
        // close status mutex
        if (loader->StatusMu != NULL)
        {
            if (!closeHandle(loader->StatusMu) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_CLEAN_S_MUTEX;
            }
        }
    }

#ifndef NO_RUNTIME
    if (freeLibrary != NULL)
    {
        // free all tracked librarys
        if (!freeLibrary(NULL) && errno == NO_ERROR)
        {
            errno = ERR_LOADER_FREE_LIBRARY;
        }
    }
#endif // NO_RUNTIME

    void* memPage  = loader->MainMemPage;
    void* peImage  = (void*)(loader->PEImage);
    void* peBackup = loader->PEBackup;
    void* tlsBlock = loader->TLSBlock;

    if (virtualUnlock != NULL)
    {
        // unlock memory page for PE image
        if (peImage != NULL)
        {
            if (!virtualUnlock(peImage, 0) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_UNLOCK_PE_IMAGE;
            }
        }
        // unlock memory page for PE image backup
        if (peBackup != NULL)
        {
            if (!virtualUnlock(peBackup, 0) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_UNLOCK_BACKUP;
            }
        }
        // unlock memory page for TLS block template
        if (tlsBlock != NULL)
        {
            if (!virtualUnlock(tlsBlock, 0) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_UNLOCK_TLS_BLOCK;
            }
        }
        // unlock main memory page for structure
        if (memPage != NULL)
        {
            if (!virtualUnlock(memPage, 0) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_UNLOCK_MAIN_MEM;
            }
        }
    }

    if (virtualFree != NULL)
    {
        // release memory page for PE image
        if (peImage != NULL)
        {
            RandBuffer(peImage, loader->ImageSize);
            if (!virtualFree(peImage, 0, MEM_RELEASE) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_FREE_PE_IMAGE;
            }
        }
        // release memory page for PE image backup
        if (peBackup != NULL)
        {
            RandBuffer(peBackup, loader->ImageSize);
            if (!virtualFree(peBackup, 0, MEM_RELEASE) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_FREE_BACKUP;
            }
        }
        // release memory page for TLS block template
        if (tlsBlock != NULL)
        {
            RandBuffer(tlsBlock, loader->TLSLen);
            if (!virtualFree(tlsBlock, 0, MEM_RELEASE) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_FREE_TLS_BLOCK;
            }
        }
        // release main memory page
        if (memPage != NULL)
        {
            RandBuffer(memPage, MAIN_MEM_PAGE_SIZE);
            if (!virtualFree(memPage, 0, MEM_RELEASE) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_FREE_MAIN_MEM;
            }
        }
    }
    return errno;
}

// updatePELoaderPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updatePELoaderPointer will fail.
#pragma optimize("", off)
static PELoader* getPELoaderPointer()
{
    uintptr pointer = PE_LOADER_POINTER;
    return (PELoader*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static bool ldr_lock()
{
    PELoader* loader = getPELoaderPointer();

    uint32 event = loader->WaitForSingleObject(loader->hMutex, INFINITE);
    return event == WAIT_OBJECT_0;
}

__declspec(noinline)
static bool ldr_unlock()
{
    PELoader* loader = getPELoaderPointer();

    return loader->ReleaseMutex(loader->hMutex);
}

__declspec(noinline)
void* ldr_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    PELoader* loader = getPELoaderPointer();

    // process ordinal import
    if (lpProcName <= (LPCSTR)(0xFFFF))
    {
        dbg_log("[PE Loader]", "GetProcAddress: %d", lpProcName);
        return loader->GetProcAddress(hModule, lpProcName);
    }
    dbg_log("[PE Loader]", "GetProcAddress: %s", lpProcName);
    // use "mem_init" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    uint16 module[MAX_PATH];
    mem_init(module, sizeof(module));
    // get module file name
    if (GetModuleFileName(hModule, module, sizeof(module)) == 0)
    {
        return NULL;
    }
    // check is PE Loader internal methods
    void* method = ldr_GetMethods(module, lpProcName);
    if (method != NULL)
    {
        return method;
    }
    return loader->GetProcAddress(hModule, lpProcName);
}

__declspec(noinline)
static void* ldr_GetMethods(LPCWSTR module, LPCSTR lpProcName)
{
    typedef struct {
        uint hash; uint key; void* method;
    } method;
    method methods[] =
#ifdef _WIN64
    {
        { 0x1DE95D906D270C1E, 0x2672227B97F5DAD9, GetFuncAddr(&ldr_GetProcAddress)       },
        { 0x1848E44B66F18C48, 0x16480B2B71CCBA71, GetFuncAddr(&hook_GetCommandLineA)     },
        { 0x6CDF268D5D259686, 0xB2ECF3E4AAC267BA, GetFuncAddr(&hook_GetCommandLineW)     },
        { 0x091A5CA0D803A190, 0x01DDBC313ED0F7ED, GetFuncAddr(&hook_CommandLineToArgvW)  },
        { 0xD64DA86D6A985B33, 0xE8DAF74FBC29AF11, GetFuncAddr(&hook_GetStdHandle)        },
        { 0x9B91E956B96D6389, 0xEBB723BF1CEE4569, GetFuncAddr(&hook_CreateThread)        },
        { 0x053D2B184D2AD724, 0x5DFCC08DACB101DD, GetFuncAddr(&hook_ExitThread)          },
        { 0x003837989C804A7A, 0x77BACCABEB6CE508, GetFuncAddr(&hook_ExitProcess)         },
        { 0x8D91B93B7BFC89B4, 0x428A7543FADEEF29, GetFuncAddr(&hook_msvcrt_getmainargs)  },
        { 0xB6627A6DDB0A9B1A, 0x729C834DB43EB70A, GetFuncAddr(&hook_msvcrt_wgetmainargs) },
        { 0x4B7D921A385FB3D2, 0xC579F5ED84E53139, GetFuncAddr(&hook_msvcrt_exit)         },
        { 0x677E9E5FFC09596F, 0xF0CDF0DC4A6693B0, GetFuncAddr(&hook_ucrtbase_p_argc)     },
        { 0x348408E3C4C1F84A, 0x00D6384B5E49BE4E, GetFuncAddr(&hook_ucrtbase_p_argv)     },
        { 0xE4963C275A179C3A, 0x56818722C1E69D4F, GetFuncAddr(&hook_ucrtbase_p_wargv)    },
        { 0xD806168873719B4E, 0x477C6E75E8D61A35, GetFuncAddr(&hook_ucrtbase_exit)       },
    };
#elif _WIN32
    {
        { 0x336C0B7C, 0xE6FD5E12, GetFuncAddr(&ldr_GetProcAddress)       },
        { 0x027AFDAA, 0x6F1EE876, GetFuncAddr(&hook_GetCommandLineA)     },
        { 0x76C60C20, 0x10FA5D7C, GetFuncAddr(&hook_GetCommandLineW)     },
        { 0xABE5D9A9, 0x32898C57, GetFuncAddr(&hook_CommandLineToArgvW)  },
        { 0x7DF993F6, 0x4AB8D860, GetFuncAddr(&hook_GetStdHandle)        },
        { 0x0465FE82, 0x70880E4A, GetFuncAddr(&hook_CreateThread)        },
        { 0x4F0C77BA, 0x89DD7B71, GetFuncAddr(&hook_ExitThread)          },
        { 0xB439D7F0, 0xF97FF53F, GetFuncAddr(&hook_ExitProcess)         },
        { 0xEC3DD822, 0x91377248, GetFuncAddr(&hook_msvcrt_getmainargs)  },
        { 0x44C32027, 0x354751F7, GetFuncAddr(&hook_msvcrt_wgetmainargs) },
        { 0xF1E55A4D, 0x9A112CBD, GetFuncAddr(&hook_msvcrt_exit)         },
        { 0x9E4AA9D4, 0xA97CC100, GetFuncAddr(&hook_ucrtbase_p_argc)     },
        { 0x4029DD68, 0x4F1713D1, GetFuncAddr(&hook_ucrtbase_p_argv)     },
        { 0x21EF5083, 0xA44FD76E, GetFuncAddr(&hook_ucrtbase_p_wargv)    },
        { 0x1207ACD2, 0x8560B050, GetFuncAddr(&hook_ucrtbase_exit)       },
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

static errno ldr_init_mutex()
{
    PELoader* loader = getPELoaderPointer();

    // close old status mutex
    if (loader->StatusMu != NULL)
    {
        loader->CloseHandle(loader->StatusMu);
    }
    // create new status mutex
    HANDLE statusMu = loader->CreateMutexA(NULL, false, NULL);
    if (statusMu == NULL)
    {
        return ERR_LOADER_CREATE_S_MUTEX;
    }
    loader->StatusMu = statusMu;
    return NO_ERROR;
}

static bool ldr_copy_image()
{
    PELoader* loader = getPELoaderPointer();

    if (loader->WaitForSingleObject(loader->StatusMu, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    // recovery PE image from backup for process data like global variable
    mem_copy((void*)loader->PEImage, loader->PEBackup, loader->ImageSize);

    return loader->ReleaseMutex(loader->StatusMu);
}

__declspec(noinline)
static bool ldr_process_import()
{
    PELoader* loader = getPELoaderPointer();

    uintptr peImage     = loader->PEImage;
    uintptr importTable = loader->ImportTable;
    uint32  tableSize   = loader->ImportTableSize;
    // check need import
    if (tableSize == 0)
    {
        return true;
    }
    // load library and fix function address
    Image_ImportDescriptor* import = (Image_ImportDescriptor*)(importTable);
    for (;;)
    {
        if (import->Name == 0)
        {
            break;
        }
        LPCSTR  dllName = (LPCSTR)(peImage + import->Name);
        HMODULE hModule = loader->LoadLibraryA(dllName);
        if (hModule == NULL)
        {
            return false;
        }
        dbg_log("[PE Loader]", "LoadLibrary: %s", dllName);
        uintptr srcThunk;
        uintptr dstThunk;
        if (import->OriginalFirstThunk != 0)
        {
            srcThunk = peImage + import->OriginalFirstThunk;
        } else {
            srcThunk = peImage + import->FirstThunk;
        }
        dstThunk = peImage + import->FirstThunk;
        // fix function address
        for (;;)
        {
            uintptr value = *(uintptr*)srcThunk;
            if (value == 0)
            {
                break;
            }
            LPCSTR procName;
            if (IMAGE_SNAP_BY_ORDINAL(value))
            {
                procName = (LPCSTR)(value & 0xFFFF);
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
        import++;
    }
    return true;
}

__declspec(noinline)
static void ldr_alloc_tls_block()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    if (loader->TLSBlock == NULL)
    {
        return;
    }

    // prepare TLS block data memory page
    void* tls = runtime->Memory.Alloc(loader->TLSLen);
    if (tls == NULL)
    {
        return;
    }
    mem_copy(tls, loader->TLSBlock, loader->TLSLen);

    // read the original TLS block address
#ifdef _WIN64
    uintptr* tlsPtr = (uintptr*)(__readgsqword(0x58));
#elif _WIN32
    uintptr* tlsPtr = (uintptr*)(__readfsdword(0x2C));
#endif

    // store the original TLS block address
    uintptr block = *tlsPtr;
    mem_copy(tls, &block, sizeof(tlsPtr));

    // replace the original TLS block address
    *tlsPtr = (uintptr)tls + 16;

    dbg_log("[PE Loader]", "allocate TLS block: 0x%zX", tls);
}

__declspec(noinline)
static void ldr_free_tls_block()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    if (loader->TLSBlock == NULL)
    {
        return;
    }

    // read the hooked TLS block address
#ifdef _WIN64
    uintptr* tlsPtr = (uintptr*)(__readgsqword(0x58));
#elif _WIN32
    uintptr* tlsPtr = (uintptr*)(__readfsdword(0x2C));
#endif

    // read the original TLS block address
    void* tls = (void*)(*tlsPtr - 16);

    // restore the original TLS block address
    *tlsPtr = *(uintptr*)tls;

    // free TLS block data
    runtime->Memory.Free(tls);

    dbg_log("[PE Loader]", "free TLS block: 0x%zX", tls);
}

__declspec(noinline)
static void ldr_tls_callback(DWORD dwReason)
{
    PELoader* loader = getPELoaderPointer();

    if (loader->TLSList == NULL)
    {
        return;
    }

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        dbg_log("[PE Loader]", "call TLS callback with DLL_PROCESS_ATTACH");
        break;
    case DLL_PROCESS_DETACH:
        dbg_log("[PE Loader]", "call TLS callback with DLL_PROCESS_DETACH");
        break;
    case DLL_THREAD_ATTACH:
        dbg_log("[PE Loader]", "call TLS callback with DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        dbg_log("[PE Loader]", "call TLS callback with DLL_THREAD_DETACH");
        break;
    }

    TLSCallback_t* list = loader->TLSList;
    while (*list != NULL)
    {
        TLSCallback_t callback = (TLSCallback_t)(*list);
        callback((HMODULE)(loader->PEImage), dwReason, NULL);
        list++;
        dbg_log("[PE Loader]", "call TLS callback: 0x%zX", callback);
    }
}

static errno ldr_exit_process(UINT uExitCode)
{
    PELoader* loader = getPELoaderPointer();

    // call ExitProcess for terminate all threads
    errno errno = NO_ERROR;
    for (;;)
    {
        // create a thread for call ExitProcess
        void* addr = GetFuncAddr(&hook_ExitProcess);
        void* para = (LPVOID)(uExitCode);
        HANDLE hThread = loader->CreateThread(NULL, 0, addr, para, 0, NULL);
        if (hThread == NULL)
        {
            errno = ERR_LOADER_CREATE_EXIT_THREAD;
            break;
        }
        // wait exit process thread exit
        loader->WaitForSingleObject(hThread, INFINITE);
        loader->CloseHandle(hThread);
        break;
    }

    // make callback about DLL_PROCESS_DETACH
    if (loader->IsDLL)
    {
        pe_dll_main(DLL_PROCESS_DETACH, true);
    }
    return errno;
}

__declspec(noinline)
LPSTR hook_GetCommandLineA()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "GetCommandLineA");

    // try to get it from config
    LPSTR cmdLine = loader->Config.CommandLineA;
    if (cmdLine != NULL)
    {
        return cmdLine;
    }
    return loader->GetCommandLineA();
}

__declspec(noinline)
LPWSTR hook_GetCommandLineW()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "GetCommandLineW");

    // try to get it from config
    LPWSTR cmdLine = loader->Config.CommandLineW;
    if (cmdLine != NULL)
    {
        return cmdLine;
    }
    return loader->GetCommandLineW();
}

__declspec(noinline)
LPWSTR* hook_CommandLineToArgvW(LPCWSTR lpCmdLine, int* pNumArgs)
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "CommandLineToArgvW: \"%ls\"", lpCmdLine);

    // find shell32.CommandLineToArgvW
#ifdef _WIN64
    uint hash = 0x4A48978496F59E02;
    uint key  = 0xC735570A84698151;
#elif _WIN32
    uint hash = 0xD7007E2E;
    uint key  = 0x15875D48;
#endif
    CommandLineToArgvW_t CommandLineToArgvW = loader->Config.FindAPI(hash, key);
    if (CommandLineToArgvW == NULL)
    {
        return NULL;
    }

    // if lpCmdLine is not L"", call the original function
    uint16 empty[] = { 0x0000 };
    if (strcmp_w((UTF16)lpCmdLine, empty) != 0)
    {
        return CommandLineToArgvW(lpCmdLine, pNumArgs);
    }

    LPWSTR cmdLine = hook_GetCommandLineW();
    return CommandLineToArgvW(cmdLine, pNumArgs);
}

__declspec(noinline)
HANDLE hook_GetStdHandle(DWORD nStdHandle)
{
    PELoader* loader = getPELoaderPointer();

    // try to get it from config
    HANDLE hStdInput  = loader->Config.StdInput;
    HANDLE hStdOutput = loader->Config.StdOutput;
    HANDLE hStdError  = loader->Config.StdError;

    switch (nStdHandle)
    {
    case STD_INPUT_HANDLE:
        if (hStdInput != NULL)
        {
            dbg_log("[PE Loader]", "Get STD_INPUT_HANDLE");
            return hStdInput;
        }
        break;
    case STD_OUTPUT_HANDLE:
        if (hStdOutput != NULL)
        {
            dbg_log("[PE Loader]", "Get STD_OUTPUT_HANDLE");
            return hStdOutput;
        }
        break;
    case STD_ERROR_HANDLE:
        if (hStdError != NULL)
        {
            dbg_log("[PE Loader]", "Get STD_ERROR_HANDLE");
            return hStdError;
        }
        break;
    }
    return loader->GetStdHandle(nStdHandle);
}

typedef struct {
    POINTER lpStartAddress;
    LPVOID  lpParameter;
} createThreadCtx;

typedef void (*func_entry_t)(LPVOID lpParameter);

__declspec(noinline)
HANDLE hook_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId
){
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "CreateThread: 0x%zX", lpStartAddress);

    // alloc memory for store actual StartAddress and Parameter
    uint size = sizeof(createThreadCtx);
    size += (1 + RandUintN((uint64)lpParameter, 4)) * 4096;
    LPVOID parameter = runtime->Memory.Alloc(size);
    if (parameter == NULL)
    {
        return NULL;
    }

    createThreadCtx* ctx = (createThreadCtx*)parameter;
    ctx->lpStartAddress = lpStartAddress;
    ctx->lpParameter    = lpParameter;

    // create thread at stub, that function will call actual StartAddress
    void* addr = GetFuncAddr(&stub_ExecuteThread);
    HANDLE hThread = loader->CreateThread
    (
        lpThreadAttributes, dwStackSize, addr,
        parameter, dwCreationFlags, lpThreadId
    );
    return hThread;
}

__declspec(noinline)
void stub_ExecuteThread(LPVOID lpParameter)
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    // copy arguments from context 
    createThreadCtx* ctx = (createThreadCtx*)lpParameter;
    POINTER startAddress = ctx->lpStartAddress;
    LPVOID  parameter    = ctx->lpParameter;
    runtime->Memory.Free(lpParameter);

    // execute TLS callback list before call function.
    ldr_alloc_tls_block();
    if (loader->IsDLL)
    {
        pe_dll_main(DLL_THREAD_ATTACH, false);
    } else {    
        ldr_tls_callback(DLL_THREAD_ATTACH);
    }

    // execute the function
    func_entry_t entry = (func_entry_t)startAddress;
    entry(parameter);

    hook_ExitThread(0);
}

__declspec(noinline)
void hook_ExitThread(DWORD dwExitCode)
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "ExitThread: %d", dwExitCode);

    // execute TLS callback list befor call ExitThread.
    if (loader->IsDLL)
    {
        pe_dll_main(DLL_THREAD_DETACH, false);
    } else {
        ldr_tls_callback(DLL_THREAD_DETACH);
    }
    ldr_free_tls_block();

    loader->ExitThread(dwExitCode);
}

__declspec(noinline)
void hook_ExitProcess(UINT uExitCode)
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "ExitProcess: %zu", uExitCode);

    // execute TLS callback list befor call ExitThread.
    ldr_tls_callback(DLL_PROCESS_DETACH);
    ldr_free_tls_block();

    loader->ExitProcess(uExitCode);
    
    clean_run_data();
    set_exit_code(uExitCode);
    set_running(false);

    loader->ExitThread(0);
}

__declspec(noinline)
int __cdecl hook_msvcrt_getmainargs(
    int* argc, byte*** argv, byte*** env, int doWildCard, void* startInfo
){
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call msvcrt.__getmainargs");

    // find msvcrt.__getmainargs
#ifdef _WIN64
    uint hash = 0x305F6CF2D8F6B0DE;
    uint key  = 0x4AB3805CF30D6415;
#elif _WIN32
    uint hash = 0xE1E75000;
    uint key  = 0x14BEF388;
#endif
    msvcrt_getmainargs_t getmainargs = loader->Config.FindAPI(hash, key);
    if (getmainargs == NULL)
    {
        return -1;
    }

    // call original function to process other arguments,
    // argv and env must NOT free, it allocated by msvcrt
    int ret = getmainargs(argc, argv, env, doWildCard, startInfo);
    if (ret == -1)
    {
        return ret;
    }

    // hijack the return value about argc and argv
    loadCommandLineToArgv(loader);
    if (loader->argc != 0)
    {
        *argc = loader->argc;
        *argv = loader->argv_a;
    }
    return ret;
}

__declspec(noinline)
int __cdecl hook_msvcrt_wgetmainargs(
    int* argc, uint16*** argv, uint16*** env, int doWildCard, void* startInfo
){
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call msvcrt.__wgetmainargs");

    // find msvcrt.__wgetmainargs
#ifdef _WIN64
    uint hash = 0x1C3CFAD70CBF5CC3;
    uint key  = 0x2443BB3D37654188;
#elif _WIN32
    uint hash = 0x44C32027;
    uint key  = 0x354751F7;
#endif
    msvcrt_wgetmainargs_t wgetmainargs = loader->Config.FindAPI(hash, key);
    if (wgetmainargs == NULL)
    {
        return -1;
    }

    // call original function to process other arguments,
    // argv and env must NOT free, it allocated by msvcrt
    int ret = wgetmainargs(argc, argv, env, doWildCard, startInfo);
    if (ret == -1)
    {
        return ret;
    }

    // hijack the return value about argc and argv
    loadCommandLineToArgv(loader);
    if (loader->argc != 0)
    {
        *argc = loader->argc;
        *argv = loader->argv_w;
    }
    return ret;
}

__declspec(noinline)
void __cdecl hook_msvcrt_exit(int exitcode)
{
    hook_ExitProcess((UINT)exitcode);
}

int* __cdecl hook_ucrtbase_p_argc()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call ucrtbase.__p___argc");

    loadCommandLineToArgv(loader);
    if (loader->argc != 0)
    {
        return &loader->argc;
    }

    // call ucrtbase.__p___argc
#ifdef _WIN64
    uint hash = 0xADF700C69C846081;
    uint key  = 0x164425A411FFA1EC;
#elif _WIN32
    uint hash = 0xDDB2351C;
    uint key  = 0x2F7CAB87;
#endif
    ucrtbase_p_argc_t p_argc = loader->Config.FindAPI(hash, key);
    if (p_argc == NULL)
    {
        return NULL;
    }
    return p_argc();
}

byte*** __cdecl hook_ucrtbase_p_argv()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call ucrtbase.__p___argv");

    loadCommandLineToArgv(loader);
    if (loader->argc != 0)
    {
        return &loader->argv_a;
    }

    // call ucrtbase.__p___argv
#ifdef _WIN64
    uint hash = 0xC64ED1F8F1B1277C;
    uint key  = 0xBDAD98E6C2B6C986;
#elif _WIN32
    uint hash = 0x4B6EA85E;
    uint key  = 0x8E47E1D6;
#endif
    ucrtbase_p_argv_t p_argv = loader->Config.FindAPI(hash, key);
    if (p_argv == NULL)
    {
        return NULL;
    }
    return p_argv();
}

uint16*** __cdecl hook_ucrtbase_p_wargv()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call ucrtbase.__p___wargv");

    loadCommandLineToArgv(loader);
    if (loader->argc != 0)
    {
        return &loader->argv_w;
    }

    // call ucrtbase.__p___wargv
#ifdef _WIN64
    uint hash = 0xC89A5BF3DB908890;
    uint key  = 0xF5124C295B193B2F;
#elif _WIN32
    uint hash = 0x020C7D19;
    uint key  = 0x0FCC5CEA;
#endif
    ucrtbase_p_wargv_t p_wargv = loader->Config.FindAPI(hash, key);
    if (p_wargv == NULL)
    {
        return NULL;
    }
    return p_wargv();
}

void __cdecl hook_ucrtbase_exit(int exitcode)
{
    hook_ExitProcess((UINT)exitcode);
}

// if you only parse the command line parameters in the configuration
// and not the current process, the size of the hook function will 
// be larger, but if there are no command line parameters in the 
// configuration, you can use the internal implementation in msvcrt 
// or ucrtbase instead of loading shell32.dll.
void loadCommandLineToArgv(PELoader* loader)
{
    Runtime_M* runtime = loader->Runtime;

    if (loader->argc != 0)
    {
        return;
    }

    LPWSTR cmdLine = loader->Config.CommandLineW;
    if (cmdLine == NULL)
    {
        return;
    }

    // make sure shell32.dll is loaded
    byte dllName[] = {
        's', 'h', 'e', 'l', 'l', '3', '2', '.', 'd', 'l', 'l', '\x00'
    };
    HMODULE hModule = loader->LoadLibraryA(dllName);
    if (hModule == NULL)
    {
        return;
    }

    int argc = 0;
    LPWSTR* argv;
    for (;;)
    {
        argv = hook_CommandLineToArgvW(cmdLine, &argc);
        if (argv == NULL)
        {
            break;
        }
        dbg_log("[PE Loader]", "argv pointer: 0x%zX", argv);

        // calculate the buffer size about argv
        // add size of pointer array
        uint size = ((uint)argc + 1) * sizeof(LPWSTR);
        // add each argument string length
        for (LPWSTR* p = argv; *p != NULL; p++)
        {
            size += (strlen_w(*p) + 1) * 2;
        }

        // copy buffer data that we can hide it
        // otherwise, it will in the local heap
        LPWSTR* argv_a = runtime->Memory.Alloc(size);
        LPWSTR* argv_w = runtime->Memory.Alloc(size);
        mem_copy(argv_a, argv, size);
        mem_copy(argv_w, argv, size);

        // fix the string pointers
        uintptr offset = (uintptr)argv_a - (uintptr)argv;
        for (LPWSTR* p = argv_a; *p != NULL; p++)
        {
            uintptr addr = (uintptr)(*p) + offset;
            *p = (LPWSTR)addr;
        }
        offset = (uintptr)argv_w - (uintptr)argv;
        for (LPWSTR* p = argv_w; *p != NULL; p++)
        {
            uintptr addr = (uintptr)(*p) + offset;
            *p = (LPWSTR)addr;
        }

        // convert each argument from UTF16 to ANSI for argv_a
        for (LPWSTR* p = argv_a; *p != NULL; p++)
        {
            LPWSTR ptr = *p;
            ANSI s = runtime->WinBase.UTF16ToANSI(ptr);
            if (s == NULL)
            {
                break;
            }
            strcpy_a((ANSI)ptr, s);
            runtime->Memory.Free(s);
        }
        LPSTR* argv_n = (LPSTR*)argv_a;

        loader->argc   = argc;
        loader->argv_a = argv_n;
        loader->argv_w = argv_w;
        break;
    }

    // free memory from CommandLineToArgvW
    if (argv != NULL)
    {
        loader->LocalFree(argv);
    }
    // free shell32.dll
    loader->FreeLibrary(hModule);
}

__declspec(noinline)
static void pe_entry_point()
{
    PELoader* loader = getPELoaderPointer();

    // execute TLS callback list before call EntryPoint.
    ldr_alloc_tls_block();
    ldr_tls_callback(DLL_PROCESS_ATTACH);

    // call EntryPoint usually is main.
    uint exitCode = ((uint(*)())(loader->EntryPoint))();

    // exit process
    hook_ExitProcess(exitCode);
}

__declspec(noinline)
static bool pe_dll_main(DWORD dwReason, bool setExitCode)
{
    PELoader* loader = getPELoaderPointer();

    // call dll main function
    DllMain_t dllMain = (DllMain_t)(loader->EntryPoint);
    HMODULE   hModule = (HMODULE)(loader->PEImage);
    bool retval = dllMain(hModule, dwReason, NULL);
    uint exitCode;
    if (retval)
    {
        exitCode = 0;
    } else {
        exitCode = 1;
    }
    if (setExitCode)
    {
        set_exit_code(exitCode);
    }
    // execute TLS callback list after call DllMain.
    ldr_tls_callback(dwReason);
    return retval;
}

static void set_exit_code(uint code)
{
    PELoader* loader = getPELoaderPointer();

    if (loader->WaitForSingleObject(loader->StatusMu, INFINITE) != WAIT_OBJECT_0)
    {
        return;
    }

    *loader->ExitCode = code;

    loader->ReleaseMutex(loader->StatusMu);
}

static uint get_exit_code()
{
    PELoader* loader = getPELoaderPointer();

    if (loader->WaitForSingleObject(loader->StatusMu, INFINITE) != WAIT_OBJECT_0)
    {
        return 1;
    }

    uint code = *loader->ExitCode;

    if (!loader->ReleaseMutex(loader->StatusMu))
    {
        return 1;
    }
    return code;
}

__declspec(noinline)
static void set_running(bool run)
{
    PELoader* loader = getPELoaderPointer();

    if (loader->WaitForSingleObject(loader->StatusMu, INFINITE) != WAIT_OBJECT_0)
    {
        return;
    }

    loader->IsRunning = run;

    loader->ReleaseMutex(loader->StatusMu);
}

__declspec(noinline)
static bool is_running()
{
    PELoader* loader = getPELoaderPointer();

    if (loader->WaitForSingleObject(loader->StatusMu, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    bool running = loader->IsRunning;

    if (!loader->ReleaseMutex(loader->StatusMu))
    {
        return false;
    }
    return running;
}

__declspec(noinline)
static void clean_run_data()
{
    PELoader* loader = getPELoaderPointer();

    // reset command line arguments
    loader->argc   = 0;
    loader->argv_a = NULL;
    loader->argv_w = NULL;
}

__declspec(noinline)
errno LDR_Execute()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock())
    {
        return ERR_LOADER_LOCK;
    }

    errno errno = NO_ERROR;

    if (is_running())
    {
        goto skip;
    }

    for (;;)
    {
        errno = ldr_init_mutex();
        if (errno != NO_ERROR)
        {
            break;
        }
        if (!ldr_copy_image())
        {
            errno = ERR_LOADER_COPY_PE_IMAGE;
            break;
        }
        // load library and fix function address
        if (!ldr_process_import())
        {
            errno = ERR_LOADER_PROCESS_IMPORT;
            break;
        }
        // make callback about DLL_PROCESS_DETACH
        if (loader->IsDLL)
        {
            if (!pe_dll_main(DLL_PROCESS_ATTACH, true))
            {
                errno = ERR_LOADER_CALL_DLL_MAIN;
            }
            break;
        }
        // change the running status
        set_running(true);
        // create thread at entry point
        void* addr = GetFuncAddr(&pe_entry_point);
        HANDLE hThread = loader->CreateThread(NULL, 0, addr, NULL, 0, NULL);
        if (hThread == NULL)
        {
            errno = ERR_LOADER_CREATE_MAIN_THREAD;
            set_running(false);
            break;
        }
        // wait main thread exit
        if (loader->Config.WaitMain)
        {
            loader->WaitForSingleObject(hThread, INFINITE);
            set_running(false);
        }
        loader->CloseHandle(hThread);
        break;
    }

skip:
    if (!ldr_unlock())
    {
        return ERR_LOADER_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
errno LDR_Exit(uint exitCode)
{
    if (!ldr_lock())
    {
        return ERR_LOADER_LOCK;
    }

    errno errno = NO_ERROR;
    if (is_running())
    {
        errno = ldr_exit_process(exitCode);
    }

    if (!ldr_unlock())
    {
        return ERR_LOADER_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
errno LDR_Destroy()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock())
    {
        return ERR_LOADER_LOCK;
    }

    errno err = NO_ERROR;

    if (is_running())
    {
        errno eep = ldr_exit_process(0);
        if (eep != NO_ERROR && err == NO_ERROR)
        {
            err = eep;
        }
    }

    if (!loader->Config.NotEraseInstruction)
    {
        DWORD oldProtect;
        if (!adjustPageProtect(loader, &oldProtect) && err == NO_ERROR)
        {
            err = ERR_LOADER_ADJUST_PROTECT;
        }

        if (!recoverPELoaderPointer(loader) && err == NO_ERROR)
        {
            err = ERR_LOADER_RECOVER_INST;
        }

        if (!recoverPageProtect(loader, oldProtect) && err == NO_ERROR)
        {
            err = ERR_LOADER_RECOVER_PROTECT;
        }
    }

    errno errcl = cleanPELoader(loader);
    if (errcl != NO_ERROR && err == NO_ERROR)
    {
        err = errcl;
    }
    return err;
}

// prevent it be linked to other functions.
#pragma optimize("", off)

#pragma warning(push)
#pragma warning(disable: 4189)
static void ldr_epilogue()
{
    byte var = 10;
    return;
}
#pragma warning(pop)

#pragma optimize("", on)
