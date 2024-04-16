#include "go_types.h"
#include "windows_t.h"
#include "pe_shelter.h"

#define PE_HEADER_SIZE 24
#define PE_OPT_HEADER_64_SIZE 240
#define PE_OPT_HEADER_32_SIZE 224
#define DATA_DIRECTORY_Size 8

typedef struct {
    PEShelterCtx* context;

    // Arguments
    uintptr ImageAddr;

    // API address
    VirtualAlloc   VirtualAlloc;
    VirtualProtect VirtualProtect;
    VirtualFree    VirtualFree;
    LoadLibraryA   LoadLibraryA;
    FreeLibrary    FreeLibrary;
    GetProcAddress GetProcAddress;
    FlushInstCache FlushInstCache;
    CreateThread   CreateThread;

    // PE image information
    uintptr PEImage;
    uint32  PEOffset;
    uint16  NumSections;
    uint16  OptHeaderSize;
    uintptr DataDir;
    uintptr EntryPoint;
    uintptr ImageBase;
    uint32  ImageSize;

    // DLL

    uintptr Debug;
} PEShelterRT;

static struct ImportDirectory {
    uint32 OriginalFirstThunk;
    uint32 TimeDateStamp;
    uint32 ForwarderChain;
    uint32 Name;
    uint32 FirstThunk;
};

static bool initAPI(PEShelterRT* runtime);
static bool parsePEImage(PEShelterRT* runtime);
static bool mapPESections(PEShelterRT* runtime);
static bool fixRelocTable(PEShelterRT* runtime);
static bool processIAT(PEShelterRT* runtime);
static void copyMemory(uintptr dst, uintptr src, uint len);

uintptr LoadPE(PEShelterCtx* context, uintptr address)
{
    PEShelterRT runtime = {
        .context   = context,
        .ImageAddr = address,

        // ignore Visual Studio bug fix
        .VirtualAlloc   = (VirtualAlloc)1,
        .VirtualProtect = (VirtualProtect)1,
        .VirtualFree    = (VirtualFree)1,
        .LoadLibraryA   = (LoadLibraryA)1,
        .FreeLibrary    = (FreeLibrary)1,
        .GetProcAddress = (GetProcAddress)1,
        .FlushInstCache = (FlushInstCache)1,
        .CreateThread   = (CreateThread)1,
    };
    if (!initAPI(&runtime))
    {
        return NULL;
    }
    for (;;)
    {
        if (!parsePEImage(&runtime))
        {
            break;
        }
        if (!mapPESections(&runtime))
        {
            break;
        }
        if (!fixRelocTable(&runtime))
        {
            break;
        }
        if (!processIAT(&runtime))
        {
            break;
        }
        // change memory protect to executable
        uint32 oldProtect;
        runtime.VirtualProtect(runtime.PEImage, runtime.ImageSize, PAGE_EXECUTE_READ, &oldProtect);
        // runtime->EntryPoint = peImage + runtime->EntryPoint;
        break;
    }
    
    // if (runtime.PEImage != NULL)
    // {
    // 
    // }
    // else
    // {
    // 
    // }
    return runtime.Debug;
}

// initAPI is used to find API addresses for PE loader.
static bool initAPI(PEShelterRT* runtime)
{
    FindAPI_t findAPI = runtime->context->FindAPI;

    uint64 hash = 0xB6A1D0D4A275D4B6;
    uint64 key  = 0x64CB4D66EC0BEFD9;
    VirtualAlloc virtualAlloc = (VirtualAlloc)findAPI(hash, key);
    if (virtualAlloc == NULL)
    {
        return false;
    }
    hash = 0x8CDC3CBC1ABF3F5F;
    key  = 0xC3AEEDC9843D7B34;
    VirtualProtect virtualProtect = (VirtualProtect)findAPI(hash, key);
    if (virtualProtect == NULL)
    {
        return false;
    }
    hash = 0xB82F958E3932DE49;
    key  = 0x1CA95AA0C4E69F35;
    VirtualFree virtualFree = (VirtualFree)findAPI(hash, key);
    if (virtualFree == NULL)
    {
        return false;
    }
    hash = 0xC0B89BE712EE4C18;
    key  = 0xF80CA8B02538CAC4;
    LoadLibraryA loadLibraryA = (LoadLibraryA)findAPI(hash, key);
    if (loadLibraryA == NULL)
    {
        return false;
    }
    hash = 0xC22B47E9D652D287;
    key  = 0xA118770E82EB0797;
    FreeLibrary freeLibrary = (FreeLibrary)findAPI(hash, key);
    if (freeLibrary == NULL)
    {
        return false;
    }
    hash = 0xB1AE911EA1306CE1;
    key  = 0x39A9670E629C64EA;
    GetProcAddress getProcAddress = (GetProcAddress)findAPI(hash, key);
    if (getProcAddress == NULL)
    {
        return false;
    }
    hash = 0x8172B49F66E495BA;
    key  = 0x8F0D0796223B56C2;
    FlushInstCache flushInstCache = (FlushInstCache)findAPI(hash, key);
    if (flushInstCache == NULL)
    {
        return false;
    }
    hash = 0x134459F9F9668FC1;
    key  = 0xB2877C84F94DB5D8;
    CreateThread createThread = (CreateThread)findAPI(hash, key);
    if (createThread == NULL)
    {
        return false;
    }
    runtime->VirtualAlloc   = virtualAlloc;
    runtime->VirtualProtect = virtualProtect;
    runtime->VirtualFree    = virtualFree;
    runtime->LoadLibraryA   = loadLibraryA;
    runtime->FreeLibrary    = freeLibrary;
    runtime->GetProcAddress = getProcAddress;
    runtime->FlushInstCache = flushInstCache;
    runtime->CreateThread   = createThread;
    return true;
}

static bool parsePEImage(PEShelterRT* runtime)
{
    uintptr imageAddr = runtime->ImageAddr;
    uint32  peOffset = *(uint32*)(imageAddr + 60);
    // parse FileHeader
    uint16 numSections = *(uint16*)(imageAddr + peOffset + 6);
    uint16 optHeaderSize = *(uint16*)(imageAddr + peOffset + 20);
    // parse OptionalHeader
    uint16  ddOffset = PE_OPT_HEADER_64_SIZE - 16 * DATA_DIRECTORY_Size;
    uintptr dataDir = imageAddr + peOffset + PE_HEADER_SIZE + ddOffset;
    uint32  entryPoint = *(uint32*)(imageAddr + peOffset + 40);
    uintptr imageBase = *(uintptr*)(imageAddr + peOffset + 48);
    uint32  imageSize = *(uint32*)(imageAddr + peOffset + 80);
    runtime->PEOffset = peOffset;
    runtime->NumSections = numSections;
    runtime->OptHeaderSize = optHeaderSize;
    runtime->DataDir = dataDir;
    runtime->EntryPoint = entryPoint;
    runtime->ImageBase = imageBase;
    runtime->ImageSize = imageSize;
    return true;
}

static bool mapPESections(PEShelterRT* runtime)
{
    // allocate memory for PE image
    uint32 imageSize = runtime->ImageSize;
    uintptr peImage = runtime->VirtualAlloc(0, imageSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (peImage == NULL)
    {
        return false;
    }
    // map PE image sections to the memory
    uintptr imageAddr = runtime->ImageAddr;
    uint32  peOffset = runtime->PEOffset;
    uint16  optHeaderSize = runtime->OptHeaderSize;
    uintptr section = imageAddr + peOffset + PE_HEADER_SIZE + optHeaderSize;
    for (uint16 i = 0; i < runtime->NumSections; i++)
    {
        uint32 virtualAddress = *(uint32*)(section + 12);
        uint32 sizeOfRawData = *(uint32*)(section + 16);
        uint32 pointerToRawData = *(uint32*)(section + 20);
        uintptr dst = peImage + virtualAddress;
        uintptr src = runtime->ImageAddr + pointerToRawData;
        copyMemory(dst, src, sizeOfRawData);
        section += 40;
    }
    runtime->PEImage = peImage;
    return true;
}

static bool fixRelocTable(PEShelterRT* runtime)
{
    uintptr peImage = runtime->PEImage;
    uint32  peOffset = runtime->PEOffset;
    uint32 tableSize = *(uint32*)(peImage + peOffset + 180);
    uint32 tableRVA = *(uint32*)(peImage + peOffset + 176);

    return true;
}

static bool processIAT(PEShelterRT* runtime)
{
    uintptr peImage = runtime->PEImage;
    uintptr dataDir = runtime->DataDir;
    uint32  importTableVA = *(uint32*)(dataDir + 1 * DATA_DIRECTORY_Size);
    struct ImportDirectory* importDir;
    importDir = (struct ImportDirectory*)(peImage + importTableVA);


    uintptr name = peImage + importDir->Name;
    HANDLE hModule = runtime->LoadLibraryA(name);


    runtime->Debug = hModule;
    return true;
}

// copyMemory is used to copy source memory data to the destination.
// It will wipe data at the source address.
static void copyMemory(uintptr dst, uintptr src, uint size)
{
    for (uintptr i = 0; i < size; i++)
    {
        *(byte*)(dst + i) = *(byte*)(src + i);
        *(byte*)(src + i) = 0;
    }
}

#ifdef _WIN64

#elif _WIN32

#endif
