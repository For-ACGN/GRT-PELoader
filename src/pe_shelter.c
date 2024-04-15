#include "go_types.h"
#include "windows_t.h"
#include "pe_shelter.h"

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
    uintptr ImageBase;
    uintptr EntryPointRVA;

    // DLL
} PEShelterRT;

static bool initAPI(PEShelterRT* runtime);
static bool parsePEImage(PEShelterRT* runtime);
static bool mapPESections(PEShelterRT* runtime);
static void fixRelocationTable(PEShelterRT* runtime);
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
        fixRelocationTable(&runtime);
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
    return runtime.PEOffset;
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
    uintptr imageBase = *(uintptr*)(imageAddr + peOffset + 48);
    uintptr entryPointRVA = *(uint32*)(imageAddr + peOffset + 40);
    runtime->PEOffset = peOffset;
    runtime->ImageBase = imageBase;
    runtime->EntryPointRVA = entryPointRVA;
    return true;
}

static bool mapPESections(PEShelterRT* runtime)
{
    // allocate memory for PE image
    uintptr peImage = runtime->VirtualAlloc(0, 123, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (peImage == NULL)
    {
        return false;
    }
    // copy PE image to the memory
    // copyMemory(peImage, address, size);
    // change memory protect to executable
    uint32 oldProtect;
    if (!runtime->VirtualProtect(peImage, 123, PAGE_EXECUTE_READ, &oldProtect))
    {
        return false;
    }
    runtime->PEImage = peImage;
    return true;
}



static void fixRelocationTable(PEShelterRT* runtime)
{
    uintptr peImage = runtime->PEImage;
    uint32  peOffset = runtime->PEOffset;

    uint32 tableSize = *(uintptr*)(peImage + peOffset + 180);
    uint32 tableRVA  = *(uintptr*)(peImage + peOffset + 176);

    runtime->PEOffset = tableSize;
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
