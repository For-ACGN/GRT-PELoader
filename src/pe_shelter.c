#include "go_types.h"
#include "windows.h"
#include "hash_api.h"

typedef uintptr(*VirtualAlloc)(uintptr lpAddress, uint dwSize, uint32 flAllocationType, uint32 flProtect);
typedef HMODULE(*LoadLibraryA)(LPCSTR lpLibFileName);
typedef uintptr(*GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef bool(*FlushInstructionCache)(HANDLE hProcess, uintptr lpBaseAddress, uint dwSize);

uintptr LoadPE(uintptr address)
{
	// find all apis 
	uint64 hash = 0xB6A1D0D4A275D4B6;
	uint64 key  = 0x64CB4D66EC0BEFD9;
	VirtualAlloc virtualAlloc = (VirtualAlloc)FindAPI(hash, key);
	if (virtualAlloc == NULL)
	{
		return 0;
	}
	hash = 0xC0B89BE712EE4C18;
	key  = 0xF80CA8B02538CAC4;
	LoadLibraryA loadLibraryA = (LoadLibraryA)FindAPI(hash, key);
	if (loadLibraryA == NULL)
	{
		return 0;
	}
	hash = 0xB1AE911EA1306CE1;
	key  = 0x39A9670E629C64EA;
	GetProcAddress getProcAddress = (GetProcAddress)FindAPI(hash, key);
	if (getProcAddress == NULL)
	{
		return 0;
	}
	hash = 0x8172B49F66E495BA;
	key  = 0x8F0D0796223B56C2;
	FlushInstructionCache flushInstructionCache = (FlushInstructionCache)FindAPI(hash, key);
	if (flushInstructionCache == NULL)
	{
		return 0;
	}

	return 1;
}

#ifdef _WIN64



#elif _WIN32

#endif
