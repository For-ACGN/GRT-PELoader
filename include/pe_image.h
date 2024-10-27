#ifndef PE_IMAGE_H
#define PE_IMAGE_H

#include "c_types.h"
#include "windows_t.h"

#define DOS_HEADER_SIZE 64

#define NT_HEADER_SIGNATURE_SIZE 4
#define PE_SECTION_HEADER_SIZE   40
#define PE_DATA_DIRECTORY_SIZE   8

#define IMAGE_FILE_MACHINE_I386  0x014C
#define IMAGE_FILE_MACHINE_AMD64 0x8664

#define IMAGE_FILE_RELOCS_STRIPPED  0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_DLL              0x2000

#define	IMAGE_DIRECTORY_ENTRY_EXPORT         0
#define	IMAGE_DIRECTORY_ENTRY_IMPORT         1
#define	IMAGE_DIRECTORY_ENTRY_RESOURCE       2
#define	IMAGE_DIRECTORY_ENTRY_EXCEPTION      3
#define	IMAGE_DIRECTORY_ENTRY_SECURITY       4
#define	IMAGE_DIRECTORY_ENTRY_BASERELOC      5
#define	IMAGE_DIRECTORY_ENTRY_DEBUG          6
#define	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   7
#define	IMAGE_DIRECTORY_ENTRY_GLOBALPTR      8
#define	IMAGE_DIRECTORY_ENTRY_TLS            9
#define	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define	IMAGE_DIRECTORY_ENTRY_IAT            12
#define	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGHLOW  3 
#define IMAGE_REL_BASED_DIR64    10

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000

#ifdef _WIN64
    #define IMAGE_SNAP_BY_ORDINAL(ordinal) ((ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#elif _WIN32
    #define IMAGE_SNAP_BY_ORDINAL(ordinal) ((ordinal & IMAGE_ORDINAL_FLAG32) != 0)
#endif

typedef struct {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} Image_FileHeader;

typedef struct {
    DWORD VirtualAddress;
    DWORD Size;
} Image_DataDirectory;

typedef struct {
    WORD  Magic;
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;          
	WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;      
	DWORD Win32VersionValue;      
	DWORD SizeOfImage;          
	DWORD SizeOfHeaders;
    DWORD CheckSum;             
	WORD  Subsystem;                  
	WORD  DllCharacteristics;
    DWORD SizeOfStackReserve;        
	DWORD SizeOfStackCommit;        
	DWORD SizeOfHeapReserve;         
	DWORD SizeOfHeapCommit;         
	DWORD LoaderFlags;          
    DWORD NumberOfRvaAndSizes;

	Image_DataDirectory DataDirectory[16];
} OptionalHeader32;

typedef struct {
    WORD  Magic;
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    QWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;      
	DWORD Win32VersionValue;      
	DWORD SizeOfImage;          
	DWORD SizeOfHeaders;
    DWORD CheckSum;              
	WORD  Subsystem;
    WORD  DllCharacteristics;
    QWORD SizeOfStackReserve;
    QWORD SizeOfStackCommit;
    QWORD SizeOfHeapReserve;
    QWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;

    Image_DataDirectory DataDirectory[16];
} OptionalHeader64;

#ifdef _WIN64
    typedef OptionalHeader64 OptionalHeader;
#elif _WIN32
    typedef OptionalHeader32 OptionalHeader;
#endif

typedef struct {
    DWORD OriginalFirstThunk;
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} Image_ImportDescriptor;

typedef struct {
    union {
        DWORD AllAttributes;
        struct {
            DWORD RVABased           :1;
            DWORD ReservedAttributes :31;
        };
    } Attributes;

    DWORD DllNameRVA;      
    DWORD ModuleHandleRVA;
    DWORD ImportAddressTableRVA;
    DWORD ImportNameTableRVA;
    DWORD BoundImportAddressTableRVA;
    DWORD UnloadInformationTableRVA;
    DWORD TimeDateStamp;
} Image_DelayloadDescriptor;

typedef struct {
    union {
        DWORD ForwarderString;
        DWORD Function;
        DWORD Ordinal;
        DWORD AddressOfData;
    } u1;
} Image_ThunkData32;

typedef struct {
    union {
        QWORD ForwarderString;
        QWORD Function;
        QWORD Ordinal;
        QWORD AddressOfData;
    } u1;
} Image_ThunkData64;

#ifdef _WIN64
    typedef Image_ThunkData64 Image_ThunkData;
#elif _WIN32
    typedef Image_ThunkData32 Image_ThunkData;
#endif

typedef struct {
    WORD Hint;
    BYTE Name[1];
} Image_ImportByName;

typedef struct {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
} Image_BaseRelocation;

typedef struct {
    WORD Offset :12;
    WORD Type   :4;
} Image_Reloc;

typedef struct {
    UINT   StartAddressOfRawData;
    UINT   EndAddressOfRawData;
    UINT*  AddressOfIndex;
    LPVOID AddressOfCallBacks;
    DWORD  SizeOfZeroFill;
    DWORD  Characteristics;
} Image_TLSDirectory;

#endif // PE_IMAGE_H
