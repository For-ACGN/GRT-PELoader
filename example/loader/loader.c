#include "go_types.h"
#include "pe_shelter.h"

#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain() {

    return LoadPE(0);
}
