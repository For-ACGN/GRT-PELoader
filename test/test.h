#ifndef TEST_H
#define TEST_H

#include "c_types.h"
#include "pe_loader.h"

// define global variables for tests
PELoader_M* pe_loader;

// define unit tests
#pragma warning(push)
#pragma warning(disable: 4276)
bool TestLibString();
bool TestRandom();

bool TestInitPELoader();

bool TestPELoader_Execute();
bool TestPELoader_Exit();
bool TestPELoader_Destroy();
#pragma warning(pop)

typedef bool (*test_t)();
typedef struct { byte* Name; test_t Test; } unit;

static unit tests[] = 
{
    { "Lib_String", TestLibString },
    { "Random",     TestRandom    },

    { "InitPELoader", TestInitPELoader },

    { "PELoader_Execute", TestPELoader_Execute },
    { "PELoader_Exit",    TestPELoader_Exit    },
    { "PELoader_Destroy", TestPELoader_Destroy },
};

#endif // TEST_H
