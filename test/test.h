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

bool TestInitPELoader();
#pragma warning(pop)

typedef bool (*test_t)();
typedef struct { byte* Name; test_t Test; } unit;

static unit tests[] = 
{
    { "Lib_String", TestLibString },

    { "InitPELoader", TestInitPELoader },
};

#endif // TEST_H
