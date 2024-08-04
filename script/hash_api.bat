@echo off

echo ============================================================
echo Build HashAPI tool from https://github.com/For-ACGN/hash_api
echo ============================================================
echo.

echo ------------------------x64------------------------
hash_api -fmt 64 -conc -func LoadLibraryA
hash_api -fmt 64 -conc -func GetProcAddress
hash_api -fmt 64 -conc -func VirtualAlloc
hash_api -fmt 64 -conc -func VirtualFree
hash_api -fmt 64 -conc -func VirtualProtect
hash_api -fmt 64 -conc -func CreateThread
hash_api -fmt 64 -conc -func FlushInstructionCache
hash_api -fmt 64 -conc -func WaitForSingleObject
hash_api -fmt 64 -conc -func CloseHandle
echo.

echo ------------------------x86------------------------
hash_api -fmt 32 -conc -func LoadLibraryA
hash_api -fmt 32 -conc -func GetProcAddress
hash_api -fmt 32 -conc -func VirtualAlloc
hash_api -fmt 32 -conc -func VirtualFree
hash_api -fmt 32 -conc -func VirtualProtect
hash_api -fmt 32 -conc -func CreateThread
hash_api -fmt 32 -conc -func FlushInstructionCache
hash_api -fmt 32 -conc -func WaitForSingleObject
hash_api -fmt 32 -conc -func CloseHandle
echo.

pause
