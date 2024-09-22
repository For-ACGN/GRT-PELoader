@echo off

echo ==================================================================
echo Build HashAPI tool from https://github.com/RSSU-Shellcode/hash_api
echo ==================================================================
echo.

echo ------------------------x64------------------------
hash_api -fmt 64 -conc -func LoadLibraryA
hash_api -fmt 64 -conc -func GetProcAddress
hash_api -fmt 64 -conc -func VirtualAlloc
hash_api -fmt 64 -conc -func VirtualFree
hash_api -fmt 64 -conc -func VirtualProtect
hash_api -fmt 64 -conc -func VirtualLock
hash_api -fmt 64 -conc -func VirtualUnlock
hash_api -fmt 64 -conc -func CreateThread
hash_api -fmt 64 -conc -func ExitThread
hash_api -fmt 64 -conc -func FlushInstructionCache
hash_api -fmt 64 -conc -func CreateMutexA
hash_api -fmt 64 -conc -func ReleaseMutex
hash_api -fmt 64 -conc -func WaitForSingleObject
hash_api -fmt 64 -conc -func CloseHandle
hash_api -fmt 64 -conc -func GetCommandLineA
hash_api -fmt 64 -conc -func GetCommandLineW
hash_api -fmt 64 -conc -func GetStdHandle
hash_api -fmt 64 -conc -func ExitProcess
hash_api -fmt 64 -conc -func RT_GetArgValue
hash_api -fmt 64 -conc -func RT_GetArgPointer
hash_api -fmt 64 -conc -func RT_EraseArgument
hash_api -fmt 64 -conc -func RT_EraseAllArgs
echo.

echo ------------------------x86------------------------
hash_api -fmt 32 -conc -func LoadLibraryA
hash_api -fmt 32 -conc -func GetProcAddress
hash_api -fmt 32 -conc -func VirtualAlloc
hash_api -fmt 32 -conc -func VirtualFree
hash_api -fmt 32 -conc -func VirtualProtect
hash_api -fmt 32 -conc -func VirtualLock
hash_api -fmt 32 -conc -func VirtualUnlock
hash_api -fmt 32 -conc -func CreateThread
hash_api -fmt 32 -conc -func ExitThread
hash_api -fmt 32 -conc -func FlushInstructionCache
hash_api -fmt 32 -conc -func CreateMutexA
hash_api -fmt 32 -conc -func ReleaseMutex
hash_api -fmt 32 -conc -func WaitForSingleObject
hash_api -fmt 32 -conc -func CloseHandle
hash_api -fmt 32 -conc -func GetCommandLineA
hash_api -fmt 32 -conc -func GetCommandLineW
hash_api -fmt 32 -conc -func GetStdHandle
hash_api -fmt 32 -conc -func ExitProcess
hash_api -fmt 32 -conc -func RT_GetArgValue
hash_api -fmt 32 -conc -func RT_GetArgPointer
hash_api -fmt 32 -conc -func RT_EraseArgument
hash_api -fmt 32 -conc -func RT_EraseAllArgs
echo.

pause
