@echo off

echo ========== initialize Visual Studio environment ==========
if "%VisualStudio%" == "" (
    echo environment variable "VisualStudio" is not set
    exit /b 1
)
call "%VisualStudio%\VC\Auxiliary\Build\vcvars64.bat"

echo ===================== clean old files ====================
rd /S /Q "Release"
rd /S /Q "x64"

echo =================== generate exe files ===================
MSBuild.exe ucrtbase.sln /t:main /p:Configuration=Release /p:Platform=x64
MSBuild.exe ucrtbase.sln /t:main /p:Configuration=Release /p:Platform=x86
MSBuild.exe ucrtbase.sln /t:wmain /p:Configuration=Release /p:Platform=x64
MSBuild.exe ucrtbase.sln /t:wmain /p:Configuration=Release /p:Platform=x86

echo ===================== move exe files =====================
move /Y x64\Release\ucrtbase_main.exe ..\x64\ucrtbase_main.exe
move /Y x64\Release\ucrtbase_wmain.exe ..\x64\ucrtbase_wmain.exe
move /Y Release\ucrtbase_main.exe ..\x86\ucrtbase_main.exe
move /Y Release\ucrtbase_wmain.exe ..\x86\ucrtbase_wmain.exe

echo ================ clean builder output files ==============
rd /S /Q "main\Release"
rd /S /Q "main\x64"
rd /S /Q "wmain\Release"
rd /S /Q "wmain\x64"
rd /S /Q "Release"
rd /S /Q "x64"
