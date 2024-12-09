rd  /S /Q ".vs\ucrtbase\v17\ipch"
del /S /Q ".vs\ucrtbase\v17\Browse.VC.db"
del /S /Q ".vs\ucrtbase\v17\Solution.VC.db"

rd /S /Q "Debug"
rd /S /Q "Release"
rd /S /Q "x64"
rd /S /Q "x86"

rd /S /Q "main\Debug"
rd /S /Q "main\Release"
rd /S /Q "main\x64"
rd /S /Q "main\x86"

rd /S /Q "wmain\Debug"
rd /S /Q "wmain\Release"
rd /S /Q "wmain\x64"
rd /S /Q "wmain\x86"