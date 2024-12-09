echo =============build ucrtbase example=============
cd ucrtbase
call Build.bat
cd ..

echo ================build Go example================
set GOARCH=amd64
go build -v -trimpath -ldflags "-s -w" -o x64/go.exe go/main.go
set GOARCH=386
go build -v -trimpath -ldflags "-s -w" -o x86/go.exe go/main.go
