set GOARCH=amd64
go build -v -trimpath -ldflags "-s -w" -o ../x64/go.exe main.go
set GOARCH=386
go build -v -trimpath -ldflags "-s -w" -o ../x86/go.exe main.go
