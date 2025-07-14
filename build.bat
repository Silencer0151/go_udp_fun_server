@echo off
setlocal

REM Ensure build directory exists
if not exist build (
    mkdir build
)

REM Build server executable
echo Building gufs-server.exe...
go build -o build/gufs-server.exe server.go

REM Build client executable
echo Building gufs-client.exe...
go build -o build/gufs-client.exe client/client.go

echo Build complete. Executables are in the build directory.