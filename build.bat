@echo off
setlocal

REM This script assumes you have initialized a Go module with 'go mod init'

REM Ensure the build directory exists
if not exist build (
    echo Creating build directory...
    mkdir build
)

echo.

REM Build the server executable.
REM Go automatically finds all .go files in the main package.
echo Building gufs-server.exe...
go build -o build/gufs-server.exe .
if %errorlevel% neq 0 (
    echo Server build FAILED.
    goto :eof
)
echo Server build successful.

echo.

REM Build the client executable.
REM We point Go to the 'client' directory, and it builds the main package within it.
echo Building gufs-client.exe...
go build -o build/gufs-client.exe ./client
if %errorlevel% neq 0 (
    echo Client build FAILED.
    goto :eof
)
echo Client build successful.

echo.
echo Build complete. Executables are in the 'build' directory.

endlocal
