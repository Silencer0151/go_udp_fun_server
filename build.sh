#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Ensure the build directory exists
if [ ! -d "build" ]; then
    echo "Creating build directory..."
    mkdir build
fi

echo

# Build the server executable
echo "Building gufs-server..."
if ! go build -o build/gufs-server .; then
    echo "Server build FAILED."
    exit 1
fi
echo "Server build successful."

echo

# Build the client executable
echo "Building gufs-client..."
if ! go build -o build/gufs-client ./client; then
    echo "Client build FAILED."
    exit 1
fi
echo "Client build successful."

echo
echo "Build complete. Executables are in the 'build' directory."
<<<<<<< HEAD

=======
>>>>>>> b375e8cc4c3b6f353a474585b484f016dd192239
