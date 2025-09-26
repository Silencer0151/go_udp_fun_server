# GUFS - Go UDP Fun Server

[![Go Version](https://img.shields.io/badge/Go-1.19+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**GUFS** (Go UDP Fun Server) is a concurrent, stateful UDP server designed for learning and experimentation with custom network protocols. It implements a robust binary communication protocol supporting client connections, real-time messaging, persistent data storage, and reliable file transfers over a hands free end-to-end encryption.

## 🚀 Features

### Core Functionality
- **Custom Binary Protocol**: Efficient single-byte command system
- **Connection Management**: 3-way handshake with heartbeat-based session maintenance
- **Concurrent Architecture**: Handles multiple clients simultaneously using goroutines
- **Thread-Safe Operations**: Mutex-protected shared state management

### Security Features
- **End-to-End Encryption**: All communication (after handshake) is secured using AES-256-GCM.
- **Secure Key Exchange** : Elliptic-curve Diffie-Hellman (ECDH) is used to safely establish a shared secret over an insecure channel.

### Communication Features
- **Real-time Broadcasting**: Multi-client messaging system
- **Direct Messaging**: Echo and data processing commands
- **Username Management**: Configurable client identities and broadcast of name changes.

### Data Storage
- **In-Memory Database**: Key-value storage with size limits
- **CRUD Operations**: Store, retrieve, and list database entries
- **Concurrent Access**: Thread-safe database operations

### File Transfer
- **Chunked Upload/Download**: Reliable file transfer with acknowledgments
- **Resume Capability**: Handles packet loss with selective chunk re-requesting.
- **Transfer Management**: Unique session IDs for concurrent uploads.

## 📋 Requirements

- Go 1.19 or higher
- Network access for UDP communication (default: localhost:8080)

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/yourusername/go_udp_fun_server.git](https://github.com/yourusername/go_udp_fun_server.git)
    cd go_udp_fun_server
    ```

2.  **Build the executables:**
    The project uses Go modules, so building is straightforward. The following commands can be run from the project root directory.
    ```bash
    # Build the server (output to ./build/gufs-server.exe)
    go build -o ./build/gufs-server.exe .

    # Build the client (output to ./build/gufs-client.exe)
    go build -o ./build/gufs-client.exe ./client
    ```
    Alternatively, you can use the provided `build.bat` script on Windows.


## 🚀 Quick Start

### Starting the Server
```bash
# Default (127.0.0.1:8080)
./gufs-server

# Custom IP and port
./gufs-server -ip 0.0.0.0 -port 9090
```

### Connecting with the Client
```bash
# Default connection (auto-generated username)
./gufs-client

# Custom server and username
./gufs-client -server 192.168.1.100:9090 -username Alice
```

### Basic Usage
Once connected, you can use various commands:

```bash
# Set your username
/username YourName

# Send a broadcast message
Hello everyone!

# List all users connected to the server
/users

# Echo test
/echo Hello World

# Private message
/msg user475 hey whats up

# Store data
/store mykey=myvalue

# Retrieve data
/retrieve mykey

# Upload a file
/send /path/to/file.txt

# Download a file
/get filename.txt

# List all database keys
/list

# List available files on the server
/listfiles

# Get help
/help
```

## 📁 Project Structure

```
go_udp_fun_server/
|── build/                 # Where executables go
├── server.go              # Main server implementation
├── build.bat              # Windows build script
├── client/
|   ├── downloads/         # Client download directory (created automatically)
│   └── client.go          # Interactive client implementation
├── internal/
|   └── security/
|           └── encryption.go # encryption layer used by client and server 
├── test/
│   ├── test_suite.go      # Comprehensive test suite
│   └── pycat.py           # Simple Python netcat clone for testing against server
├── uploads/               # Server file storage (created automatically)
└── README.md              # This file
```

## 🔌 Protocol Documentation

GUFS uses a custom binary protocol over UDP. All packets begin with a single command byte followed by optional payload data.

### Connection Protocol

1. **Handshake Sequence**:
   ```
      A standard 3-way handshake is required to establish a connection.

         Client → Server: [0x10] (CONNECT_SYN)

         Server → Client: [0x11] (CONNECT_SYN_ACK)

         Client → Server: [0x12] (CONNECT_ACK)
   ```

2. **Encryption Handshake (Optional)**
   ```
      Immediately after the connection is established, the client may initiate a key exchange to enable end-to-end encryption.

      Client → Server: [0x17][Client Public Key]

      Server → Client: [0x17][Server Public Key]

      Client → Server: [0x18] (KEY_CONFIRM)

      Server → Client: [0x18] (KEY_CONFIRM)

      After this handshake, all further communication between this client and the server is encrypted.
   ```

3. **Session Maintenance**:
   - Clients must send heartbeats `[0x13]` every 15 seconds
   - Server removes inactive clients after 60 seconds

### Command Reference

| Byte | Command | Payload Format | Description |
|------|---------|----------------|-------------|
| `0x02` | BROADCAST | `string(message)` | Send message to all connected clients |
| `0x03` | STATUS | None | Get server uptime and client count |
| `0x04` | PROCESS_DATA | `string(text)` | Reverse the provided text |
| `0x05` | TIME | None | Get current server time |
| `0x06` | SET_USERNAME | `string(username)` | Set client display name |
| `0x07` | ECHO | `[]byte(data)` | Echo data back to client |
| `0x08` | CMD_LIST_USERS | `string(usernames)` | Return list of active users | 
| `0x09` | CMD_PRIVATE_MSG  | `[]byte(receiver'\n'message)` | Private message user connected to server |
| `0x10` | CONNECT_SYN | None | Initiate connection |
| `0x11` | CONNECT_SYN_ACK | None | Server connection response |
| `0x12` | CONNECT_ACK | None | Client connection confirmation |
| `0x13` | HEARTBEAT | None | Keep connection alive |
| `0x14` | DISCONNECT | None | Disconnect from server |
| `0x15` | CMD_PING | None | Sent to server from client to receive pong |
| `0x16` | CMD_PONG | None | Send back to client after ping received |
| `0x17` | KEY_EXCHANGE | `[]byte(publicKey)` | Exchange public keys for encryption |
| `0x18` | KEY_CONFIRM  | None                | Confirm encryption is enabled        |
| `0x19` | CMD_SERVER_HEARTBEAT | None | Ensure server is alive |
| `0x20` | DB_STORE | `string(key=value)` | Store key-value pair |
| `0x21` | DB_RETRIEVE | `string(key)` | Retrieve value by key |
| `0x22` | DB_LIST | None | List all database keys |
| `0x23` | CMD_ROLL_DICE	 | `(string(message))` | Return random dice roll |
| `0x24` | CMD_EIGHT_BALL	 | `(string(message))` | Return 8 ball message |
| `0x30` | VERSION | None | Get server version |
| `0x31` | HELP | None | Get command help text |
| `0x40` | FILE_START | `[4B chunks][filename]` | Initiate file upload |
| `0x41` | FILE_CHUNK | `[4B seq][1B idLen][id][data]` | Send file chunk |
| `0x42` | FILE_ACK | `[4B sequence]` | Acknowledge chunk receipt |
| `0x43` | FILE_GET | `string(filename)` | Request file download |
| `0x44` | FILE_LIST | None | List available files |
| `0x45` | FILE_REQUEST_CHUNKS | [filename][4B seq1][4B seq2]... | Client requests specific missing chunks. |
| `0x46` | CMD_FILE_DOWNLOAD_ACK | None | File download acknowledgement | 
| `0x47` | CMD_FILE_DELETE   | None | Deletes file on server | 
| `0x50` | CMD_SERVER_ANNOUNCEMENT | `string(message)` | Server announcement  to clients |

### File Transfer Protocol

The file transfer system uses a reliable chunked approach:

1. **Upload Process**:
   ```
   Client → Server: FILE_START [totalChunks][filename]
   Server → Client: transferID
   Client → Server: FILE_CHUNK [seqNum][idLen][transferID][data] (repeat)
   Server → Client: FILE_ACK [seqNum] (for each chunk)
   ```

2. **Download Process**:
   ```
   Client → Server: FILE_GET [filename]
   Server → Client: FILE_START [totalChunks][filename]
   Server → Client: FILE_CHUNK [seqNum][data] (repeat for each chunk)
   Client → Server: FILE_REQUEST_CHUNKS [filename][missingSeq1]... (if chunks are missing after timeout)
   Server → Client: FILE_CHUNK [missingSeqNum][data] (re-sends only requested chunks)
   ```

3. **Features**:
   - 1KB chunk size for optimal UDP performance
   - Sequence-based ordering for reliable assembly
   - Retry mechanism with 3-attempt limit
   - Concurrent transfer support with unique session IDs
   - Automatic timeout handling (20 seconds)

## 🧪 Testing

Run the comprehensive test suite:

```bash
cd test
go run test_suite.go
```

The test suite covers:
- Connection handshake
- Username management
- Echo and data processing
- Database operations
- Multi-client broadcasting
- Error handling

### Test Output Example
```
--- STARTING TEST SUITE ---
--- Running Single-Client Tests ---
Testing: Handshake
✅ Handshake PASSED
Testing: Set Username to 'TestClient1'
✅ Set Username PASSED
...
--- Running Multi-Client Broadcast Test ---
✅ Broadcast Test PASSED!
--- TEST SUITE COMPLETE ---
```

## 🔧 Configuration

### Server Options
- `-ip`: Bind IP address (default: "127.0.0.1")
- `-port`: Listen port (default: "8080")

### Client Options
- `-server`: Server address (default: "127.0.0.1:8080")
- `-username`: Initial username (default: auto-generated)

### Limits
- Database: 64 key-value pairs maximum
- Value size: 8KB maximum per entry
- File chunk size: 1KB
- Client timeout: 60 seconds without heartbeat


## 🔒 Security & Encryption

### Automatic Encryption
GUFS automatically negotiates encryption with compatible clients:
- **New clients**: Receive full AES-256-GCM encryption automatically
- **Legacy clients**: Continue to work without encryption (backwards compatible)
- **Mixed environments**: Encrypted and unencrypted clients can coexist on the same server

### Encryption Details
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Exchange**: ECDH P-256 (Elliptic Curve Diffie-Hellman)
- **Key Length**: 256-bit encryption keys
- **Authentication**: Built-in message authentication prevents tampering
- **Forward Secrecy**: Keys are ephemeral and not stored

### Connection Security Flow
1. Standard UDP handshake establishes connection
2. Client and server exchange ECDH public keys
3. Both derive shared AES-256 key from ECDH
4. All subsequent communication is encrypted and authenticated
5. Legacy clients skip steps 2-4 and communicate unencrypted

## 🐛 Troubleshooting

### Common Issues

1. **Connection Refused**
   ```bash
   Error: Could not connect to server at 127.0.0.1:8080
   ```
   - Ensure the server is running
   - Check firewall settings
   - Verify the correct IP/port

2. **File Upload Timeout**
   ```bash
   Timeout waiting for ACK on chunk 0. Retrying...
   ```
   - Check network connectivity
   - Verify file permissions
   - Ensure sufficient disk space on server

3. **Username Required Error**
   ```bash
   Error: You must set a username before broadcasting!
   ```
   - Set username with `/username YourName`
   - Username is required for most operations

4. **Encryption Warnings**
   ```bash
   Warning: Encryption setup failed: server did not confirm encryption
   ```
   - This is normal when connecting to older servers
   - Client will continue with unencrypted communication
   - All functionality remains available

5. **Mixed Client Environment**
   ```bash
   Some clients show 🔒 indicator, others don't
   ```
   - This is expected behavior in mixed environments
   - Encrypted clients show 🔒 lock icon
   - All clients can communicate regardless of encryption status

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`cd test && go run test_suite.go`)
4. Commit changes (`git commit -am 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**derrybm/silencer0151**

## 🙏 Acknowledgments

- Built for learning UDP networking concepts
- Inspired by traditional IRC servers
- Designed for educational and experimental use

### 🎯 **Key Highlights**
- **Military-grade encryption** with zero configuration required
- **Seamless backwards compatibility** with legacy clients  
- **Perfect forward secrecy** protects past communications
- **Automatic security negotiation** without user intervention

---

**Note**: This server is designed for educational purposes and local network use. For production environments, consider additional security measures, authentication, and error handling.
