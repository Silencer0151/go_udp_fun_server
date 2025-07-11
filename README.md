# GUFS - Go UDP Fun Server

[![Go Version](https://img.shields.io/badge/Go-1.19+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**GUFS** (Go UDP Fun Server) is a concurrent, stateful UDP server designed for learning and experimentation with custom network protocols. It implements a robust binary communication protocol supporting client connections, real-time messaging, persistent data storage, and reliable file transfers.

## 🚀 Features

### Core Functionality
- **Custom Binary Protocol**: Efficient single-byte command system
- **Connection Management**: 3-way handshake with heartbeat-based session maintenance
- **Concurrent Architecture**: Handles multiple clients simultaneously using goroutines
- **Thread-Safe Operations**: Mutex-protected shared state management

### Communication Features
- **Real-time Broadcasting**: Multi-client messaging system
- **Direct Messaging**: Echo and data processing commands
- **Username Management**: Configurable client identities

### Data Storage
- **In-Memory Database**: Key-value storage with size limits
- **CRUD Operations**: Store, retrieve, and list database entries
- **Concurrent Access**: Thread-safe database operations

### File Transfer
- **Chunked Upload/Download**: Reliable file transfer with acknowledgments
- **Resume Capability**: Handles packet loss with retry mechanisms
- **Transfer Management**: Unique session IDs for concurrent transfers

## 📋 Requirements

- Go 1.19 or higher
- Network access for UDP communication (default: localhost:8080)

## 🛠️ Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/go_udp_fun_server.git
cd go_udp_fun_server
```

2. Build the server:
```bash
go build -o gufs-server server.go
```

3. Build the client:
```bash
cd client
go build -o gufs-client client.go
```

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
# Default connection
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

# Echo test
/echo Hello World

# Store data
/store mykey=myvalue

# Retrieve data
/retrieve mykey

# Upload a file
/send /path/to/file.txt

# Download a file
/get filename.txt

# Get help
/help
```

## 📁 Project Structure

```
go_udp_fun_server/
├── server.go              # Main server implementation
├── client/
|   ├── downloads/         # Client download directory (created automatically)
│   └── client.go          # Interactive client implementation
├── test/
│   └── test_suite.go      # Comprehensive test suite
├── uploads/               # Server file storage (created automatically)
└── README.md             # This file
```

## 🔌 Protocol Documentation

GUFS uses a custom binary protocol over UDP. All packets begin with a single command byte followed by optional payload data.

### Connection Protocol

1. **Handshake Sequence**:
   ```
   Client → Server: [0x10] (SYN)
   Server → Client: [0x11] (SYN-ACK)
   Client → Server: [0x12] (ACK)
   ```

2. **Session Maintenance**:
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
| `0x10` | CONNECT_SYN | None | Initiate connection |
| `0x11` | CONNECT_SYN_ACK | None | Server connection response |
| `0x12` | CONNECT_ACK | None | Client connection confirmation |
| `0x13` | HEARTBEAT | None | Keep connection alive |
| `0x20` | DB_STORE | `string(key=value)` | Store key-value pair |
| `0x21` | DB_RETRIEVE | `string(key)` | Retrieve value by key |
| `0x22` | DB_LIST | None | List all database keys |
| `0x30` | VERSION | None | Get server version |
| `0x31` | HELP | None | Get command help text |
| `0x40` | FILE_START | `[4B chunks][filename]` | Initiate file upload |
| `0x41` | FILE_CHUNK | `[4B seq][1B idLen][id][data]` | Send file chunk |
| `0x42` | FILE_ACK | `[4B sequence]` | Acknowledge chunk receipt |
| `0x43` | FILE_GET | `string(filename)` | Request file download |
| `0x44` | FILE_LIST | None | List available files |

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
   Server → Client: FILE_CHUNK [seqNum][data] (repeat)
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
   Timeout waiting for ACK on chunk 0
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

---

**Note**: This server is designed for educational purposes and local network use. For production environments, consider additional security measures, authentication, and error handling.
