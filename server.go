// GUFS: Go UDP Fun Server
// Author: derrybm/silencer0151
// Version: 0.9.6
//
// Description:
// A concurrent, stateful UDP server designed for learning and experimentation.
// It implements a custom binary protocol to handle client connections,
// messaging, data storage, and file transfers. The server is built
// to be robust, handling multiple clients simultaneously using goroutines
// and managing state safely with mutexes.
//
// Protocol Overview:
// - Communication is done via single-byte commands.
// - A 3-way handshake (SYN, SYN-ACK, ACK) is required to establish a session.
// - Heartbeats are used to maintain sessions and clean up inactive clients.
// - See the getHelpText() function for a full command list.

/*
	-- TODO LIST --
	- Chat rooms (create, leave, set topic)
	- Basic user authentication (hashed password on a simple db)
		- User persistence, username/pw db
*/

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"gufs/internal/security"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Define command constants
const (
	SERVER_VERSION = "GUFS v0.9.6"

	// General Commands
	CMD_BROADCAST           byte = 0x02
	CMD_STATUS              byte = 0x03
	CMD_PROCESS_DATA        byte = 0x04
	CMD_TIME                byte = 0x05
	CMD_SET_USERNAME        byte = 0x06
	CMD_ECHO                byte = 0x07
	CMD_LIST_USERS          byte = 0x08
	CMD_PRIVATE_MSG         byte = 0x09
	CMD_SERVER_ANNOUNCEMENT byte = 0x50

	// Connection Protocol
	CMD_CONNECT_SYN      byte = 0x10
	CMD_CONNECT_SYN_ACK  byte = 0x11
	CMD_CONNECT_ACK      byte = 0x12
	CMD_HEARTBEAT        byte = 0x13
	CMD_DISCONNECT       byte = 0x14
	CMD_PING             byte = 0x15
	CMD_PONG             byte = 0x16
	CMD_SERVER_HEARTBEAT byte = 0x19

	// Database Commands
	CMD_DB_STORE    byte = 0x20
	CMD_DB_RETRIEVE byte = 0x21
	CMD_DB_LIST     byte = 0x22

	// Metadata Commands
	CMD_VERSION byte = 0x30
	CMD_HELP    byte = 0x31

	// File Transfer Protocol
	CMD_FILE_START          byte = 0x40
	CMD_FILE_CHUNK          byte = 0x41
	CMD_FILE_ACK            byte = 0x42
	CMD_FILE_GET            byte = 0x43
	CMD_FILE_LIST           byte = 0x44
	CMD_FILE_REQUEST_CHUNKS byte = 0x45
	CMD_FILE_DOWNLOAD_ACK   byte = 0x46
	CMD_FILE_DELETE         byte = 0x47

	// End-To-End Encryption Handshake Commands
	CMD_KEY_EXCHANGE byte = 0x17 // Exchange public keys
	CMD_KEY_CONFIRM  byte = 0x18 // Confirm encryption is ready

	// Special marker to identify encrypted packets
	ENCRYPTED_MARKER byte = 0xFF // Prepended to encrypted data
)

// database global variables and map
const DB_MAX_SIZE int = 64          //max num of key value pairs
const DB_MAX_VALUE_BYTES int = 8000 // max size for a value

var database = make(map[string][]byte)
var dbMutex = &sync.Mutex{}

// Client struct and map for state management
type Client struct {
	Username      string
	Addr          *net.UDPAddr
	IsConnected   bool
	LastHeartbeat time.Time
	EncMgr        *security.EncryptionManager
	IsEncrypted   bool
}

var clients = make(map[string]Client)
var clientsMutex = &sync.Mutex{}
var serverStartTime = time.Now()

// file transfer struct, map and globals
type FileTransfer struct {
	Filename       string
	TotalChunks    uint32
	ReceivedChunks map[uint32][]byte
	LastActivity   time.Time
	LastProgress   time.Time
}

var activeTransfers = make(map[string]*FileTransfer) // key: transfer ID
var transfersMutex = &sync.Mutex{}

type FileDownloadSession struct {
	ClientAddr   *net.UDPAddr
	Filename     string
	FileData     []byte
	TotalChunks  int
	WindowSize   int
	WindowStart  int
	WindowEnd    int
	AckedChunks  map[int]bool
	LastActivity time.Time
	RetryCount   map[int]int // Track retries per chunk
	AckChan      chan int    // Channel for receiving ACKs
	Done         chan bool   // Signal completion
	Mutex        sync.Mutex
}

type HistoryMessage struct {
	Timestamp time.Time
	Username  string
	Message   string
}

var messageHistory []HistoryMessage
var historyMutex = &sync.Mutex{}

const MAX_HISTORY_SIZE = 8

var downloadSessions = make(map[string]*FileDownloadSession) // key: clientAddr + filename
var downloadSessionsMutex = &sync.Mutex{}
var logChannel = make(chan string, 50)
var shutdownChan = make(chan struct{})
var replShutdown = make(chan struct{})
var wg sync.WaitGroup
var shutdownOnce sync.Once
var replShutdownOnce sync.Once

func main() {

	// Handle CLI flags
	ip := flag.String("ip", "127.0.0.1", "The IP address to bind the server to.")
	port := flag.String("port", "8080", "The port to listen on.")
	flag.Parse()

	//LOGGING
	go func() {
		for logMsg := range logChannel {
			fmt.Print(logMsg) // Simple, clean output without ANSI codes (single line)
		}
	}()

	addrStr := *ip + ":" + *port
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		logChannel <- fmt.Sprintf("Error resolving address: %s\n", err)
		os.Exit(1)
	}

	// create uploads directory proactively
	_ = os.Mkdir("uploads", 0755)

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		logChannel <- fmt.Sprintf("Error listening: %s\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	//REPL
	wg.Add(1)
	go startREPL(conn)

	logChannel <- fmt.Sprintf("UDP server listening on %s\n", conn.LocalAddr().String())

	wg.Add(4) // REPL + 3 background go routines
	// Start the client cleanup goroutine
	go cleanupDeadClients(conn)
	// cleanup download sessions
	go cleanupDownloadSessions()
	// send heartbeats to clients
	go sendServerHeartbeats(conn)

	buffer := make([]byte, 8192)
	for {
		select {
		case <-shutdownChan:
			// The 'quit' command was used.
			logChannel <- "Closing UDP listener...\n"
			conn.Close() // Close the connection to stop blocking reads.
			logChannel <- "Server shutdown complete.\n"
			return // Exit the main goroutine.
		default:
			// No shutdown signal, proceed with reading from the connection.
		}

		// We must set a read deadline. This makes the ReadFromUDP call non-blocking
		// and allows the 'select' statement to check for the shutdown signal periodically.
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			// If the error is a timeout, it's expected. We just continue the loop.
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// If the error is not a timeout, it could be a real issue or the connection closing.
			logChannel <- fmt.Sprintf("Error reading from UDP: %v\n", err)
			continue
		}

		// Copy the raw data
		data := make([]byte, n)
		copy(data, buffer[:n])

		//Check if this client has encryption enabled and try to decrypt
		clientsMutex.Lock()
		client, exists := clients[clientAddr.String()]
		clientsMutex.Unlock()

		if exists && client.IsEncrypted && client.EncMgr != nil && client.EncMgr.IsReady() {
			decrypted, err := client.EncMgr.Decrypt(data)
			if err != nil {
				// Decryption failed - might be an unencrypted handshake packet
				// Log it but continue with original data
				logChannel <- fmt.Sprintf("Decryption failed for %s: %v (might be unencrypted)\n", clientAddr, err)
			} else {
				// Successfully decrypted, use the decrypted data
				data = decrypted
			}
		}
		// If client doesn't exist or encryption isn't enabled, data remains unchanged

		// Call existing handlePacket function with potentially decrypted data
		go handlePacket(conn, clientAddr, data)
	}
}

// this is for potential nc users who may want to view the protocol without a "client"
func getProtocolText() string {
	return `
--- GUFS Raw Byte Protocol ---
This server communicates via a binary protocol. Packets must start with a 1-byte command.
Payload formats are specified below. Full documentation: https://github.com/Silencer0151/go_udp_fun_server

[Connection]
1. Client sends [0x10] (CMD_CONNECT_SYN)
2. Server replies with [0x11] (CMD_CONNECT_SYN_ACK)
3. Client sends [0x12] (CMD_CONNECT_ACK) to finalize.
4. Client must send [0x13] (CMD_HEARTBEAT) periodically to stay connected.

[Encryption Handshake (Optional, after Connection)]
1. Client -> Server: [0x17][Client Public Key] (CMD_KEY_EXCHANGE)
2. Server -> Client: [0x17][Server Public Key] (CMD_KEY_EXCHANGE)
3. Client computes shared secret and sends [0x18] (CMD_KEY_CONFIRM).
4. Server computes shared secret and replies with [0x18] (CMD_KEY_CONFIRM).
5. All subsequent communication from both sides is now encrypted.

[Commands (Byte | Name | Payload)]
0x06 | SET_USERNAME      | string(username)
0x02 | BROADCAST         | string(message)
0x07 | ECHO              | []byte(any data)
0x03 | STATUS            | (no payload)
0x05 | TIME              | (no payload)
0x04 | PROCESS_DATA      | string(any text to be reversed)
0x08 | CMD_LIST_USERS    | []byte(usernames)
0x09 | CMD_PRIVATE_MSG   | []byte(receiver'\n'message)
0x15 | CMD_PING          | (no payload)
0x16 | CMD_PONG          | (no payload)
0x17 | CMD_KEY_EXCHANGE  | []byte(publicKey)
0x18 | CMD_KEY_CONFIRM   | (no payload)
0x19 | CMD_SERVER_HEARTBEAT | (no payload)
0x30 | VERSION           | (no payload)
0x31 | HELP              | (no payload) - Returns REPL client help.
0x47 | CMD_FILE_DELETE   | (no payload) 
0x50 | CMD_SERVER_ANNOUNCEMENT | string(message) 

[Database]
0x20 | DB_STORE      | key=value
0x21 | DB_RETRIEVE   | key
0x22 | DB_LIST       | (no payload)

[File Transfer Protocol]
Upload Process:
1. Client -> Server: [0x40][4B totalChunks][filename] (FILE_START)
2. Server -> Client: transferID (string response)
3. Client -> Server: [0x41][4B seqNum][1B idLen][transferID][data] (FILE_CHUNK)
4. Server -> Client: [0x42][4B seqNum] (FILE_ACK) - for each chunk

Download Process:
1. Client -> Server: [0x43][filename] (FILE_GET)
2. Server -> Client: [0x40][4B totalChunks][filename] (FILE_START)
3. Server -> Client: [0x41][4B seqNum][data] (FILE_CHUNK) - repeated
4. Client assembles chunks by sequence number

Additional File Commands:
0x44 | FILE_LIST     | (no payload) - List available files

Notes:
- Chunk size: 1024 bytes
- Retry limit: 3 attempts per chunk
- Transfer timeout: 20 seconds
- Sequence numbers ensure correct assembly
`
}

func getHelpText() string {
	return fmt.Sprintf(`
--- GUFS Help (%s) ---
Usage: Type a message to broadcast, or use /<command> for special actions.
Example: /username Alice

[Connection]
/quit                  Disconnect from the server.

[Messaging]
/username <name>       Set your display name.
/echo <message>        Server repeats a message back to you.
/users                 Server sends list of connected client usernames.
/msg <username> <message> Direct message user connected to the server.

[Server Info]
/help                  Show this help message.
/version               Get the server version.
/status                Get server uptime and client count.
/time                  Get the current server time.
/reverse <message>     Server reverses a string for you.
/ping                  Get ping from server.

[Key-Value Database]
/store <key=value>     Store a value in the database.
/retrieve <key>        Get a value from the database.
/list                  List all keys in the database.

[File Transfer]
/send <local_filepath> Upload a file to the server.
/get <filename>        Download a file from the server.
/listfiles             List all available files on the server.
/delete <filename>     Deletes specified file on the server.
`, SERVER_VERSION)
}

func handlePacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	if len(data) == 0 {
		return
	}

	// ensure 'client' is in scope for all operations
	addrStr := addr.String()
	clientsMutex.Lock()
	client, isKnown := clients[addrStr]
	clientsMutex.Unlock()

	if string(data) == "help\n" {
		secureWriteToUDP(conn, []byte(getProtocolText()), addr, &client)
		return
	}
	// For netcat users wanting protocol details
	if string(data) == "protocol\n" {
		secureWriteToUDP(conn, []byte(getProtocolText()), addr, &client)
		return
	}

	command := data[0]
	payload := data[1:]

	// Allow connection commands to pass through
	isConnectCmd := command == CMD_CONNECT_SYN || command == CMD_CONNECT_ACK

	// If the command is not a connection command and the client is not connected, reject it.
	if !isConnectCmd && (!isKnown || !client.IsConnected) {
		secureWriteToUDP(conn, []byte("The server did not understand your request, try 'protocol' for more information."), addr, &client)
		logChannel <- fmt.Sprintf("Rejected command from unconnected client %s - '%s'\n", addr, string(data))
		return
	}

	// Route commands
	switch command {
	case CMD_PING:
		secureWriteToUDP(conn, []byte{CMD_PONG}, addr, &client)
		logChannel <- fmt.Sprintf("Sent PONG to %s\n", client.Username)

	case CMD_TIME:
		serverTime := time.Now().Format(time.RFC3339)
		secureWriteToUDP(conn, []byte(serverTime), addr, &client)

	case CMD_SET_USERNAME:
		username := strings.TrimSpace(string(payload))

		// Basic validation
		if username == "" {
			secureWriteToUDP(conn, []byte("Error: Username cannot be empty."), addr, &client)
			return
		}

		if len(username) > 50 {
			secureWriteToUDP(conn, []byte("Error: Username too long (max 50 characters)."), addr, &client)
			return
		}

		clientsMutex.Lock()
		defer clientsMutex.Unlock()

		// Check if username is already taken
		if isUsernameTaken(username, addrStr) {
			secureWriteToUDP(conn, []byte("Error: Username '"+username+"' is already taken. Please choose another."), addr, &client)
			return
		}

		// Get current client and update username
		if client, ok := clients[addrStr]; ok {
			oldUsername := client.Username
			client.Username = username
			clients[addrStr] = client

			logChannel <- fmt.Sprintf("Set username for %s to '%s'\n", addr, username)
			secureWriteToUDP(conn, []byte("Username set successfully!"), addr, &client)

			if oldUsername == "" {
				// This is a new user joining - send them history first
				history := getHistoryForNewUser()
				if history != "" {
					secureWriteToUDP(conn, []byte(history), addr, &client)
					time.Sleep(100 * time.Millisecond) // Small delay to ensure history is received first
				}

				joinMsg := fmt.Sprintf("[Server]: Welcome, %s has joined!", username)
				// Broadcast the join message
				for clientAddr, otherClient := range clients {
					if clientAddr != addrStr && otherClient.IsConnected {
						secureWriteToUDP(conn, []byte(joinMsg), otherClient.Addr, &otherClient)
					}
				}
			} else if oldUsername != username {
				// If oldUsername was not empty and is different, it's a name change.
				changeMsg := fmt.Sprintf("[Server]: User '%s' changed their name to '%s'", oldUsername, username)
				// Broadcast the name change
				for clientAddr, otherClient := range clients {
					if clientAddr != addrStr && otherClient.IsConnected {
						secureWriteToUDP(conn, []byte(changeMsg), otherClient.Addr, &otherClient)
					}
				}
			}
		}

	case CMD_STATUS:
		uptime := time.Since(serverStartTime).Round(time.Second)
		clientsMutex.Lock()
		numClients := len(clients)
		clientsMutex.Unlock()
		statusMsg := fmt.Sprintf("Server Uptime: %s | Connected Clients: %d", uptime, numClients)
		secureWriteToUDP(conn, []byte(statusMsg), addr, &client)

	case CMD_LIST_USERS:
		clientsMutex.Lock()
		defer clientsMutex.Unlock()

		userList := []byte(trimTrailingNewline(getUsers()))
		secureWriteToUDP(conn, userList, addr, &client)

	case CMD_BROADCAST:
		clientsMutex.Lock()
		defer clientsMutex.Unlock()

		sender, ok := clients[addrStr]
		if !ok || sender.Username == "" {
			// if no username tell user to set one
			secureWriteToUDP(conn, []byte("Error: You must set a username before broadcasting!"), addr, &client)
			return
		}

		message := string(payload)
		messageToBroadcast := fmt.Sprintf("[%s]: %s", sender.Username, message)
		logChannel <- fmt.Sprintf("Broadcasting from %s: %s\n", sender.Username, message)

		// Add to history BEFORE broadcasting
		addToHistory(sender.Username, message)

		for _, otherClient := range clients {
			if otherClient.Addr.String() == addrStr || !otherClient.IsConnected {
				continue
			}

			secureWriteToUDP(conn, []byte(messageToBroadcast), otherClient.Addr, &otherClient)
		}

	case CMD_PROCESS_DATA:
		// convert payload into slicve of runes for character handling
		runes := []rune(string(payload))

		// two pointer swap to reverse the slice
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}

		reversedPayload := []byte(string(runes))
		secureWriteToUDP(conn, reversedPayload, addr, &client)

	case CMD_PRIVATE_MSG:
		// 1. Parse the payload: [receiverUsername]\n[message]
		parts := bytes.SplitN(payload, []byte("\n"), 2)
		if len(parts) != 2 {
			// Invalid payload format, do nothing.
			return
		}
		receiverUsername := string(parts[0])
		message := string(parts[1])

		clientsMutex.Lock()

		// 2. Get the sender's username
		sender, senderOK := clients[addr.String()]
		if !senderOK || sender.Username == "" {
			// The sender is not properly connected or has no username.
			clientsMutex.Unlock()
			secureWriteToUDP(conn, []byte("Error: You must have a username to send messages."), addr, &client)
			return
		}

		// 3. Find the receiver client
		var receiverClient Client
		receiverFound := false
		for _, client := range clients {
			if client.Username == receiverUsername && client.IsConnected {
				receiverClient = client
				receiverFound = true
				break
			}
		}

		// Unlock the mutex after reading from the map is finished.
		clientsMutex.Unlock()

		// 4. Relay the message or send an error
		if receiverFound {
			// Format the private message
			formattedMsg := fmt.Sprintf("[Private from %s]: %s", sender.Username, message)
			secureWriteToUDP(conn, []byte(formattedMsg), receiverClient.Addr, &receiverClient)

			// Send a confirmation back to the sender
			secureWriteToUDP(conn, []byte("Message sent."), addr, &client)
		} else {
			// Send an error if the user was not found
			errorMsg := fmt.Sprintf("Error: User '%s' not found or is not connected.", receiverUsername)
			secureWriteToUDP(conn, []byte(errorMsg), addr, &client)
		}

	case CMD_DB_STORE:
		// First, check if the client is valid. This only requires the clientMutex.
		clientsMutex.Lock()
		sender, ok := clients[addrStr]
		if !ok || sender.Username == "" {
			clientsMutex.Unlock() // Unlock before returning!
			secureWriteToUDP(conn, []byte("Error: You must set a username before storing values!"), addr, &client)
			return
		}
		senderUsername := sender.Username // Copy the username
		clientsMutex.Unlock()             // Unlock immediately after check.

		// Now, handle the database logic, which uses the dbMutex.
		parts := bytes.SplitN(payload, []byte("="), 2)
		if len(parts) != 2 {
			secureWriteToUDP(conn, []byte("Error: Invalid format. Use key=value."), addr, &client)
			return
		}
		key, value := string(parts[0]), string(parts[1])

		if len(value) > DB_MAX_VALUE_BYTES {
			msg := fmt.Sprintf("Error: Value size exceeds the limit of %d bytes.", DB_MAX_VALUE_BYTES)
			secureWriteToUDP(conn, []byte(msg), addr, &client)
			return
		}

		dbMutex.Lock()
		_, keyExists := database[key]
		if !keyExists && len(database) >= DB_MAX_SIZE {
			dbMutex.Unlock() // Unlock before returning!
			secureWriteToUDP(conn, []byte("Error: Database is full."), addr, &client)
			return
		}
		database[key] = []byte(value)
		dbMutex.Unlock() // Unlock immediately after DB operation.

		logChannel <- fmt.Sprintf("Stored key '%s' for client %s\n", key, addr)
		secureWriteToUDP(conn, []byte("Value stored successfully."), addr, &client)

		// Broadcast that a value was set
		messageToBroadcast := fmt.Sprintf("[Server]: User [%s] has set a value for %s", senderUsername, key)
		clientsMutex.Lock()
		for _, otherClient := range clients {
			if otherClient.Addr.String() != addrStr && otherClient.IsConnected {
				secureWriteToUDP(conn, []byte(messageToBroadcast), otherClient.Addr, &otherClient)
			}
		}
		clientsMutex.Unlock()

	case CMD_DB_RETRIEVE:
		key := string(payload)

		dbMutex.Lock()
		value, ok := database[key]
		dbMutex.Unlock()

		if !ok {
			secureWriteToUDP(conn, []byte("Error: Key not found."), addr, &client)
			return
		}

		secureWriteToUDP(conn, value, addr, &client)

	case CMD_DB_LIST:
		dbMutex.Lock()

		if len(database) == 0 {
			dbMutex.Unlock()
			secureWriteToUDP(conn, []byte("Database is empty."), addr, &client)
			return
		}

		// Create a slice to hold all the keys
		keys := make([]string, 0, len(database))
		for k := range database {
			keys = append(keys, k)
		}
		dbMutex.Unlock()

		//join the keys with a newline for a clean, readable list
		response := strings.Join(keys, "\n")
		secureWriteToUDP(conn, []byte(response), addr, &client)

	case CMD_FILE_START:
		if len(payload) < 5 { // 4 bytes for chunk count + at least 1 for filename
			secureWriteToUDP(conn, []byte("Error: Malformed file transfer start packet."), addr, &client)
			return
		}

		// Read the total number of chunks from the first 4 bytes of the payload
		totalChunks := binary.BigEndian.Uint32(payload[0:4])
		filename := string(payload[4:])

		// Create a unique ID for this transfer session
		transferID := fmt.Sprintf("%s-%s", addr.String(), filename)

		logChannel <- fmt.Sprintf("Initiating file transfer '%s' (%d chunks) for ID %s\n", filename, totalChunks, transferID)

		// Create and store the state for this new transfer
		transfersMutex.Lock()
		activeTransfers[transferID] = &FileTransfer{
			Filename:       filename,
			TotalChunks:    totalChunks,
			ReceivedChunks: make(map[uint32][]byte),
			LastActivity:   time.Now(),
		}
		transfersMutex.Unlock()

		// Respond to the client with the transfer ID they must use
		secureWriteToUDP(conn, []byte(transferID), addr, &client)

	case CMD_FILE_CHUNK:
		if len(payload) < 5 { // 4 for sequence + 1 for ID len
			return // Invalid packet
		}

		// Parse the packet
		sequenceNumber := binary.BigEndian.Uint32(payload[0:4])
		idLen := int(payload[4])
		if len(payload) < 5+idLen {
			return // Invalid packet
		}
		transferID := string(payload[5 : 5+idLen])
		chunkData := payload[5+idLen:]

		transfersMutex.Lock()
		defer transfersMutex.Unlock()

		// Find the active transfer
		transfer, ok := activeTransfers[transferID]
		if !ok {
			return // Transfer not found or expired
		}

		// Store the chunk if we haven't seen it before
		if _, exists := transfer.ReceivedChunks[sequenceNumber]; !exists {
			transfer.ReceivedChunks[sequenceNumber] = chunkData
			transfer.LastActivity = time.Now()

			if time.Since(transfer.LastProgress) > time.Second {
				progress := (len(transfer.ReceivedChunks) * 100) / int(transfer.TotalChunks)
				logChannel <- fmt.Sprintf("Receiving '%s'... %d%% (%d/%d chunks)\n", transfer.Filename, progress, len(transfer.ReceivedChunks), transfer.TotalChunks)
				transfer.LastProgress = time.Now()
			}
		}

		// Check if the transfer is complete
		if uint32(len(transfer.ReceivedChunks)) == transfer.TotalChunks {
			logChannel <- fmt.Sprintf("Received all %d chunks for file '%s'. Assembling...\n", transfer.TotalChunks, transfer.Filename)
			go assembleFile(transfer)           // Assemble in a new goroutine to not block
			delete(activeTransfers, transferID) // Clean up the completed transfer
		}

		// Send ACK back to the client: [CMD_ACK][4 bytes for sequence_number]
		ackPacket := make([]byte, 5)
		ackPacket[0] = CMD_FILE_ACK
		binary.BigEndian.PutUint32(ackPacket[1:5], sequenceNumber)
		secureWriteToUDP(conn, ackPacket, addr, &client)

	case CMD_FILE_ACK:
		// Improved ACK format: [filename_len (1 byte)][filename][4B seqNum]
		if len(payload) < 6 { // 1 for len, at least 1 for filename, 4 for seqNum
			return
		}

		filenameLen := int(payload[0])
		if len(payload) < 1+filenameLen+4 {
			return // Malformed packet
		}

		filename := string(payload[1 : 1+filenameLen])
		seqNumPayload := payload[1+filenameLen:]
		seqNum := int(binary.BigEndian.Uint32(seqNumPayload))

		// Construct the specific session key to find the right download
		sessionKey := addr.String() + ":" + filename

		downloadSessionsMutex.Lock()
		if session, ok := downloadSessions[sessionKey]; ok {
			// Deliver the ACK to the correct channel
			select {
			case session.AckChan <- seqNum:
				// ACK delivered
			default:
				// Channel might be full, which is okay.
			}
		}
		downloadSessionsMutex.Unlock()

	case CMD_FILE_REQUEST_CHUNKS:
		// The payload will be: [filename_len (1 byte)][filename][4B seqNum1][4B seqNum2]...
		if len(payload) < 2 { // Must have at least length byte and one char for filename
			return
		}

		// 1. Read the length of the filename from the first byte.
		filenameLen := int(payload[0])
		if len(payload) < 1+filenameLen { // Check if payload is long enough for the filename
			return
		}

		// 2. Extract the filename.
		filename := string(payload[1 : 1+filenameLen])

		// 3. The rest of the payload is the list of missing chunk numbers.
		missingChunksData := payload[1+filenameLen:]

		// 4. Call the resend function with the correctly parsed data.
		go resendMissingChunks(conn, addr, filename, missingChunksData)

	case CMD_FILE_LIST:
		files, err := os.ReadDir("./uploads")
		if err != nil {
			secureWriteToUDP(conn, []byte("Error: Could not read uploads directory."), addr, &client)
			return
		}
		if len(files) == 0 {
			secureWriteToUDP(conn, []byte("No files available on server."), addr, &client)
			return
		}
		var filenames []string
		for _, f := range files {
			if !f.IsDir() {
				filenames = append(filenames, f.Name())
			}
		}
		secureWriteToUDP(conn, []byte(strings.Join(filenames, "\n")), addr, &client)

	case CMD_FILE_GET:
		filename := string(payload)
		go sendFileToClient(conn, addr, filename)

	case CMD_FILE_DELETE:
		clientsMutex.Lock()
		client, ok := clients[addr.String()]
		clientsMutex.Unlock()

		if !ok {
			return // Or handle error appropriately
		}

		filename := string(payload)
		filePath := filepath.Join("uploads", filename)

		// Basic security check to prevent directory traversal
		if strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
			secureWriteToUDP(conn, []byte("Error: Invalid filename."), addr, &client)
			return
		}

		err := os.Remove(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				secureWriteToUDP(conn, []byte("Error: File not found on server."), addr, &client)
			} else {
				secureWriteToUDP(conn, []byte("Error: Could not delete file."), addr, &client)
			}
			logChannel <- fmt.Sprintf("Failed attempt to delete file '%s' by %s: %v\n", filename, client.Username, err)
			return
		}

		successMsg := fmt.Sprintf("File '%s' was successfully deleted.", filename)
		secureWriteToUDP(conn, []byte(successMsg), addr, &client)
		logChannel <- fmt.Sprintf("User '%s' deleted file '%s'\n", client.Username, filename)

		// Announce the deletion to all other connected clients
		broadcastMsg := fmt.Sprintf("[Server]: %s deleted the file '%s'.", client.Username, filename)
		clientsMutex.Lock()
		for _, otherClient := range clients {
			if otherClient.Addr.String() != addr.String() && otherClient.IsConnected {
				secureWriteToUDP(conn, []byte(broadcastMsg), otherClient.Addr, &otherClient)
			}
		}
		clientsMutex.Unlock()

	case CMD_ECHO:
		secureWriteToUDP(conn, payload, addr, &client)

	case CMD_VERSION:
		secureWriteToUDP(conn, []byte(SERVER_VERSION), addr, &client)

	case CMD_HELP:
		secureWriteToUDP(conn, []byte(getHelpText()), addr, &client)

	case CMD_KEY_EXCHANGE:
		clientsMutex.Lock()
		clientForKey, ok := clients[addrStr]
		if !ok {
			clientsMutex.Unlock()
			return
		}

		// Initialize encryption manager for this client if not exists
		if clientForKey.EncMgr == nil {
			clientForKey.EncMgr, _ = security.NewEncryptionManager()
		}

		// Set peer's public key and establish shared secret
		err := clientForKey.EncMgr.SetSharedSecret(payload)
		if err != nil {
			clientsMutex.Unlock()
			conn.WriteToUDP([]byte("Encryption setup failed"), addr) // UNENCRYPTED
			return
		}

		// Send our public key back
		ourPublicKey := clientForKey.EncMgr.GetPublicKey()
		clients[addrStr] = clientForKey
		clientsMutex.Unlock()

		response := append([]byte{CMD_KEY_EXCHANGE}, ourPublicKey...)
		conn.WriteToUDP(response, addr) // UNENCRYPTED - this is handshake data

	case CMD_KEY_CONFIRM:
		clientsMutex.Lock()
		if clientToConfirm, ok := clients[addrStr]; ok && clientToConfirm.EncMgr != nil && clientToConfirm.EncMgr.IsReady() {
			clientToConfirm.IsEncrypted = true
			clients[addrStr] = clientToConfirm
			logChannel <- fmt.Sprintf("Encryption enabled for client %s\n", addrStr)
			conn.WriteToUDP([]byte{CMD_KEY_CONFIRM}, addr) // UNENCRYPTED - this is handshake confirmation
		}
		clientsMutex.Unlock()

	case CMD_CONNECT_SYN:
		logChannel <- fmt.Sprintf("Received SYN from %s, sending SYN-ACK\n", addrStr)

		// add client in a non-connected state
		clientsMutex.Lock()
		// We create a new client struct here to be added.
		newClient := Client{Addr: addr, IsConnected: false}
		clients[addrStr] = newClient
		clientsMutex.Unlock()

		//respond with SYNACK
		secureWriteToUDP(conn, []byte{CMD_CONNECT_SYN_ACK}, addr, &newClient)

	case CMD_CONNECT_ACK:
		clientsMutex.Lock()
		//check if connection is already pending
		if client, ok := clients[addrStr]; ok && !client.IsConnected {
			client.IsConnected = true
			client.LastHeartbeat = time.Now() //start timer for heartbeat
			clients[addrStr] = client
			logChannel <- fmt.Sprintf("Received ACK from %s. Connection established.\n", addrStr)
		}
		clientsMutex.Unlock()

	case CMD_HEARTBEAT:
		clientsMutex.Lock()
		if client, ok := clients[addr.String()]; ok && client.IsConnected {
			client.LastHeartbeat = time.Now()
			clients[addr.String()] = client
		}
		clientsMutex.Unlock()

	case CMD_DISCONNECT:
		clientsMutex.Lock()
		// First, find the client to get their username before they are removed.
		client, ok := clients[addrStr]
		if !ok {
			// If the client isn't in our map for some reason, just unlock and do nothing.
			clientsMutex.Unlock()
			return
		}
		// Store the username for the broadcast message.
		disconnectedUsername := client.Username
		if disconnectedUsername == "" {
			disconnectedUsername = "An unnamed user" // Fallback for users without a name
		}

		// Remove the client from the map. This is the core of the disconnect.
		delete(clients, addrStr)
		logChannel <- fmt.Sprintf("Client %s (%s) has disconnected.\n", disconnectedUsername, addrStr)

		// Prepare the broadcast message to notify other users.
		disconnectMsg := fmt.Sprintf("[Server]: %s has disconnected.", disconnectedUsername)

		// Loop through all *remaining* connected clients to notify them.
		for _, otherClient := range clients {
			// No need to check for the sender, as they've already been deleted.
			if otherClient.IsConnected {
				secureWriteToUDP(conn, []byte(disconnectMsg), otherClient.Addr, &otherClient)
			}
		}
		clientsMutex.Unlock()

	default:
		errMsg := fmt.Sprintf("Unknown command byte: 0x%x. Type 'help' for more information.", command)
		secureWriteToUDP(conn, []byte(errMsg), addr, &client)
		logChannel <- fmt.Sprintf("received unknown packet from client: %s - 0x%x\n", addrStr, command)
	}
}

func sendFileToClient(conn *net.UDPConn, addr *net.UDPAddr, filename string) {
	const chunkSize = 1024
	const windowSize = 32
	const maxRetries = 3
	const ackTimeout = 2 * time.Second

	filePath := "./uploads/" + filename
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		// Handle error as before
		clientsMutex.Lock()
		client, exists := clients[addr.String()]
		clientsMutex.Unlock()

		if exists {
			secureWriteToUDP(conn, []byte("Error: File not found on server."), addr, &client)
		}
		return
	}

	// Get client info for encryption
	clientsMutex.Lock()
	client, exists := clients[addr.String()]
	clientsMutex.Unlock()

	if !exists {
		return
	}

	totalChunks := (len(fileData) + chunkSize - 1) / chunkSize
	sessionKey := addr.String() + ":" + filename

	// Create download session
	session := &FileDownloadSession{
		ClientAddr:   addr,
		Filename:     filename,
		FileData:     fileData,
		TotalChunks:  totalChunks,
		WindowSize:   windowSize,
		WindowStart:  0,
		WindowEnd:    0,
		AckedChunks:  make(map[int]bool),
		LastActivity: time.Now(),
		RetryCount:   make(map[int]int),
		AckChan:      make(chan int, 100),
		Done:         make(chan bool, 1),
	}

	if totalChunks > 10000 {
		session.WindowSize = 64 // larger window for big files
	}

	// Register session
	downloadSessionsMutex.Lock()
	downloadSessions[sessionKey] = session
	downloadSessionsMutex.Unlock()

	// Cleanup on exit
	defer func() {
		downloadSessionsMutex.Lock()
		delete(downloadSessions, sessionKey)
		downloadSessionsMutex.Unlock()
		close(session.AckChan)
		close(session.Done)
	}()

	// Send file start packet
	startPayload := make([]byte, 4+len(filename))
	binary.BigEndian.PutUint32(startPayload[0:4], uint32(totalChunks))
	copy(startPayload[4:], []byte(filename))
	startPacket := append([]byte{CMD_FILE_START}, startPayload...)
	secureWriteToUDP(conn, startPacket, addr, &client)

	logChannel <- fmt.Sprintf("Starting sliding window file send '%s' to %s (%d chunks)\n", filename, addr.String(), totalChunks)

	// Start ACK processor goroutine
	go processAcks(session)

	// Main sliding window loop
	lastProgressTime := time.Now()
	for session.WindowStart < totalChunks {
		session.Mutex.Lock()

		// Only send packets to fill the window, don't blast them all at once.
		// This loop ensures that we've attempted to send every packet up to the
		// edge of our sliding window.
		for session.WindowEnd < totalChunks && (session.WindowEnd-session.WindowStart) < session.WindowSize {
			if !session.AckedChunks[session.WindowEnd] {
				// Only send if it's not already acknowledged.
				// We don't check the retry count here; the retransmit function will handle that.
				sendChunk(conn, session, session.WindowEnd, &client)
			}
			session.WindowEnd++
		}

		// Progress reporting remains the same
		progress := (session.WindowStart * 100) / totalChunks
		if time.Since(lastProgressTime) > 2*time.Second {
			logChannel <- fmt.Sprintf("Sending '%s': %d%% (%d/%d chunks)\n", filename, progress, session.WindowStart, totalChunks)
			lastProgressTime = time.Now()
		}

		allAcked := len(session.AckedChunks) >= totalChunks
		session.Mutex.Unlock()

		if allAcked {
			break
		}

		// Check for timeout and retransmit lost packets.
		// This is the core of our pacing. We send a bit, then check for ACKs/timeouts.
		if time.Since(session.LastActivity) > ackTimeout {
			retransmitTimeouts(conn, session, &client)
			session.Mutex.Lock()
			session.LastActivity = time.Now() // Reset activity timer after retransmit
			session.Mutex.Unlock()
		}

		// A short sleep to prevent the loop from busy-waiting and consuming 100% CPU.
		// This gives the network and other goroutines time to process.
		time.Sleep(10 * time.Millisecond)
	}

	logChannel <- fmt.Sprintf("Completed sliding window file send '%s' to %s\n", filename, addr.String())
}

func sendChunk(conn *net.UDPConn, session *FileDownloadSession, seqNum int, client *Client) {
	const chunkSize = 1024

	start := seqNum * chunkSize
	end := start + chunkSize
	if end > len(session.FileData) {
		end = len(session.FileData)
	}
	chunkData := session.FileData[start:end]

	// Create packet: [CMD_FILE_CHUNK][4B seqNum][data]
	packet := make([]byte, 1+4+len(chunkData))
	packet[0] = CMD_FILE_CHUNK
	binary.BigEndian.PutUint32(packet[1:5], uint32(seqNum))
	copy(packet[5:], chunkData)

	secureWriteToUDP(conn, packet, session.ClientAddr, client)
	session.RetryCount[seqNum]++
}

func processAcks(session *FileDownloadSession) {
	timeout := time.NewTimer(30 * time.Second) // Overall timeout
	defer timeout.Stop()

	for {
		select {
		case seqNum := <-session.AckChan:
			//fmt.Printf("<- [ACK] Received for chunk #%d for '%s'\n", seqNum, session.Filename)
			session.Mutex.Lock()
			if seqNum >= 0 && seqNum < session.TotalChunks {
				session.AckedChunks[seqNum] = true
				session.LastActivity = time.Now()

				// Reset timeout for active transfers
				timeout.Reset(30 * time.Second)
			}

			// Slide the window forward!
			// As long as the chunk at the start of the window is acked,
			// we can advance the window.
			for session.AckedChunks[session.WindowStart] {
				session.WindowStart++
			}
			// Check if complete
			if session.WindowStart >= session.TotalChunks {
				session.Mutex.Unlock()
				return
			}
			session.Mutex.Unlock()

		case <-timeout.C:
			// Overall timeout - check if we should exit
			session.Mutex.Lock()
			allDone := session.WindowStart >= session.TotalChunks
			session.Mutex.Unlock()

			if allDone {
				return
			}

			// Reset for continued operation
			timeout.Reset(30 * time.Second)
		}
	}
}

func retransmitTimeouts(conn *net.UDPConn, session *FileDownloadSession, client *Client) {
	session.Mutex.Lock()
	defer session.Mutex.Unlock()

	retransmitCount := 0
	for i := session.WindowStart; i < session.WindowEnd && i < session.TotalChunks; i++ {
		if !session.AckedChunks[i] && session.RetryCount[i] < 3 {
			sendChunk(conn, session, i, client)
			retransmitCount++
		}
	}

	if retransmitCount > 0 {
		logChannel <- fmt.Sprintf("Retransmitted %d chunks for %s\n", retransmitCount, session.Filename)
	}
}

// This function runs forever, cleaning up clients that have timed out.
func cleanupDeadClients(conn *net.UDPConn) {
	defer wg.Done()
	const timeout = 60 * time.Second

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownChan:
			return
		case <-ticker.C:
			clientsMutex.Lock()
			for addrStr, client := range clients {
				if time.Since(client.LastHeartbeat) > timeout {
					// ... existing cleanup logic stays the same ...
					if client.Username != "" {
						disconnectMsg := fmt.Sprintf("[Server]: User '%s' has disconnected or timed out.", client.Username)
						logChannel <- fmt.Sprintf("Client %s (%s) timed out. Removing.\n", client.Username, addrStr)

						for otherAddr, otherClient := range clients {
							if otherAddr != addrStr && otherClient.IsConnected {
								secureWriteToUDP(conn, []byte(disconnectMsg), otherClient.Addr, &otherClient)
								logChannel <- fmt.Sprintf("%s", disconnectMsg)
							}
						}
					} else {
						logChannel <- fmt.Sprintf("Client %s timed out. Removing.\n", addrStr)
					}
					delete(clients, addrStr)
				}
			}
			clientsMutex.Unlock()
		}
	}
}

func cleanupDownloadSessions() {
	defer wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownChan:
			return
		case <-ticker.C:
			downloadSessionsMutex.Lock()
			for sessionKey, session := range downloadSessions {
				if time.Since(session.LastActivity) > 2*time.Minute {
					logChannel <- fmt.Sprintf("Cleaning up stale download session: %s\n", sessionKey)
					close(session.AckChan)
					close(session.Done)
					delete(downloadSessions, sessionKey)
				}
			}
			downloadSessionsMutex.Unlock()
		}
	}
}

func assembleFile(transfer *FileTransfer) {
	// Create a directory for uploads if it doesn't exist
	_ = os.Mkdir("uploads", 0755)
	filePath := fmt.Sprintf("uploads/%s", transfer.Filename)

	// Create the destination file
	file, err := os.Create(filePath)
	if err != nil {
		logChannel <- fmt.Sprintf("Error creating file %s: %v\n", filePath, err)
		return
	}
	defer file.Close()

	// Write chunks in the correct order
	for i := uint32(0); i < transfer.TotalChunks; i++ {
		chunk, ok := transfer.ReceivedChunks[i]
		if !ok {
			logChannel <- fmt.Sprintf("Error: Missing chunk #%d for file %s. Aborting assembly.\n", i, transfer.Filename)
			// In a real-world scenario, you might request the missing chunk again.
			// For now, we'll just abort.
			file.Close()
			os.Remove(filePath) // Clean up the partial file
			return
		}
		_, err := file.Write(chunk)
		if err != nil {
			logChannel <- fmt.Sprintf("Error writing chunk #%d to file %s: %v\n", i, transfer.Filename, err)
			return
		}
	}

	logChannel <- fmt.Sprintf("✅ Successfully assembled and saved file: %s\n", filePath)
}

func resendMissingChunks(conn *net.UDPConn, addr *net.UDPAddr, filename string, missingChunksPayload []byte) {
	const chunkSize = 1024
	filePath := "./uploads/" + filename
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		// Can't do much if the file is gone, so we just log and exit.
		logChannel <- fmt.Sprintf("Could not re-read file %s for re-sending chunks.\n", filename)
		return
	}

	// Get client info for encryption
	clientsMutex.Lock()
	client, exists := clients[addr.String()]
	clientsMutex.Unlock()

	if !exists {
		logChannel <- fmt.Sprintf("Client not found for chunk resend: %s\n", addr.String())
		return
	}

	// The payload contains a list of 4-byte sequence numbers
	for i := 0; i < len(missingChunksPayload); i += 4 {
		if i+4 > len(missingChunksPayload) {
			break
		}
		seqNum := binary.BigEndian.Uint32(missingChunksPayload[i : i+4])

		start := int(seqNum) * chunkSize
		end := start + chunkSize
		if start > len(fileData) {
			continue // Invalid sequence number requested
		}
		if end > len(fileData) {
			end = len(fileData)
		}
		chunkData := fileData[start:end]

		// Re-send the chunk packet (NOW ENCRYPTED)
		packet := make([]byte, 1+4+len(chunkData))
		packet[0] = CMD_FILE_CHUNK
		binary.BigEndian.PutUint32(packet[1:5], seqNum)
		copy(packet[5:], chunkData)

		secureWriteToUDP(conn, packet, addr, &client) // NOW ENCRYPTED
		time.Sleep(5 * time.Millisecond)              // Small delay for the os
	}
}

// checks if username already exists
func isUsernameTaken(username string, excludeAddr string) bool {
	for addrStr, client := range clients {
		if addrStr != excludeAddr && client.IsConnected && client.Username == username {
			return true
		}
	}
	return false
}

func getUsers() string {
	var result string
	for _, client := range clients {
		if client.IsConnected {
			result += client.Username + "\n"
		}
	}

	return result
}

func trimTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s[:len(s)-1]
	}
	return s
}

// addToHistory adds a message to the broadcast history
func addToHistory(username, message string) {
	historyMutex.Lock()
	defer historyMutex.Unlock()

	historyMsg := HistoryMessage{
		Timestamp: time.Now(),
		Username:  username,
		Message:   message,
	}

	// Add to the end
	messageHistory = append(messageHistory, historyMsg)

	// Remove oldest if we exceed max size
	if len(messageHistory) > MAX_HISTORY_SIZE {
		messageHistory = messageHistory[1:] // Remove first element
	}
}

// getHistoryForNewUser returns formatted history for new users
func getHistoryForNewUser() string {
	historyMutex.Lock()
	defer historyMutex.Unlock()

	if len(messageHistory) == 0 {
		return ""
	}

	var historyLines []string
	historyLines = append(historyLines, "--- Recent Messages ---")

	for _, msg := range messageHistory {
		timeStr := msg.Timestamp.Format("15:04:05")
		formatted := fmt.Sprintf("[%s] %s: %s", timeStr, msg.Username, msg.Message)
		historyLines = append(historyLines, formatted)
	}

	historyLines = append(historyLines, "--- End History ---")
	return strings.Join(historyLines, "\n")
}

func sendServerHeartbeats(conn *net.UDPConn) {
	defer wg.Done()
	//send heartebeat every 15 seconds
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownChan:
			return
		case <-ticker.C:
			clientsMutex.Lock()
			clientsCopy := make(map[string]Client)
			for k, v := range clients {
				clientsCopy[k] = v
			}
			clientsMutex.Unlock()

			for _, client := range clientsCopy {
				if client.IsConnected {
					secureWriteToUDP(conn, []byte{CMD_SERVER_HEARTBEAT}, client.Addr, &client)
				}
			}
		}
	}
}

func secureWriteToUDP(conn *net.UDPConn, data []byte, addr *net.UDPAddr, client *Client) (int, error) {
	if client != nil && client.IsEncrypted && client.EncMgr != nil && client.EncMgr.IsReady() {
		encrypted, err := client.EncMgr.Encrypt(data)
		if err != nil {
			logChannel <- fmt.Sprintf("Encryption failed for %s: %v\n", addr, err)
			return conn.WriteToUDP(data, addr) // Fallback to unencrypted
		}
		return conn.WriteToUDP(encrypted, addr)
	}
	return conn.WriteToUDP(data, addr)
}

func broadcastAnnouncement(conn *net.UDPConn, message string) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	announcementPacket := append([]byte{CMD_SERVER_ANNOUNCEMENT}, []byte(message)...)

	for _, client := range clients {
		if client.IsConnected {
			// Use the existing secure write function to handle encryption automatically
			secureWriteToUDP(conn, announcementPacket, client.Addr, &client)
		}
	}
}

func startREPL(conn *net.UDPConn) {
	defer wg.Done()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("GUFS-Admin> ")

	for {
		select {
		case <-replShutdown:
			return
		default:
		}

		text, err := reader.ReadString('\n')
		if err != nil {
			if err.Error() == "EOF" {
				logChannel <- "REPL: EOF received, shutting down...\n"
				gracefulShutdown()
				return
			}
			logChannel <- fmt.Sprintf("REPL: Error reading input: %v\n", err)
			continue
		}

		text = strings.TrimSpace(text)
		if text == "" {
			fmt.Print("GUFS-Admin> ")
			continue
		}

		parts := strings.Fields(text)
		command := strings.ToLower(parts[0])
		args := parts[1:]

		// Execute command and handle prompt afterwards
		executeREPLCommand(conn, command, args)

		// Give log messages time to print, then show prompt
		time.Sleep(100 * time.Millisecond)
		fmt.Print("GUFS-Admin> ")
	}
}

func executeREPLCommand(conn *net.UDPConn, command string, args []string) {
	switch command {
	case "announce":
		if len(args) > 0 {
			message := strings.Join(args, " ")
			broadcastAnnouncement(conn, message)
			logChannel <- fmt.Sprintf("Announcement sent: %s\n", message)
		} else {
			logChannel <- "Usage: announce <message>\n"
		}

	case "status":
		showServerStatus()

	case "clients", "list":
		showConnectedClients()

	case "kick":
		if len(args) > 0 {
			kickClient(conn, args[0])
		} else {
			logChannel <- "Usage: kick <username>\n"
		}

	case "stats":
		showServerStats()

	case "files":
		showUploadedFiles()

	case "db":
		if len(args) > 0 {
			handleDBCommand(args)
		} else {
			logChannel <- "Usage: db <list|get|set|delete> [key] [value]\n"
		}

	case "history":
		showMessageHistory()

	case "clearhistory":
		clearMessageHistory()

	case "help":
		showREPLHelp()

	case "quit", "exit":
		logChannel <- "Server shutting down...\n"
		gracefulShutdown()

	default:
		logChannel <- fmt.Sprintf("Unknown command: %s (type 'help' for available commands)\n", command)
	}
}

func showServerStatus() {
	uptime := time.Since(serverStartTime).Round(time.Second)

	clientsMutex.Lock()
	connectedCount := 0
	for _, client := range clients {
		if client.IsConnected {
			connectedCount++
		}
	}
	totalClients := len(clients)
	clientsMutex.Unlock()

	dbMutex.Lock()
	dbSize := len(database)
	dbMutex.Unlock()

	transfersMutex.Lock()
	activeTransferCount := len(activeTransfers)
	transfersMutex.Unlock()

	downloadSessionsMutex.Lock()
	downloadSessionCount := len(downloadSessions)
	downloadSessionsMutex.Unlock()

	logChannel <- fmt.Sprintf("=== Server Status ===\n")
	logChannel <- fmt.Sprintf("Uptime: %s\n", uptime)
	logChannel <- fmt.Sprintf("Connected clients: %d/%d\n", connectedCount, totalClients)
	logChannel <- fmt.Sprintf("Database entries: %d/%d\n", dbSize, DB_MAX_SIZE)
	logChannel <- fmt.Sprintf("Active transfers: %d\n", activeTransferCount)
	logChannel <- fmt.Sprintf("Download sessions: %d\n", downloadSessionCount)
}

func showConnectedClients() {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	logChannel <- "=== Connected Clients ===\n"
	if len(clients) == 0 {
		logChannel <- "No clients connected\n"
		return
	}

	for addr, client := range clients {
		if client.IsConnected {
			username := client.Username
			if username == "" {
				username = "<no username>"
			}
			lastSeen := time.Since(client.LastHeartbeat).Round(time.Second)
			encryption := "No"
			if client.IsEncrypted {
				encryption = "Yes"
			}
			logChannel <- fmt.Sprintf("• %s (%s) - Last heartbeat: %s ago - Encrypted: %s\n",
				username, addr, lastSeen, encryption)
		}
	}
}

func kickClient(conn *net.UDPConn, username string) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	for addr, client := range clients {
		if client.IsConnected && client.Username == username {
			// Send disconnect message to client
			secureWriteToUDP(conn, []byte{CMD_DISCONNECT}, client.Addr, &client)

			// Remove from clients map
			delete(clients, addr)

			// Notify other clients
			kickMsg := fmt.Sprintf("[Server]: %s was kicked by admin.", username)
			for _, otherClient := range clients {
				if otherClient.IsConnected {
					secureWriteToUDP(conn, []byte(kickMsg), otherClient.Addr, &otherClient)
				}
			}

			logChannel <- fmt.Sprintf("Kicked user: %s (%s)\n", username, addr)
			return
		}
	}
	logChannel <- fmt.Sprintf("User not found: %s\n", username)
}

func showServerStats() {
	// Calculate file storage usage
	files, _ := os.ReadDir("./uploads")
	var totalSize int64
	fileCount := 0

	for _, file := range files {
		if !file.IsDir() {
			info, err := file.Info()
			if err == nil {
				totalSize += info.Size()
				fileCount++
			}
		}
	}

	logChannel <- fmt.Sprintf("=== Server Statistics ===\n")
	logChannel <- fmt.Sprintf("Files stored: %d\n", fileCount)
	logChannel <- fmt.Sprintf("Storage used: %.2f MB\n", float64(totalSize)/1024/1024)
	logChannel <- fmt.Sprintf("Server version: %s\n", SERVER_VERSION)
}

func showUploadedFiles() {
	files, err := os.ReadDir("./uploads")
	if err != nil {
		logChannel <- fmt.Sprintf("Error reading uploads directory: %v\n", err)
		return
	}

	logChannel <- "=== Uploaded Files ===\n"
	if len(files) == 0 {
		logChannel <- "No files uploaded\n"
		return
	}

	for _, file := range files {
		if !file.IsDir() {
			info, err := file.Info()
			if err == nil {
				size := float64(info.Size()) / 1024 // KB
				logChannel <- fmt.Sprintf("• %s (%.1f KB) - %s\n",
					file.Name(), size, info.ModTime().Format("2006-01-02 15:04:05"))
			}
		}
	}
}

func handleDBCommand(args []string) {
	if len(args) == 0 {
		return
	}

	subcommand := strings.ToLower(args[0])
	switch subcommand {
	case "list":
		dbMutex.Lock()
		if len(database) == 0 {
			logChannel <- "Database is empty\n"
		} else {
			logChannel <- "=== Database Keys ===\n"
			for key := range database {
				logChannel <- fmt.Sprintf("• %s", key)
			}
		}
		dbMutex.Unlock()

	case "get":
		if len(args) < 2 {
			logChannel <- "Usage: db get <key>\n"
			return
		}
		key := args[1]
		dbMutex.Lock()
		value, exists := database[key]
		dbMutex.Unlock()

		if exists {
			logChannel <- fmt.Sprintf("Key '%s': %s\n", key, string(value))
		} else {
			logChannel <- fmt.Sprintf("Key '%s' not found\n", key)
		}

	case "delete", "del":
		if len(args) < 2 {
			logChannel <- "Usage: db delete <key>\n"
			return
		}
		key := args[1]
		dbMutex.Lock()
		_, exists := database[key]
		if exists {
			delete(database, key)
			logChannel <- fmt.Sprintf("Deleted key: %s\n", key)
		} else {
			logChannel <- fmt.Sprintf("Key '%s' not found\n", key)
		}
		dbMutex.Unlock()

	default:
		logChannel <- "Usage: db <list|get|delete> [key]\n"
	}
}

func showREPLHelp() {
	logChannel <- "=== Admin Commands ===\n"
	logChannel <- "announce <message>  - Send announcement to all clients\n"
	logChannel <- "status             - Show server status\n"
	logChannel <- "clients, list      - Show connected clients\n"
	logChannel <- "kick <username>    - Disconnect a user\n"
	logChannel <- "stats             - Show server statistics\n"
	logChannel <- "files             - Show uploaded files\n"
	logChannel <- "history			 - Display message history\n"
	logChannel <- "clearhistory		 - Clear message history\n"
	logChannel <- "db <cmd> [args]   - Database operations (list|get|delete)\n"
	logChannel <- "help              - Show this help\n"
	logChannel <- "quit, exit        - Shutdown server\n"
}

func showMessageHistory() {
	historyMutex.Lock()
	defer historyMutex.Unlock()

	if len(messageHistory) == 0 {
		logChannel <- "No message history available\n"
		return
	}

	logChannel <- "=== Message History ===\n"
	for i, msg := range messageHistory {
		timeStr := msg.Timestamp.Format("15:04:05")
		logChannel <- fmt.Sprintf("%d. [%s] %s: %s\n", i+1, timeStr, msg.Username, msg.Message)
	}
}

func clearMessageHistory() {
	historyMutex.Lock()
	messageHistory = nil
	historyMutex.Unlock()
	logChannel <- "Message history cleared\n"
}

func gracefulShutdown() {
	// Use sync.Once to ensure channels are only closed once
	shutdownOnce.Do(func() {
		close(shutdownChan)
	})

	replShutdownOnce.Do(func() {
		close(replShutdown)
	})

	// Give goroutines time to cleanup
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logChannel <- "Graceful shutdown complete\n"
	case <-time.After(5 * time.Second):
		logChannel <- "Shutdown timeout reached, forcing exit\n"
	}

	os.Exit(0)
}
