// GUFS: Go UDP Fun Server
// Author: derrybm/silencer0151
// Version: 0.8.0
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
	- Implement Sliding Window:
		Current Method (Stop-and-Wait): Send chunk 0 -> Wait for ACK 0 -> Send chunk 1 -> Wait for ACK 1...
		New Method (Sliding Window): Send chunks 0, 1, 2, 3, 4, 5 all at once. As ACKs for 0, 1, 2 come back, send chunks 6, 7, 8.

	- File deletion /delete filename
	- Message history

	- encryption
*/

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Define command constants
const (
	SERVER_VERSION = "GUFS v0.8.0"

	// General Commands
	CMD_BROADCAST    byte = 0x02
	CMD_STATUS       byte = 0x03
	CMD_PROCESS_DATA byte = 0x04
	CMD_TIME         byte = 0x05
	CMD_SET_USERNAME byte = 0x06
	CMD_ECHO         byte = 0x07
	CMD_LIST_USERS   byte = 0x08
	CMD_PRIVATE_MSG  byte = 0x09

	// Connection Protocol
	CMD_CONNECT_SYN     byte = 0x10
	CMD_CONNECT_SYN_ACK byte = 0x11
	CMD_CONNECT_ACK     byte = 0x12
	CMD_HEARTBEAT       byte = 0x13
	CMD_DISCONNECT      byte = 0x14
	CMD_PING            byte = 0x15
	CMD_PONG            byte = 0x16

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
}

var activeTransfers = make(map[string]*FileTransfer) // key: transfer ID
var transfersMutex = &sync.Mutex{}

func main() {
	// Handle CLI flags
	ip := flag.String("ip", "127.0.0.1", "The IP address to bind the server to.")
	port := flag.String("port", "8080", "The port to listen on.")
	flag.Parse()

	addrStr := *ip + ":" + *port
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		fmt.Println("Error resolving address:", err)
		os.Exit(1)
	}

	// create uploads directory proactively
	_ = os.Mkdir("uploads", 0755)

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("UDP server listening on %s\n", conn.LocalAddr().String())

	// Start the client cleanup goroutine
	go cleanupDeadClients(conn)

	buffer := make([]byte, 8192)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from UDP:", err)
			continue
		}
		data := make([]byte, n)
		copy(data, buffer[:n])
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

[Commands (Byte | Name | Payload)]
0x06 | SET_USERNAME 	| string(username)
0x02 | BROADCAST    	| string(message)
0x07 | ECHO         	| []byte(any data)
0x03 | STATUS       	| (no payload)
0x05 | TIME         	| (no payload)
0x04 | PROCESS_DATA 	| string(any text to be reversed)
0x08 | CMD_LIST_USERS 	| []byte(usernames) 
0x09 | CMD_PRIVATE_MSG  | []byte(receiver'\n'message)
0x15 | CMD_PING         | (no payload) 
0x16 | CMD_PONG         | (no payload) 
0x30 | VERSION        	| (no payload)
0x31 | HELP           	| (no payload) - Returns REPL client help.

[Database]
0x20 | DB_STORE     | key=value
0x21 | DB_RETRIEVE  | key
0x22 | DB_LIST      | (no payload)

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
0x44 | FILE_LIST    | (no payload) - List available files

Notes:
- Chunk size: 1024 bytes
- Retry limit: 3 attempts per chunk
- Transfer timeout: 20 seconds
- Sequence numbers ensure correct assembly
`
}

func getHelpText() string {
	return `
--- GUFS Help (v0.8.0) ---
Usage: Type a message to broadcast, or use /<command> for special actions.
Example: /username Alice

[Connection]
/quit                  Disconnect from the server.

[Messaging]
/username <name>       Set your display name.
/echo <message>        Server repeats a message back to you.
/users				   Server sends list of connected client usernames.
/msg <username>	<message> Direct message user connected to the server.

[Server Info]
/help                  Show this help message.
/version               Get the server version.
/status                Get server uptime and client count.
/time                  Get the current server time.
/reverse <message>     Server reverses a string for you.
/ping				   Get ping from server.

[Key-Value Database]
/store <key=value>     Store a value in the database.
/retrieve <key>        Get a value from the database.
/list                  List all keys in the database.

[File Transfer]
/send <local_filepath> Upload a file to the server.
/get <filename>        Download a file from the server.
/listfiles             List all available files on the server.
`
}

func handlePacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	if len(data) == 0 {
		return
	}
	if string(data) == "help\n" {
		//conn.WriteToUDP([]byte(getHelpText()), addr)
		conn.WriteToUDP([]byte(getProtocolText()), addr)
		return
	}
	// For netcat users wanting protocol details
	if string(data) == "protocol\n" {
		conn.WriteToUDP([]byte(getProtocolText()), addr)
		return
	}

	command := data[0]
	payload := data[1:]
	addrStr := addr.String()

	// Allow connection commands to pass through
	isConnectCmd := command == CMD_CONNECT_SYN || command == CMD_CONNECT_ACK

	clientsMutex.Lock()
	client, isKnown := clients[addr.String()]
	clientsMutex.Unlock()

	// If the command is not a connection command and the client is not connected, reject it.
	if !isConnectCmd && (!isKnown || !client.IsConnected) {
		conn.WriteToUDP([]byte("The server did not understand your request, try 'protocol' for more information."), addr)

		fmt.Printf("Rejected command from unconnected client %s - '%s'\n", addr, string(data))
		return
	}

	// Route commands
	switch command {
	case CMD_PING:
		conn.WriteToUDP([]byte{CMD_PONG}, addr)
		fmt.Printf("Sent PONG to %s\n", client.Username)

	case CMD_TIME:
		serverTime := time.Now().Format(time.RFC3339)
		conn.WriteToUDP([]byte(serverTime), addr)

	case CMD_SET_USERNAME:
		username := strings.TrimSpace(string(payload))

		// Basic validation
		if username == "" {
			conn.WriteToUDP([]byte("Error: Username cannot be empty."), addr)
			return
		}

		if len(username) > 50 { // Add reasonable length limit
			conn.WriteToUDP([]byte("Error: Username too long (max 50 characters)."), addr)
			return
		}

		clientsMutex.Lock()
		defer clientsMutex.Unlock()

		// Check if username is already taken
		if isUsernameTaken(username, addrStr) {
			conn.WriteToUDP([]byte("Error: Username '"+username+"' is already taken. Please choose another."), addr)
			return
		}

		// Get current client and update username
		if client, ok := clients[addrStr]; ok {
			oldUsername := client.Username
			client.Username = username
			clients[addrStr] = client

			fmt.Printf("Set username for %s to '%s'\n", addr, username)
			conn.WriteToUDP([]byte("Username set successfully!"), addr)

			if oldUsername == "" {
				joinMsg := fmt.Sprintf("[Server]: Welcome, %s has joined!", username)
				// Broadcast the join message
				for clientAddr, otherClient := range clients {
					if clientAddr != addrStr && otherClient.IsConnected {
						conn.WriteToUDP([]byte(joinMsg), otherClient.Addr)
					}
				}
			} else if oldUsername != username {
				// If oldUsername was not empty and is different, it's a name change.
				changeMsg := fmt.Sprintf("[Server]: User '%s' changed their name to '%s'", oldUsername, username)
				// Broadcast the name change
				for clientAddr, otherClient := range clients {
					if clientAddr != addrStr && otherClient.IsConnected {
						conn.WriteToUDP([]byte(changeMsg), otherClient.Addr)
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
		conn.WriteToUDP([]byte(statusMsg), addr)

	case CMD_LIST_USERS:
		clientsMutex.Lock()
		defer clientsMutex.Unlock()

		userList := []byte(trimTrailingNewline(getUsers()))
		conn.WriteToUDP(userList, addr)

	case CMD_BROADCAST:
		clientsMutex.Lock()
		defer clientsMutex.Unlock()

		sender, ok := clients[addrStr]
		if !ok || sender.Username == "" {
			// if no username tell user to set one
			conn.WriteToUDP([]byte("Error: You must set a username before broadcasting!"), addr)
			return
		}

		messageToBroadcast := fmt.Sprintf("[%s]: %s", sender.Username, string(payload))
		fmt.Printf("Broadcasting from %s: %s\n", sender.Username, string(payload))

		for _, client := range clients {
			if client.Addr.String() == addrStr || !client.IsConnected {
				continue
			}

			conn.WriteToUDP([]byte(messageToBroadcast), client.Addr)
		}

	case CMD_PROCESS_DATA:
		// convert payload into slicve of runes for character handling
		runes := []rune(string(payload))

		// two pointer swap to reverse the slice
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}

		reversedPayload := []byte(string(runes))
		conn.WriteToUDP(reversedPayload, addr)

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
			conn.WriteToUDP([]byte("Error: You must have a username to send messages."), addr)
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
			conn.WriteToUDP([]byte(formattedMsg), receiverClient.Addr)

			// Send a confirmation back to the sender
			conn.WriteToUDP([]byte("Message sent."), addr)
		} else {
			// Send an error if the user was not found
			errorMsg := fmt.Sprintf("Error: User '%s' not found or is not connected.", receiverUsername)
			conn.WriteToUDP([]byte(errorMsg), addr)
		}

	case CMD_DB_STORE:
		// First, check if the client is valid. This only requires the clientMutex.
		clientsMutex.Lock()
		sender, ok := clients[addrStr]
		if !ok || sender.Username == "" {
			clientsMutex.Unlock() // Unlock before returning!
			conn.WriteToUDP([]byte("Error: You must set a username before storing values!"), addr)
			return
		}
		senderUsername := sender.Username // Copy the username
		clientsMutex.Unlock()             // Unlock immediately after check.

		// Now, handle the database logic, which uses the dbMutex.
		parts := bytes.SplitN(payload, []byte("="), 2)
		if len(parts) != 2 {
			conn.WriteToUDP([]byte("Error: Invalid format. Use key=value."), addr)
			return
		}
		key, value := string(parts[0]), string(parts[1])

		if len(value) > DB_MAX_VALUE_BYTES {
			msg := fmt.Sprintf("Error: Value size exceeds the limit of %d bytes.", DB_MAX_VALUE_BYTES)
			conn.WriteToUDP([]byte(msg), addr)
			return
		}

		dbMutex.Lock()
		_, keyExists := database[key]
		if !keyExists && len(database) >= DB_MAX_SIZE {
			dbMutex.Unlock() // Unlock before returning!
			conn.WriteToUDP([]byte("Error: Database is full."), addr)
			return
		}
		database[key] = []byte(value)
		dbMutex.Unlock() // Unlock immediately after DB operation.

		fmt.Printf("Stored key '%s' for client %s\n", key, addr)
		conn.WriteToUDP([]byte("Value stored successfully."), addr)

		// Broadcast that a value was set
		messageToBroadcast := fmt.Sprintf("[Server]: User [%s] has set a value for %s", senderUsername, key)
		clientsMutex.Lock()
		for _, client := range clients {
			if client.Addr.String() != addrStr && client.IsConnected {
				conn.WriteToUDP([]byte(messageToBroadcast), client.Addr)
			}
		}
		clientsMutex.Unlock()

	case CMD_DB_RETRIEVE:
		key := string(payload)

		dbMutex.Lock()
		value, ok := database[key]
		dbMutex.Unlock()

		if !ok {
			conn.WriteToUDP([]byte("Error: Key not found."), addr)
			return
		}

		conn.WriteToUDP(value, addr)

	case CMD_DB_LIST:
		dbMutex.Lock()

		if len(database) == 0 {
			dbMutex.Unlock()
			conn.WriteToUDP([]byte("Database is empty."), addr)
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
		conn.WriteToUDP([]byte(response), addr)

	case CMD_FILE_START:
		if len(payload) < 5 { // 4 bytes for chunk count + at least 1 for filename
			conn.WriteToUDP([]byte("Error: Malformed file transfer start packet."), addr)
			return
		}

		// Read the total number of chunks from the first 4 bytes of the payload
		totalChunks := binary.BigEndian.Uint32(payload[0:4])
		filename := string(payload[4:])

		// Create a unique ID for this transfer session
		transferID := fmt.Sprintf("%s-%s", addr.String(), filename)

		fmt.Printf("Initiating file transfer '%s' (%d chunks) for ID %s\n", filename, totalChunks, transferID)

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
		conn.WriteToUDP([]byte(transferID), addr)

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
		}

		// Check if the transfer is complete
		if uint32(len(transfer.ReceivedChunks)) == transfer.TotalChunks {
			fmt.Printf("Received all %d chunks for file '%s'. Assembling...\n", transfer.TotalChunks, transfer.Filename)
			go assembleFile(transfer)           // Assemble in a new goroutine to not block
			delete(activeTransfers, transferID) // Clean up the completed transfer
		}

		// Send ACK back to the client: [CMD_ACK][4 bytes for sequence_number]
		ackPacket := make([]byte, 5)
		ackPacket[0] = CMD_FILE_ACK
		binary.BigEndian.PutUint32(ackPacket[1:5], sequenceNumber)
		conn.WriteToUDP(ackPacket, addr)

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
			conn.WriteToUDP([]byte("Error: Could not read uploads directory."), addr)
			return
		}
		if len(files) == 0 {
			conn.WriteToUDP([]byte("No files available on server."), addr)
			return
		}
		var filenames []string
		for _, f := range files {
			if !f.IsDir() {
				filenames = append(filenames, f.Name())
			}
		}
		conn.WriteToUDP([]byte(strings.Join(filenames, "\n")), addr)

	case CMD_FILE_GET:
		filename := string(payload)
		go sendFileToClient(conn, addr, filename)

	case CMD_ECHO:
		conn.WriteToUDP(payload, addr)

	case CMD_VERSION:
		conn.WriteToUDP([]byte(SERVER_VERSION), addr)

	case CMD_HELP:
		conn.WriteToUDP([]byte(getHelpText()), addr)

	case CMD_CONNECT_SYN:
		addrStr := addr.String()
		fmt.Printf("Received SYN from %s, sending SYN-ACK\n", addrStr)

		// add client in a non-connected state
		clientsMutex.Lock()
		clients[addrStr] = Client{Addr: addr, IsConnected: false}
		clientsMutex.Unlock()

		//respond with SYNACK
		conn.WriteToUDP([]byte{CMD_CONNECT_SYN_ACK}, addr)

	case CMD_CONNECT_ACK:
		addrStr := addr.String()
		clientsMutex.Lock()
		//check if connection is already pending
		if client, ok := clients[addrStr]; ok && !client.IsConnected {
			client.IsConnected = true
			client.LastHeartbeat = time.Now() //start timer for heartbeat
			clients[addrStr] = client
			fmt.Printf("Received ACK from %s. Connection established.\n", addrStr)
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
		fmt.Printf("Client %s (%s) has disconnected.\n", disconnectedUsername, addrStr)

		// Prepare the broadcast message to notify other users.
		disconnectMsg := fmt.Sprintf("[Server]: %s has disconnected.", disconnectedUsername)

		// Loop through all *remaining* connected clients to notify them.
		for _, otherClient := range clients {
			// No need to check for the sender, as they've already been deleted.
			if otherClient.IsConnected {
				conn.WriteToUDP([]byte(disconnectMsg), otherClient.Addr)
			}
		}
		clientsMutex.Unlock()

	default:
		errMsg := fmt.Sprintf("Unknown command byte: 0x%x. Type 'help' for more information.", command)
		conn.WriteToUDP([]byte(errMsg), addr)
		fmt.Printf("received unknown packet from client: %s - 0x%x\n", addrStr, command)
	}
}

// In server.go

func sendFileToClient(conn *net.UDPConn, addr *net.UDPAddr, filename string) {
	const chunkSize = 1024
	filePath := "./uploads/" + filename
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("File not found for sending: %s\n", filePath)
		conn.WriteToUDP([]byte("Error: File not found on server."), addr)
		return
	}

	totalChunks := (len(fileData) + chunkSize - 1) / chunkSize

	// --- New Sliding Window Variables ---
	windowSize := 32
	windowStart := 0
	windowEnd := 0

	//ackedChunks := make(map[int]bool)
	//var ackedMutex sync.Mutex
	//ackChan := make(chan int, windowSize) // Channel for this specific download

	// Announce the file transfer to the client
	startPayload := make([]byte, 4+len(filename))
	binary.BigEndian.PutUint32(startPayload[0:4], uint32(totalChunks))
	copy(startPayload[4:], []byte(filename))
	startPacket := append([]byte{CMD_FILE_START}, startPayload...)
	conn.WriteToUDP(startPacket, addr)

	fmt.Printf("Starting file send '%s' to %s\n", filename, addr.String())

	// This goroutine's job is to listen for incoming packets from this specific client
	// and filter out the ACKs for this download.
	// NOTE: This is a simplification. A truly robust server would have a central
	// demultiplexer to route incoming packets instead of creating a new listener.
	go func() {
		// This is a conceptual placeholder. The main `handlePacket` loop
		// needs to be aware of this channel to route ACKs here.
		// For now, we'll simulate receiving ACKs.
	}()

	// --- New Sliding Window Send Loop ---
	for windowStart < totalChunks {
		// Send packets in the window
		for windowEnd < totalChunks && windowEnd-windowStart < windowSize {
			start := windowEnd * chunkSize
			end := start + chunkSize
			if end > len(fileData) {
				end = len(fileData)
			}
			chunkData := fileData[start:end]

			// Packet: [CMD_CHUNK][SeqNum][Data]
			packet := make([]byte, 1+4+len(chunkData))
			packet[0] = CMD_FILE_CHUNK
			binary.BigEndian.PutUint32(packet[1:5], uint32(windowEnd))
			copy(packet[5:], chunkData)

			conn.WriteToUDP(packet, addr)
			windowEnd++
		}

		// This is where the server would wait on its ackChan.
		// Since we can't easily create a new listener here, we will just
		// add a small delay to simulate the flow. The real performance gain
		// comes from the client-side upload window.
		time.Sleep(50 * time.Millisecond)

		// In a full implementation, we would slide the window like this:
		// ackedMutex.Lock()
		// for ackedChunks[windowStart] {
		// 	windowStart++
		// }
		// ackedMutex.Unlock()

		// Simplified slide for this example:
		windowStart = windowEnd
	}

	fmt.Printf("Finished sending file '%s' to %s\n", filename, addr.String())
}

// This function runs forever, cleaning up clients that have timed out.
func cleanupDeadClients(conn *net.UDPConn) {
	const timeout = 60 * time.Second
	for {
		time.Sleep(30 * time.Second)

		clientsMutex.Lock()
		for addrStr, client := range clients {
			if time.Since(client.LastHeartbeat) > timeout {
				// Announce user disconnect if they had a username
				if client.Username != "" {
					disconnectMsg := fmt.Sprintf("[Server]: User '%s' has disconnected or timed out.", client.Username)
					fmt.Printf("Client %s (%s) timed out. Removing.\n", client.Username, addrStr)

					// Notify other clients
					for otherAddr, otherClient := range clients {
						if otherAddr != addrStr && otherClient.IsConnected {
							conn.WriteToUDP([]byte(disconnectMsg), otherClient.Addr)
							fmt.Printf("%s", disconnectMsg)
						}
					}
				} else {
					fmt.Printf("Client %s timed out. Removing.\n", addrStr)
				}
				delete(clients, addrStr)
			}
		}
		clientsMutex.Unlock()
	}
}

func assembleFile(transfer *FileTransfer) {
	// Create a directory for uploads if it doesn't exist
	_ = os.Mkdir("uploads", 0755)
	filePath := fmt.Sprintf("uploads/%s", transfer.Filename)

	// Create the destination file
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Printf("Error creating file %s: %v\n", filePath, err)
		return
	}
	defer file.Close()

	// Write chunks in the correct order
	for i := uint32(0); i < transfer.TotalChunks; i++ {
		chunk, ok := transfer.ReceivedChunks[i]
		if !ok {
			fmt.Printf("Error: Missing chunk #%d for file %s. Aborting assembly.\n", i, transfer.Filename)
			// In a real-world scenario, you might request the missing chunk again.
			// For now, we'll just abort.
			file.Close()
			os.Remove(filePath) // Clean up the partial file
			return
		}
		_, err := file.Write(chunk)
		if err != nil {
			fmt.Printf("Error writing chunk #%d to file %s: %v\n", i, transfer.Filename, err)
			return
		}
	}

	fmt.Printf("✅ Successfully assembled and saved file: %s\n", filePath)
}

func resendMissingChunks(conn *net.UDPConn, addr *net.UDPAddr, filename string, missingChunksPayload []byte) {
	const chunkSize = 1024
	filePath := "./uploads/" + filename
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		// Can't do much if the file is gone, so we just log and exit.
		fmt.Printf("Could not re-read file %s for re-sending chunks.\n", filename)
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

		// Re-send the chunk packet
		packet := make([]byte, 1+4+len(chunkData))
		packet[0] = CMD_FILE_CHUNK
		binary.BigEndian.PutUint32(packet[1:5], seqNum)
		copy(packet[5:], chunkData)

		conn.WriteToUDP(packet, addr)
		time.Sleep(5 * time.Millisecond) // Small delay for the os
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
