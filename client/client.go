// GUFS Client: Go UDP Fun Server - Interactive REPL Client
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"gufs/internal/security"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
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
	
	// Fun
	CMD_ROLL_DICE		byte = 0x23

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

	// New Encryption Handshake Commands
	CMD_KEY_EXCHANGE byte = 0x17 // Exchange public keys
	CMD_KEY_CONFIRM  byte = 0x18 // Confirm encryption is ready

	// Special marker to identify encrypted packets
	ENCRYPTED_MARKER byte = 0xFF // Prepended to encrypted data
)

const (
	CHUNK_SIZE = 1024
)

// Client holds the state for a single client connection.
type Client struct {
	conn               net.Conn
	username           string
	serverAddr         string
	isConnected        bool
	quitChan           chan struct{}
	ackChan            chan uint32 // Channel for file upload ACKs
	responseChan       chan []byte // Channel for direct command responses
	transferLock       sync.Mutex  // Prevents multiple file transfers at once
	responseLock       sync.Mutex  // Protects the responseChan
	lastServerActivity time.Time
	activeDownloads    map[string]*FileDownload
	downloadMutex      sync.Mutex
	encMgr             *security.EncryptionManager
	isEncrypted        bool
}

// file download hold the state for an incoming file
type FileDownload struct {
	TotalChunks uint32
	Chunks      chan []byte // A channel to stream chunk data to the receiver
}

func generateUsername() string {
	//rand.Seed(time.Now().UnixNano())
	randomNumber := rand.Intn(10000)
	return fmt.Sprintf("user%04d", randomNumber)
}

func main() {
	serverAddr := flag.String("server", "127.0.0.1:8080", "Address of the GUFS server.")
	username := flag.String("username", generateUsername(), "Your username for the session.")
	flag.Parse()

	client := &Client{
		serverAddr:      *serverAddr,
		username:        *username,
		quitChan:        make(chan struct{}),
		ackChan:         make(chan uint32, 100),
		activeDownloads: make(map[string]*FileDownload),
	}

	err := client.Connect()
	if err != nil {
		fmt.Printf("Error: Could not connect to server at %s. %v\n", *serverAddr, err)
		os.Exit(1)
	}
	defer client.conn.Close()

	client.sendCommand(CMD_SET_USERNAME, []byte(client.username))
	client.Run()
}

// Connect establishes a connection with the server using the 3-way handshake.
func (c *Client) Connect() error {
	var err error
	c.conn, err = net.Dial("udp", c.serverAddr)
	if err != nil {
		return err
	}

	// Initialize encryption manager
	c.encMgr, err = security.NewEncryptionManager()
	if err != nil {
		return fmt.Errorf("failed to initialize encryption: %w", err)
	}

	// Existing handshake
	_, err = c.conn.Write([]byte{CMD_CONNECT_SYN})
	if err != nil {
		return err
	}

	buffer := make([]byte, 1024)
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.conn.Read(buffer)
	if err != nil || n == 0 || buffer[0] != CMD_CONNECT_SYN_ACK {
		return fmt.Errorf("did not receive SYN-ACK from server")
	}

	_, err = c.conn.Write([]byte{CMD_CONNECT_ACK})
	if err != nil {
		return err
	}

	// Key exchange after successful handshake
	err = c.performKeyExchange()
	if err != nil {
		fmt.Printf("Warning: Encryption setup failed: %v. Continuing without encryption.\n", err)
	} else {
		c.isEncrypted = true
		fmt.Println("🔒 Secure connection established")
	}
	c.lastServerActivity = time.Now()
	c.isConnected = true
	fmt.Printf("Successfully connected to %s as '%s'.\n", c.serverAddr, c.username)
	return nil
}

func (c *Client) performKeyExchange() error {
	// Send our public key
	ourPublicKey := c.encMgr.GetPublicKey()
	keyExchangePacket := append([]byte{CMD_KEY_EXCHANGE}, ourPublicKey...)
	_, err := c.conn.Write(keyExchangePacket)
	if err != nil {
		return err
	}

	// Receive server's public key
	buffer := make([]byte, 1024)
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.conn.Read(buffer)
	if err != nil || n < 2 || buffer[0] != CMD_KEY_EXCHANGE {
		return fmt.Errorf("invalid key exchange response")
	}
	c.conn.SetReadDeadline(time.Time{})

	// Establish shared secret
	serverPublicKey := buffer[1:n]
	err = c.encMgr.SetSharedSecret(serverPublicKey)
	if err != nil {
		return err
	}

	// Confirm encryption is ready
	_, err = c.conn.Write([]byte{CMD_KEY_CONFIRM})
	if err != nil {
		return err
	}

	// Wait for server confirmation
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = c.conn.Read(buffer)
	if err != nil || n == 0 || buffer[0] != CMD_KEY_CONFIRM {
		return fmt.Errorf("server did not confirm encryption")
	}
	c.conn.SetReadDeadline(time.Time{})

	return nil
}

// Run starts the main client goroutines for handling I/O and heartbeats.
func (c *Client) Run() {
	go c.handleServerMessages()
	go c.handleUserInput()
	go c.handleHeartbeats()
	go c.checkServerLiveness()

	<-c.quitChan
	fmt.Println("Disconnecting from server...")
}

// handleServerMessages runs in a loop, processing all incoming data from the server.
func (c *Client) handleServerMessages() {
	buffer := make([]byte, 8192)
	for {
		n, err := c.conn.Read(buffer)
		c.lastServerActivity = time.Now()

		if err != nil {
			select {
			case <-c.quitChan: // Expected closure
				return
			default: // Unexpected closure
				fmt.Println("\nConnection to server lost.")
				close(c.quitChan)
				return
			}
		}

		data := make([]byte, n)
		copy(data, buffer[:n]) // Make a copy to avoid data races

		if len(data) == 0 {
			continue
		}

		// Decrypt if encryption is enabled
		if c.isEncrypted && c.encMgr != nil && c.encMgr.IsReady() {
			decrypted, err := c.encMgr.Decrypt(data)
			if err != nil {
				// Might be unencrypted packet, continue with original
				fmt.Printf("Warning: Could not decrypt packet: %v\n", err)
			} else {
				data = decrypted
			}
		}

		command := data[0]
		payload := data[1:]

		// Check if there's an active listener for a direct response
		c.responseLock.Lock()
		isWaitingForResponse := c.responseChan != nil
		c.responseLock.Unlock()

		// Route specific protocol messages
		switch command {
		case CMD_FILE_ACK:
			if len(payload) == 4 { // Corrected length check
				seqNum := binary.BigEndian.Uint32(payload)
				c.ackChan <- seqNum
			}
		case CMD_FILE_START:
			go c.receiveFile(payload)

		case CMD_FILE_CHUNK:
			// This is a chunk for an incoming file. Route it.
			if len(payload) >= 5 { // 4 for seq num + at least 1 for data
				// We need to figure out which file this belongs to.
				// A more robust protocol would include a filename or transfer ID in the chunk packet.
				// For now, we assume only one download can happen at a time.
				c.downloadMutex.Lock()
				for _, download := range c.activeDownloads {
					// Send the full chunk payload (seq num + data)
					download.Chunks <- payload
					break // Exit after sending to the first active download
				}
				c.downloadMutex.Unlock()
			}
		case CMD_SERVER_ANNOUNCEMENT:
			fmt.Printf("\r[SERVER ANNOUNCEMENT]: %s\n> ", string(payload))
		case CMD_SERVER_HEARTBEAT:
			// This is the server's liveness check. We've already updated the
			// lastServerActivity timestamp just by receiving the packet.
			// We do nothing here to keep the console clean for the user.
			break
			//Handle disconnect command from server (kick)
		case CMD_DISCONNECT:
			fmt.Printf("\r❌ You have been disconnected from the server.\n")
			fmt.Printf("Reason: You were kicked by an administrator.\n")
			close(c.quitChan)
			return

		default:
			// If a function is waiting for a direct response, send it there.
			// Otherwise, print it as a general message.
			if isWaitingForResponse {
				c.responseLock.Lock()
				if c.responseChan != nil {
					c.responseChan <- data
				}
				c.responseLock.Unlock()
			} else {
				fmt.Printf("\r%s\n> ", string(data))
			}
		}
	}
}

// handleUserInput reads from stdin and sends commands or messages to the server.
func (c *Client) handleUserInput() {
	reader := bufio.NewReader(os.Stdin)

	// Wait a moment for initial server responses to be processed
	time.Sleep(200 * time.Millisecond)
	fmt.Print("> ")

	for {
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" {
			fmt.Print("> ")
			continue
		}

		if strings.HasPrefix(text, "/") {
			parts := strings.Fields(text)
			command := parts[0]
			args := parts[1:]

			switch command {
			case "/ping":
				start := time.Now()
				_, err := c.sendAndReceive(CMD_PING, nil, 5*time.Second)
				if err != nil {
					fmt.Printf("Ping failed: %v\n", err)
				} else {
					elapsed := time.Since(start)
					fmt.Printf("Pong received in %s\n", elapsed)
				}
			case "/quit":
				c.sendCommand(CMD_DISCONNECT, nil)
				time.Sleep(50 * time.Millisecond)
				close(c.quitChan)
				return
			case "/help":
				c.sendCommand(CMD_HELP, nil)
			case "/version":
				c.sendCommand(CMD_VERSION, nil)
			case "/status":
				c.sendCommand(CMD_STATUS, nil)
			case "/time":
				c.sendCommand(CMD_TIME, nil)
			case "/username":
				if len(args) > 0 {
					c.username = strings.Join(args, " ")
					c.sendCommand(CMD_SET_USERNAME, []byte(c.username))
				} else {
					fmt.Println("Usage: /username <new_name>")
				}
			case "/users":
				c.sendCommand(CMD_LIST_USERS, []byte(strings.Join(args, " ")))
			case "/echo":
				c.sendCommand(CMD_ECHO, []byte(strings.Join(args, " ")))
			case "/reverse":
				c.sendCommand(CMD_PROCESS_DATA, []byte(strings.Join(args, " ")))
			case "/msg":
				if len(args) > 1 {
					receiver := args[0]
					message := strings.Join(args[1:], " ")

					// create payload with '\n' seperator for ease of parsing
					payload := []byte(receiver + "\n" + message)
					c.sendCommand(CMD_PRIVATE_MSG, payload)

				} else {
					fmt.Println("Usage: /msg <username> <message>")
				}
			case "/roll":
				c.sendCommand(CMD_ROLL_DICE, []byte(strings.Join(args, " ")))
			case "/store":
				c.sendCommand(CMD_DB_STORE, []byte(strings.Join(args, " ")))
			case "/retrieve":
				c.sendCommand(CMD_DB_RETRIEVE, []byte(strings.Join(args, " ")))
			case "/list":
				c.sendCommand(CMD_DB_LIST, nil)
			case "/send":
				if len(args) == 1 {
					go c.sendFile(args[0])
				} else {
					fmt.Println("Usage: /send <filepath>")
				}
			case "/get":
				if len(args) == 1 {
					c.sendCommand(CMD_FILE_GET, []byte(args[0]))
				} else {
					fmt.Println("Usage: /get <filename>")
				}
			case "/listfiles":
				c.sendCommand(CMD_FILE_LIST, nil)
			case "/delete":
				if len(args) == 1 {
					c.sendCommand(CMD_FILE_DELETE, []byte(args[0]))
				} else {
					fmt.Println("Usage: /delete <filename>")
				}
			default:
				fmt.Printf("\rUnknown command: %s. Type /help.\n", command)
			}
		} else {
			c.sendCommand(CMD_BROADCAST, []byte(text))
		}
		fmt.Print("> ")
	}
}

// handleHeartbeats sends a heartbeat packet every 15 seconds.
func (c *Client) handleHeartbeats() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.sendCommand(CMD_HEARTBEAT, nil)
		case <-c.quitChan:
			return
		}
	}
}

// sendCommand is a simple helper to construct and send a packet.
func (c *Client) sendCommand(cmd byte, payload []byte) {
	packet := append([]byte{cmd}, payload...)

	// Encrypt if encryption is enabled and ready
	if c.isEncrypted && c.encMgr != nil && c.encMgr.IsReady() {
		encrypted, err := c.encMgr.Encrypt(packet)
		if err != nil {
			// For file transfer, encryption failure is critical
			if cmd == CMD_FILE_CHUNK || cmd == CMD_FILE_START {
				fmt.Printf("\nCritical: File transfer encryption failed: %v\n", err)
				return // Don't send unencrypted file data
			}
			fmt.Printf("\nWarning: Encryption failed, sending unencrypted: %v\n", err)
		} else {
			packet = encrypted
		}
	}

	_, err := c.conn.Write(packet)
	if err != nil {
		select {
		case <-c.quitChan:
		default:
			fmt.Printf("\nError sending command: %v\n", err)
		}
	}
}

// sendFile handles the logic for uploading a file to the server.
func (c *Client) sendFile(filePath string) {
	c.transferLock.Lock()
	defer c.transferLock.Unlock()

	// --- Configuration ---
	windowSize := 64 // Increased window size for better performance
	ackTimeout := 2 * time.Second
	maxRetries := 5

	// --- File Reading & Setup ---
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("\rError reading file: %v\n> ", err)
		return
	}

	filename := filepath.Base(filePath)
	totalChunks := (len(fileData) + CHUNK_SIZE - 1) / CHUNK_SIZE

	// --- Transfer Initiation ---
	startPayload := make([]byte, 4+len(filename))
	binary.BigEndian.PutUint32(startPayload[0:4], uint32(totalChunks))
	copy(startPayload[4:], []byte(filename))
	resp, err := c.sendAndReceive(CMD_FILE_START, startPayload, 5*time.Second)
	if err != nil {
		fmt.Printf("\rServer did not respond to file transfer request: %v\n> ", err)
		return
	}
	transferID := string(resp)
	fmt.Printf("\rUploading '%s' (%d chunks) with ID: %s\n> ", filename, totalChunks, transferID)

	// --- State Management ---
	windowStart := 0
	windowEnd := 0
	ackedChunks := make(map[int]bool)
	retryCount := make(map[int]int)
	lastAckTime := time.Now()
	var stateMutex sync.Mutex

	// --- ACK Processing Goroutine ---
	ackDone := make(chan struct{})
	go func() {
		for {
			select {
			case seqNum := <-c.ackChan:
				//fmt.Printf("\r<- [ACK] Received for uploaded chunk #%d\n> ", seqNum)
				stateMutex.Lock()
				ackedChunks[int(seqNum)] = true
				lastAckTime = time.Now()
				// Slide the window
				for ackedChunks[windowStart] {
					windowStart++
				}
				stateMutex.Unlock()
			case <-ackDone:
				return
			}
		}
	}()

	// --- Main Sending Loop ---
	lastProgressTime := time.Now()
	for windowStart < totalChunks {
		stateMutex.Lock()

		// Send new chunks to fill the window
		for windowEnd < totalChunks && windowEnd-windowStart < windowSize {
			if retryCount[windowEnd] < maxRetries {
				start := windowEnd * CHUNK_SIZE
				end := start + CHUNK_SIZE
				if end > len(fileData) {
					end = len(fileData)
				}
				chunkPayload := make([]byte, 4+1+len(transferID))
				binary.BigEndian.PutUint32(chunkPayload[0:4], uint32(windowEnd))
				chunkPayload[4] = byte(len(transferID))
				copy(chunkPayload[5:], []byte(transferID))
				chunkPayload = append(chunkPayload, fileData[start:end]...)
				c.sendCommand(CMD_FILE_CHUNK, chunkPayload)
			}
			windowEnd++
		}

		// Update progress
		if time.Since(lastProgressTime) > time.Second {
			progress := (windowStart * 100) / totalChunks
			fmt.Printf("\rUploading... %d%% (%d/%d chunks)", progress, windowStart, totalChunks)
			lastProgressTime = time.Now()
		}

		// Check for timeout to retransmit
		if time.Since(lastAckTime) > ackTimeout {
			fmt.Printf("\rTimeout detected, retransmitting window...\n> ")
			// Retransmit un-acked chunks in the current window
			for i := windowStart; i < windowEnd; i++ {
				if !ackedChunks[i] && retryCount[i] < maxRetries {
					retryCount[i]++ // Increment retry count

					start := i * CHUNK_SIZE
					end := start + CHUNK_SIZE
					if end > len(fileData) {
						end = len(fileData)
					}
					chunkPayload := make([]byte, 4+1+len(transferID))
					binary.BigEndian.PutUint32(chunkPayload[0:4], uint32(i))
					chunkPayload[4] = byte(len(transferID))
					copy(chunkPayload[5:], []byte(transferID))
					chunkPayload = append(chunkPayload, fileData[start:end]...)
					c.sendCommand(CMD_FILE_CHUNK, chunkPayload)
				}
			}
			lastAckTime = time.Now() // Reset timeout timer
		}

		stateMutex.Unlock()
		time.Sleep(10 * time.Millisecond) // Prevent busy-waiting
	}

	close(ackDone) // Stop the ACK goroutine

	fmt.Printf("\rUpload complete for '%s' ✅\n> ", filename)
}

func (c *Client) receiveFile(startPayload []byte) {
	if len(startPayload) < 4 {
		return
	}
	totalChunks := binary.BigEndian.Uint32(startPayload[0:4])
	filename := string(startPayload[4:])

	fmt.Printf("\rIncoming file from server: '%s' (%d chunks). Receiving...\n> ", filename, totalChunks)

	_ = os.Mkdir("downloads", 0755)
	filePath := filepath.Join("downloads", filename)

	download := &FileDownload{
		TotalChunks: totalChunks,
		Chunks:      make(chan []byte, 200), // A buffer to hold incoming chunks
	}
	c.downloadMutex.Lock()
	c.activeDownloads[filename] = download
	c.downloadMutex.Unlock()

	defer func() {
		c.downloadMutex.Lock()
		delete(c.activeDownloads, filename)
		c.downloadMutex.Unlock()
	}()

	receivedChunks := make([][]byte, totalChunks)
	var receivedCount uint32 = 0
	lastProgressTime := time.Now()

	// Simplified single-phase reception loop with retries
	for retries := 0; retries < 5 && receivedCount < totalChunks; retries++ {
		// Listen for incoming chunks for a set period.
		// On the first pass (retries=0), this is the main download phase.
		// On subsequent passes, this is for receiving re-sent chunks.
		listenTimeout := 10 * time.Second // Wait up to 10 seconds for chunks
		listenEndTime := time.Now().Add(listenTimeout)

		for time.Now().Before(listenEndTime) {
			select {
			case chunkPayload := <-download.Chunks:
				if len(chunkPayload) < 4 {
					continue
				}
				seqNum := binary.BigEndian.Uint32(chunkPayload[0:4])
				if seqNum < totalChunks && receivedChunks[seqNum] == nil {
					receivedChunks[seqNum] = chunkPayload[4:]
					receivedCount++

					// Payload format: [filename_len (1 byte)][filename][4B seqNum]
					filenameBytes := []byte(filename)
					ackPayload := make([]byte, 1+len(filenameBytes)+4)
					ackPayload[0] = byte(len(filenameBytes))
					copy(ackPayload[1:], filenameBytes)
					binary.BigEndian.PutUint32(ackPayload[1+len(filenameBytes):], seqNum)

					c.sendCommand(CMD_FILE_ACK, ackPayload)
				}
			default:
				// If channel is empty, sleep briefly to avoid busy-waiting
				time.Sleep(10 * time.Millisecond)
			}
			// Update progress periodically
			if time.Since(lastProgressTime) > time.Second {
				progress := (receivedCount * 100) / totalChunks
				fmt.Printf("\rDownloading '%s'... %d%% (%d/%d chunks)", filename, progress, receivedCount, totalChunks)
				lastProgressTime = time.Now()
			}

			if receivedCount == totalChunks {
				break // Exit listen loop if complete
			}
		}

		// If we're still missing chunks, request them.
		if receivedCount < totalChunks {
			var missingChunks []uint32
			for i := uint32(0); i < totalChunks; i++ {
				if receivedChunks[i] == nil {
					missingChunks = append(missingChunks, i)
				}
			}

			if len(missingChunks) > 0 {
				fmt.Printf("\rRequesting %d missing chunks (attempt %d/5)...\n> ", len(missingChunks), retries+1)
				// Batch requests to avoid creating a massive UDP packet
				batchSize := 250 // Request up to 250 missing chunks at a time
				for i := 0; i < len(missingChunks); i += batchSize {
					end := i + batchSize
					if end > len(missingChunks) {
						end = len(missingChunks)
					}
					batch := missingChunks[i:end]

					// Construct payload: [filename_len (1 byte)][filename][missing_chunks_data]
					missingPayload := make([]byte, 0, len(batch)*4)
					for _, seq := range batch {
						seqBytes := make([]byte, 4)
						binary.BigEndian.PutUint32(seqBytes, seq)
						missingPayload = append(missingPayload, seqBytes...)
					}
					requestPayload := make([]byte, 1+len(filename))
					requestPayload[0] = byte(len(filename))
					copy(requestPayload[1:], []byte(filename))
					requestPayload = append(requestPayload, missingPayload...)
					c.sendCommand(CMD_FILE_REQUEST_CHUNKS, requestPayload)
					time.Sleep(50 * time.Millisecond) // Small delay between batch requests
				}
			}
		}
	}

	// Final Assembly and Status Report
	fmt.Println() // Newline after progress indicator
	if receivedCount < totalChunks {
		fmt.Printf("\rDownload for '%s' failed. Missing %d chunks. File is corrupt.\n> ", filename, totalChunks-receivedCount)
	} else {
		fmt.Printf("\rDownload complete for '%s'. Assembling file...\n> ", filename)
	}

	file, err := os.Create(filePath)
	if err != nil {
		fmt.Printf("\rError creating file: %v\n> ", err)
		return
	}
	defer file.Close()

	// Write all received chunks
	for i := uint32(0); i < totalChunks; i++ {
		if receivedChunks[i] != nil {
			if _, err := file.Write(receivedChunks[i]); err != nil {
				fmt.Printf("\rError writing to file: %v\n> ", err)
				return
			}
		}
	}

	if receivedCount == totalChunks {
		fmt.Printf("\rSuccessfully saved file to %s ✅\n> ", filePath)
	}
}

// sendAndReceive is a robust helper for commands that expect a direct response.
func (c *Client) sendAndReceive(cmd byte, payload []byte, timeout time.Duration) ([]byte, error) {
	c.responseLock.Lock()
	c.responseChan = make(chan []byte, 1)
	c.responseLock.Unlock()

	defer func() {
		c.responseLock.Lock()
		c.responseChan = nil
		c.responseLock.Unlock()
	}()

	packet := append([]byte{cmd}, payload...)
	_, err := c.conn.Write(packet)
	if err != nil {
		return nil, err
	}

	select {
	case response := <-c.responseChan:
		return response, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for response")
	}
}

func (c *Client) checkServerLiveness() {
	// The timeout duration should be longer than the server's heartbeat interval (15s)
	const serverTimeout = 45 * time.Second
	ticker := time.NewTicker(5 * time.Second) // Check every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if time.Since(c.lastServerActivity) > serverTimeout {
				fmt.Printf("\nConnection to server timed out. No response for over %v.\n", serverTimeout)
				close(c.quitChan) // Trigger a clean shutdown
				return
			}
		case <-c.quitChan:
			return // Exit if the client is quitting normally
		}
	}
}
