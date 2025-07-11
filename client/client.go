// GUFS Client: Go UDP Fun Server - Interactive REPL Client
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
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
	CMD_BROADCAST    byte = 0x02
	CMD_STATUS       byte = 0x03
	CMD_PROCESS_DATA byte = 0x04
	CMD_TIME         byte = 0x05
	CMD_SET_USERNAME byte = 0x06
	CMD_ECHO         byte = 0x07

	// Connection Protocol
	CMD_CONNECT_SYN     byte = 0x10
	CMD_CONNECT_SYN_ACK byte = 0x11
	CMD_CONNECT_ACK     byte = 0x12
	CMD_HEARTBEAT       byte = 0x13

	// Database Commands
	CMD_DB_STORE    byte = 0x20
	CMD_DB_RETRIEVE byte = 0x21
	CMD_DB_LIST     byte = 0x22

	// Metadata Commands
	CMD_VERSION byte = 0x30
	CMD_HELP    byte = 0x31

	// File Transfer Protocol
	CMD_FILE_START byte = 0x40
	CMD_FILE_CHUNK byte = 0x41
	CMD_FILE_ACK   byte = 0x42
	CMD_FILE_GET   byte = 0x43
	CMD_FILE_LIST  byte = 0x44
)

const (
	CHUNK_SIZE = 1024
)

// Client holds the state for a single client connection.
type Client struct {
	conn            net.Conn
	username        string
	serverAddr      string
	isConnected     bool
	quitChan        chan struct{}
	ackChan         chan uint32 // Channel for file upload ACKs
	responseChan    chan []byte // Channel for direct command responses
	transferLock    sync.Mutex  // Prevents multiple file transfers at once
	responseLock    sync.Mutex  // Protects the responseChan
	activeDownloads map[string]*FileDownload
	downloadMutex   sync.Mutex
}

// file download hold the state for an incoming file
type FileDownload struct {
	TotalChunks uint32
	Chunks      chan []byte // A channel to stream chunk data to the receiver
}

func generateUsername() string {
	rand.Seed(time.Now().UnixNano())
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
	c.conn.SetReadDeadline(time.Time{})

	_, err = c.conn.Write([]byte{CMD_CONNECT_ACK})
	if err != nil {
		return err
	}

	c.isConnected = true
	fmt.Printf("Successfully connected to %s as '%s'. Type /help for commands.\n", c.serverAddr, c.username)
	return nil
}

// Run starts the main client goroutines for handling I/O and heartbeats.
func (c *Client) Run() {
	go c.handleServerMessages()
	go c.handleUserInput()
	go c.handleHeartbeats()

	<-c.quitChan
	fmt.Println("Disconnecting from server...")
}

// handleServerMessages runs in a loop, processing all incoming data from the server.
func (c *Client) handleServerMessages() {
	buffer := make([]byte, 8192)
	for {
		n, err := c.conn.Read(buffer)
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
			case "/quit":
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
			case "/echo":
				c.sendCommand(CMD_ECHO, []byte(strings.Join(args, " ")))
			case "/reverse":
				c.sendCommand(CMD_PROCESS_DATA, []byte(strings.Join(args, " ")))
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

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("\rError reading file: %v\n> ", err)
		return
	}

	filename := filepath.Base(filePath)
	totalChunks := (len(fileData) + CHUNK_SIZE - 1) / CHUNK_SIZE

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

	for i := 0; i < totalChunks; i++ {
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

		for retries := 0; retries < 3; retries++ {
			c.sendCommand(CMD_FILE_CHUNK, chunkPayload)
			select {
			case ackNum := <-c.ackChan:
				if ackNum == uint32(i) {
					goto nextChunk
				}
			case <-time.After(2 * time.Second):
				fmt.Printf("\rTimeout waiting for ACK on chunk %d. Retrying...\n> ", i)
			}
		}
		fmt.Printf("\rFailed to upload chunk %d after 3 retries. Aborting.\n> ", i)
		return

	nextChunk:
		fmt.Printf("\rUploading... %d%%", (i+1)*100/totalChunks)
	}
	fmt.Printf("\rUpload complete for '%s'.\n> ", filename)
}

func (c *Client) receiveFile(startPayload []byte) {
	if len(startPayload) < 5 {
		return
	}
	totalChunks := binary.BigEndian.Uint32(startPayload[0:4])
	filename := string(startPayload[4:])

	fmt.Printf("\rIncoming file from server: '%s' (%d chunks). Preparing to receive...\n> ", filename, totalChunks)

	// Create download directory if it doesn't exist
	_ = os.Mkdir("downloads", 0755)
	filePath := filepath.Join("downloads", filename)
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Printf("\rError creating file for download: %v\n> ", err)
		return
	}
	defer file.Close()

	// Register this download so the message handler can route chunks to it
	download := &FileDownload{
		TotalChunks: totalChunks,
		Chunks:      make(chan []byte, 100), // Buffered channel
	}
	c.downloadMutex.Lock()
	c.activeDownloads[filename] = download
	c.downloadMutex.Unlock()

	// Unregister the download when this function finishes
	defer func() {
		c.downloadMutex.Lock()
		delete(c.activeDownloads, filename)
		c.downloadMutex.Unlock()
	}()

	receivedChunks := make([][]byte, totalChunks)
	var receivedCount uint32 = 0
	timeout := time.NewTimer(20 * time.Second) // 20-second timeout for the whole transfer

	for receivedCount < totalChunks {
		select {
		case <-timeout.C:
			fmt.Printf("\rFile download for '%s' timed out. Incomplete file saved.\n> ", filename)
			return
		case chunkPayload := <-download.Chunks:
			if len(chunkPayload) < 4 {
				continue
			}
			seqNum := binary.BigEndian.Uint32(chunkPayload[0:4])
			if seqNum < totalChunks && receivedChunks[seqNum] == nil {
				receivedChunks[seqNum] = chunkPayload[4:]
				receivedCount++
				fmt.Printf("\rDownloading '%s'... %d%%", filename, (receivedCount*100)/totalChunks)
			}
		}
	}
	timeout.Stop()

	// All chunks received, assemble the file.
	fmt.Printf("\rDownload complete for '%s'. Assembling file...\n> ", filename)
	for i := uint32(0); i < totalChunks; i++ {
		if _, err := file.Write(receivedChunks[i]); err != nil {
			fmt.Printf("\rError writing to file: %v\n> ", err)
			return
		}
	}
	fmt.Printf("\rSuccessfully saved file to %s\n> ", filePath)
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
