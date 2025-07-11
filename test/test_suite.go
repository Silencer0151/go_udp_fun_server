package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	CMD_BROADCAST       byte = 0x02
	CMD_STATUS          byte = 0x03
	CMD_PROCESS_DATA    byte = 0x04
	CMD_TIME            byte = 0x05
	CMD_SET_USERNAME    byte = 0x06
	CMD_ECHO            byte = 0x07
	CMD_CONNECT_SYN     byte = 0x10
	CMD_CONNECT_SYN_ACK byte = 0x11
	CMD_CONNECT_ACK     byte = 0x12
	CMD_HEARTBEAT       byte = 0x13
	CMD_DB_STORE        byte = 0x20
	CMD_DB_RETRIEVE     byte = 0x21
	CMD_DB_LIST         byte = 0x22
)

const SERVER_ADDR = "127.0.0.1:8080"

func main() {
	fmt.Println("--- STARTING TEST SUITE ---")

	// --- Single Client Tests ---
	runSingleClientTests()

	// --- Multi-Client Broadcast Test ---
	runBroadcastTest()

	fmt.Println("\n--- TEST SUITE COMPLETE ---")
}

// runSingleClientTests runs all tests that can be performed by one client.
func runSingleClientTests() {
	fmt.Println("\n--- Running Single-Client Tests ---")
	conn, err := net.Dial("udp", SERVER_ADDR)
	if err != nil {
		fmt.Printf("❌ FATAL: Could not connect to server: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Run tests in sequence
	testHandshake(conn)
	testSetUsername(conn, "TestClient1")
	testEcho(conn)
	testProcessData(conn)
	testTimeAndStatus(conn)
	testDatabaseFeatures(conn)
}

// runBroadcastTest simulates two clients to test the broadcast function.
func runBroadcastTest() {
	fmt.Println("\n--- Running Multi-Client Broadcast Test ---")
	var wg sync.WaitGroup
	wg.Add(2)

	// Channel to receive the broadcast message on
	broadcastChan := make(chan string, 1)

	// Start Listener Client
	go func() {
		defer wg.Done()
		listenerConn, _ := net.Dial("udp", SERVER_ADDR)
		defer listenerConn.Close()

		if !testHandshake(listenerConn) {
			return
		}
		testSetUsername(listenerConn, "Listener")

		// Listen for 3 seconds for a broadcast
		fmt.Println("[Listener]: Listening for broadcast...")
		listenerConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buffer := make([]byte, 1024)
		n, err := listenerConn.Read(buffer)
		if err != nil {
			fmt.Println("❌ [Listener]: Did not receive broadcast in time.")
			return
		}
		receivedMsg := string(buffer[:n])
		fmt.Printf("✅ [Listener]: Received a message: '%s'\n", receivedMsg)
		broadcastChan <- receivedMsg
	}()

	// Give the listener a moment to get set up
	time.Sleep(500 * time.Millisecond)

	// Start Broadcaster Client
	go func() {
		defer wg.Done()
		broadcasterConn, _ := net.Dial("udp", SERVER_ADDR)
		defer broadcasterConn.Close()

		if !testHandshake(broadcasterConn) {
			return
		}
		testSetUsername(broadcasterConn, "Broadcaster")

		fmt.Println("[Broadcaster]: Sending broadcast message...")
		broadcastMsg := "Hello all listeners!"
		cmd := append([]byte{CMD_BROADCAST}, []byte(broadcastMsg)...)
		broadcasterConn.Write(cmd)
	}()

	// Wait for both clients to finish
	wg.Wait()
	close(broadcastChan)

	// Verify the result
	finalMsg, ok := <-broadcastChan
	expectedMsg := "[Broadcaster]: Hello all listeners!"
	if !ok {
		fmt.Println("❌ Broadcast Test FAILED: Listener channel was empty.")
	} else if finalMsg != expectedMsg {
		fmt.Printf("❌ Broadcast Test FAILED: Expected '%s', got '%s'\n", expectedMsg, finalMsg)
	} else {
		fmt.Println("✅ Broadcast Test PASSED!")
	}
}

// --- Helper function to send and receive ---
func sendAndReceive(conn net.Conn, command []byte) (string, error) {
	_, err := conn.Write(command)
	if err != nil {
		return "", fmt.Errorf("error sending: %w", err)
	}
	buffer := make([]byte, 8192) // Increased buffer for DB values
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("error reading: %w", err)
	}
	return string(buffer[:n]), nil
}

// --- Individual Test Functions ---

func testHandshake(conn net.Conn) bool {
	fmt.Println("Testing: Handshake")
	_, err := conn.Write([]byte{CMD_CONNECT_SYN})
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil || n == 0 || buffer[0] != CMD_CONNECT_SYN_ACK {
		fmt.Printf("❌ Handshake SYN-ACK FAILED. Err: %v\n", err)
		return false
	}
	_, err = conn.Write([]byte{CMD_CONNECT_ACK})
	if err != nil {
		fmt.Printf("❌ Handshake ACK FAILED. Err: %v\n", err)
		return false
	}
	fmt.Println("✅ Handshake PASSED")
	return true
}

func testSetUsername(conn net.Conn, name string) {
	fmt.Printf("Testing: Set Username to '%s'\n", name)
	cmd := append([]byte{CMD_SET_USERNAME}, []byte(name)...)
	resp, err := sendAndReceive(conn, cmd)
	if err != nil || resp != "Username set successfully!" {
		fmt.Printf("❌ Set Username FAILED. Response: '%s', Err: %v\n", resp, err)
	} else {
		fmt.Println("✅ Set Username PASSED")
	}
}

func testEcho(conn net.Conn) {
	fmt.Println("Testing: Echo")
	msg := "echo test message"
	resp, err := sendAndReceive(conn, append([]byte{CMD_ECHO}, []byte(msg)...))
	if err != nil || resp != msg {
		fmt.Printf("❌ Echo FAILED. Expected '%s', got '%s'\n", msg, resp)
	} else {
		fmt.Println("✅ Echo PASSED")
	}
}

func testProcessData(conn net.Conn) {
	fmt.Println("Testing: Process Data (Reverse)")
	msg := "reverse this!"
	expected := "!siht esrever"
	resp, err := sendAndReceive(conn, append([]byte{CMD_PROCESS_DATA}, []byte(msg)...))
	if err != nil || resp != expected {
		fmt.Printf("❌ Process Data FAILED. Expected '%s', got '%s'\n", expected, resp)
	} else {
		fmt.Println("✅ Process Data PASSED")
	}
}

func testTimeAndStatus(conn net.Conn) {
	fmt.Println("Testing: Time and Status")
	_, err := sendAndReceive(conn, []byte{CMD_TIME})
	if err != nil {
		fmt.Printf("❌ Time FAILED. Err: %v\n", err)
	} else {
		fmt.Println("✅ Time PASSED")
	}
	_, err = sendAndReceive(conn, []byte{CMD_STATUS})
	if err != nil {
		fmt.Printf("❌ Status FAILED. Err: %v\n", err)
	} else {
		fmt.Println("✅ Status PASSED")
	}
}

func testDatabaseFeatures(conn net.Conn) {
	fmt.Println("Testing: Database Features")
	// Store
	key, val := "testKey", "testValue"
	cmd := append([]byte{CMD_DB_STORE}, []byte(key+"="+val)...)
	resp, err := sendAndReceive(conn, cmd)
	if err != nil || resp != "Value stored successfully." {
		fmt.Printf("❌ DB Store FAILED. Resp: '%s', Err: %v\n", resp, err)
		return
	}
	fmt.Println("  - ✅ DB Store PASSED")

	// Retrieve
	cmd = append([]byte{CMD_DB_RETRIEVE}, []byte(key)...)
	resp, err = sendAndReceive(conn, cmd)
	if err != nil || resp != val {
		fmt.Printf("❌ DB Retrieve FAILED. Expected '%s', got '%s'\n", val, resp)
		return
	}
	fmt.Println("  - ✅ DB Retrieve PASSED")

	// List
	cmd = []byte{CMD_DB_LIST}
	resp, err = sendAndReceive(conn, cmd)
	if err != nil || !strings.Contains(resp, key) {
		fmt.Printf("❌ DB List FAILED. Resp: '%s', Err: %v\n", resp, err)
		return
	}
	fmt.Println("  - ✅ DB List PASSED")

	// Retrieve non-existent key
	cmd = append([]byte{CMD_DB_RETRIEVE}, []byte("nonexistentkey")...)
	resp, err = sendAndReceive(conn, cmd)
	if err != nil || resp != "Error: Key not found." {
		fmt.Printf("❌ DB Retrieve Non-Existent FAILED. Resp: '%s'\n", resp)
		return
	}
	fmt.Println("  - ✅ DB Retrieve Non-Existent PASSED")

}
