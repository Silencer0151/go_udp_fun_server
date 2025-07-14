#!/usr/bin/env python3
import socket
import argparse
import sys
import threading

# --- Global flag to signal threads to stop ---
shutdown_event = threading.Event()

def server_loop(host, port):
    """
    Runs in listen mode. Binds to a host/port and prints any UDP packets it receives.
    """
    # Create a UDP socket
    # AF_INET specifies IPv4
    # SOCK_DGRAM specifies UDP
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # Bind the socket to the specified host and port to listen for incoming packets
        server.bind((host, port))
        print(f"[*] UDP Server listening on {host}:{port}")

        while not shutdown_event.is_set():
            # Wait for and receive data (up to 4096 bytes)
            # recvfrom returns the data and the address (ip, port) of the sender
            data, addr = server.recvfrom(4096)
            
            # Print the received data, converting it from bytes to a string
            print(f"[*] Received from {addr[0]}:{addr[1]}:")
            # Use sys.stdout.buffer.write to handle raw bytes, in case it's not valid utf-8
            sys.stdout.buffer.write(data)
            sys.stdout.flush()

    except OSError as e:
        print(f"[!] Error: {e}")
        print(f"[!] Could not bind to {host}:{port}. Is the port already in use?")
    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")
    finally:
        server.close()

def client_receiver(sock):
    """
    A dedicated thread for receiving messages in client mode.
    """
    while not shutdown_event.is_set():
        try:
            # Set a timeout so the recvfrom call doesn't block forever
            # This allows the thread to check the shutdown_event periodically
            sock.settimeout(1.0)
            data, addr = sock.recvfrom(4096)
            
            print("\n<-- Response from server:")
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
            print("--> ", end='', flush=True) # Reprint the prompt

        except socket.timeout:
            continue # Nothing received, loop again
        except (ConnectionResetError, OSError):
            print("[!] Connection closed by server.")
            shutdown_event.set()
            break
        except Exception as e:
            if not shutdown_event.is_set():
                print(f"\n[!] Receiver error: {e}")
            break

def client_sender(host, port, binary_mode=False):
    """
    Runs in client mode. Sends data from stdin to a target host/port.
    """
    # Create a UDP socket
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Start a thread to handle receiving responses from the server
    receiver_thread = threading.Thread(target=client_receiver, args=(client,))
    receiver_thread.daemon = True # Allows main thread to exit even if this one is running
    receiver_thread.start()

    print(f"[*] UDP Client targeting {host}:{port}")
    if binary_mode:
        print("[*] BINARY MODE ENABLED: Sending raw bytes from stdin. Ctrl+C to exit.")
    else:
        print("[*] TEXT MODE ENABLED: Type your message and press Enter to send. Ctrl+C to exit.")

    try:
        if binary_mode:
            # In binary mode, read stdin as a raw byte stream in chunks
            while not shutdown_event.is_set():
                chunk = sys.stdin.buffer.read(4096)
                if not chunk:
                    break # End of stream (e.g., Ctrl+D or end of piped file)
                client.sendto(chunk, (host, port))
        else:
            # Original text mode
            while not shutdown_event.is_set():
                print("--> ", end='', flush=True)
                message = sys.stdin.readline()
                if not message:
                    break # stdin was closed (e.g., piped input finished)
                client.sendto(message.encode('utf-8'), (host, port))

    except KeyboardInterrupt:
        print("\n[*] Client shutting down.")
    finally:
        # Give a moment for final packets to be received before shutting down
        threading.sleep(0.1)
        shutdown_event.set() # Signal the receiver thread to stop
        receiver_thread.join(timeout=1) # Wait briefly for the thread to finish
        client.close()


def main():
    parser = argparse.ArgumentParser(
        description="A simple Python Netcat clone for UDP.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('host', help="Target host IP address.")
    parser.add_argument('port', type=int, help="Target port.")
    parser.add_argument(
        '-l', '--listen',
        action='store_true',
        help="Listen mode. Binds to [host]:[port] and waits for incoming data."
    )
    parser.add_argument(
        '-b', '--binary',
        action='store_true',
        help="Binary mode. Reads raw bytes from stdin and sends without encoding."
    )
    args = parser.parse_args()

    if args.listen:
        # Start in listen (server) mode
        server_loop(args.host, args.port)
    else:
        # Start in client mode, passing the binary flag
        client_sender(args.host, args.port, args.binary)

if __name__ == '__main__':
    main()
