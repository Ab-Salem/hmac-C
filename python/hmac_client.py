#!/usr/bin/env python3
import socket
import hmac
import hashlib
import time
import argparse
from typing import Tuple

def calculate_hmac(message: bytes, key: bytes) -> bytes:
    """Calculate HMAC-SHA256 for the given message and key."""
    h = hmac.new(key, message, hashlib.sha256)
    return h.digest()

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='HMAC Client')
    parser.add_argument('--ip', default='127.0.0.1', help='Server IP address')
    parser.add_argument('--port', type=int, default=8080, help='Server port')
    parser.add_argument('--key', default='my-secret-key', help='Secret key for HMAC')
    parser.add_argument('--num', type=int, default=1000, help='Number of messages to send')
    parser.add_argument('--size', type=int, default=1024, help='Size of each message in bytes')
    args = parser.parse_args()
    
    # Create socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Connect to server
        print(f"Connecting to {args.ip}:{args.port}...")
        client_socket.connect((args.ip, args.port))
        print("Connected!")
        
        # Create a message of specified size
        message = b'A' * args.size
        secret_key = args.key.encode()
        
        # Benchmark variables
        total_time = 0
        hmac_time = 0
        send_time = 0
        
        print(f"Starting benchmark: sending {args.num} messages of size {args.size} bytes")
        
        # Send messages and measure time
        for i in range(args.num):
            start_time = time.time()
            
            # Calculate HMAC
            hmac_start = time.time()
            hmac_digest = calculate_hmac(message, secret_key)
            hmac_end = time.time()
            hmac_time += hmac_end - hmac_start
            
            # Convert HMAC to hex string
            hmac_hex = hmac_digest.hex()
            
            # Prepare message with HMAC: [hmac_hex]:[message]
            payload = f"{hmac_hex}:{message.decode('latin1')}".encode('latin1')
            
            # Send the message
            send_start = time.time()
            client_socket.send(payload)
            
            # Receive acknowledgement
            ack = client_socket.recv(16)
            send_end = time.time()
            send_time += send_end - send_start
            
            end_time = time.time()
            total_time += end_time - start_time
            
            if i % 100 == 0:
                print(f"Processed {i} messages...")
        
        # Convert times to milliseconds
        total_time_ms = total_time * 1000
        hmac_time_ms = hmac_time * 1000
        send_time_ms = send_time * 1000
        
        # Print benchmark results
        print("\nBenchmark Results:")
        print(f"Total Time: {total_time_ms:.2f} ms")
        print(f"Average Time per Message: {total_time_ms / args.num:.2f} ms")
        print(f"HMAC Calculation Time: {hmac_time_ms:.2f} ms ({hmac_time_ms / total_time_ms * 100:.2f}%)")
        print(f"Network I/O Time: {send_time_ms:.2f} ms ({send_time_ms / total_time_ms * 100:.2f}%)")
    
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()