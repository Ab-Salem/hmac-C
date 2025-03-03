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
    parser = argparse.ArgumentParser(description='HMAC Server')
    parser.add_argument('--port', type=int, default=8080, help='Server port')
    parser.add_argument('--key', default='my-secret-key', help='Secret key for HMAC')
    args = parser.parse_args()
    
    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Bind and listen
        server_socket.bind(('0.0.0.0', args.port))
        server_socket.listen(1)
        print(f"Server listening on port {args.port}")
        
        # Accept connection
        client_socket, client_address = server_socket.accept()
        print(f"Client connected: {client_address[0]}:{client_address[1]}")
        
        secret_key = args.key.encode()
        
        # Benchmarking variables
        message_count = 0
        valid_hmacs = 0
        invalid_hmacs = 0
        total_time = 0
        verify_time = 0
        
        buffer_size = 8192  # Adjust based on expected message size
        
        while True:
            try:
                # Receive message
                start_time = time.time()
                
                data = client_socket.recv(buffer_size)
                if not data:
                    print("Client disconnected")
                    break
                
                # Parse message
                payload = data.decode('latin1')
                delimiter_pos = payload.find(':')
                
                if delimiter_pos == -1:
                    print("Invalid message format")
                    break
                
                received_hmac_hex = payload[:delimiter_pos]
                message = payload[delimiter_pos + 1:].encode('latin1')
                
                # Verify HMAC
                verify_start = time.time()
                expected_hmac = calculate_hmac(message, secret_key)
                expected_hmac_hex = expected_hmac.hex()
                verify_end = time.time()
                verify_time += verify_end - verify_start
                
                # Check if HMACs match
                hmac_valid = received_hmac_hex == expected_hmac_hex
                if hmac_valid:
                    valid_hmacs += 1
                    client_socket.send(b"OK")
                else:
                    invalid_hmacs += 1
                    client_socket.send(b"FAIL")
                    print(f"HMAC verification failed for message {message_count}")
                
                end_time = time.time()
                total_time += end_time - start_time
                
                message_count += 1
                
                if message_count % 100 == 0:
                    print(f"Processed {message_count} messages...")
            
            except Exception as e:
                print(f"Error processing message: {e}")
                break
        
        # Convert times to milliseconds
        total_time_ms = total_time * 1000
        verify_time_ms = verify_time * 1000
        
        # Print benchmark results
        print("\nBenchmark Results:")
        print(f"Total messages processed: {message_count}")
        print(f"Valid HMACs: {valid_hmacs}")
        print(f"Invalid HMACs: {invalid_hmacs}")
        print(f"Total Time: {total_time_ms:.2f} ms")
        
        if message_count > 0:
            print(f"Average Time per Message: {total_time_ms / message_count:.2f} ms")
            print(f"HMAC Verification Time: {verify_time_ms:.2f} ms ({verify_time_ms / total_time_ms * 100:.2f}%)")
    
    except Exception as e:
        print(f"Server error: {e}")
    
    finally:
        try:
            client_socket.close()
        except:
            pass
        server_socket.close()

if __name__ == "__main__":
    main()