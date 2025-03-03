# HMAC Client-Server Implementation

This repository contains implementations of HMAC authentication over network sockets in both C++ and Python, including benchmarking capabilities.

## C++ Implementation

The C++ implementation uses:
* OpenSSL for HMAC-SHA256 computation
* POSIX sockets for networking
* Chrono library for high-precision timing

### Files:
1. `hmac_client.cpp` - Sends messages with HMAC authentication
2. `hmac_server.cpp` - Receives and verifies HMAC-authenticated messages

### Usage:

```bash
# Compile
g++ -o hmac_server hmac_server.cpp -lcrypto
g++ -o hmac_client hmac_client.cpp -lcrypto

# Run server
./hmac_server --port 8080 --key "my-secret-key"

# Run client
./hmac_client --ip 127.0.0.1 --port 8080 --key "my-secret-key" --num 1000 --size 1024
```

## Python Implementation

The Python implementation uses:
* Built-in `hmac` and `hashlib` modules for HMAC-SHA256
* Socket library for networking
* Time module for benchmarking

### Files:
1. `hmac_client.py` - Sends messages with HMAC authentication
2. `hmac_server.py` - Receives and verifies HMAC-authenticated messages

### Usage:

```bash
# Run server
python hmac_server.py --port 8080 --key "my-secret-key"

# Run client
python hmac_client.py --ip 127.0.0.1 --port 8080 --key "my-secret-key" --num 1000 --size 1024
```

## Benchmark Information

Both implementations provide detailed benchmarking data:
* Total processing time
* Average time per message
* HMAC calculation/verification time (as absolute time and percentage)
* Network I/O time

The benchmark data will help you compare the performance differences between C++ and Python for this specific HMAC processing task.
