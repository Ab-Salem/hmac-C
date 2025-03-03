#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <cstring>
#include <openssl/hmac.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

// HMAC calculation function
std::vector<unsigned char> calculate_hmac(const std::string& message, const std::string& key) {
    unsigned int len = EVP_MAX_MD_SIZE;
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.c_str(), key.length(), EVP_sha256(), nullptr);
    HMAC_Update(ctx, reinterpret_cast<const unsigned char*>(message.c_str()), message.length());
    HMAC_Final(ctx, digest.data(), &len);
    HMAC_CTX_free(ctx);
    
    digest.resize(len);
    return digest;
}

// Convert binary to hex string
std::string bin_to_hex(const std::vector<unsigned char>& binary) {
    std::string hex;
    char hex_byte[3];
    for (auto byte : binary) {
        sprintf(hex_byte, "%02x", byte);
        hex += hex_byte;
    }
    return hex;
}

int main(int argc, char* argv[]) {
    // Default parameters
    std::string server_ip = "127.0.0.1";
    int port = 8080;
    std::string secret_key = "my-secret-key";
    int num_messages = 1000;
    int message_size = 1024;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 < argc) {
            if (strcmp(argv[i], "--ip") == 0) server_ip = argv[i + 1];
            else if (strcmp(argv[i], "--port") == 0) port = std::stoi(argv[i + 1]);
            else if (strcmp(argv[i], "--key") == 0) secret_key = argv[i + 1];
            else if (strcmp(argv[i], "--num") == 0) num_messages = std::stoi(argv[i + 1]);
            else if (strcmp(argv[i], "--size") == 0) message_size = std::stoi(argv[i + 1]);
        }
    }
    
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }
    
    // Server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Convert IP address to binary form
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address or address not supported" << std::endl;
        return 1;
    }
    
    // Connect to the server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return 1;
    }
    
    std::cout << "Connected to server " << server_ip << ":" << port << std::endl;
    
    // Generate a message of specified size filled with 'A's
    std::string message(message_size, 'A');
    
    // Benchmarking variables
    std::chrono::duration<double, std::milli> total_time(0);
    std::chrono::duration<double, std::milli> hmac_time(0);
    std::chrono::duration<double, std::milli> send_time(0);
    
    std::cout << "Starting benchmark: sending " << num_messages 
              << " messages of size " << message_size << " bytes" << std::endl;
    
    // Send messages and measure time
    for (int i = 0; i < num_messages; ++i) {
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Calculate HMAC
        auto hmac_start = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> hmac = calculate_hmac(message, secret_key);
        auto hmac_end = std::chrono::high_resolution_clock::now();
        hmac_time += hmac_end - hmac_start;
        
        // Convert HMAC to hex string
        std::string hmac_hex = bin_to_hex(hmac);
        
        // Prepare message with HMAC: [hmac_hex]:[message]
        std::string payload = hmac_hex + ":" + message;
        
        // Send the message
        auto send_start = std::chrono::high_resolution_clock::now();
        int bytes_sent = send(sock, payload.c_str(), payload.length(), 0);
        if (bytes_sent < 0) {
            std::cerr << "Failed to send message" << std::endl;
            break;
        }
        
        // Receive ack
        char buffer[16];
        int bytes_received = recv(sock, buffer, sizeof(buffer), 0);
        if (bytes_received < 0) {
            std::cerr << "Failed to receive acknowledgement" << std::endl;
            break;
        }
        
        auto send_end = std::chrono::high_resolution_clock::now();
        send_time += send_end - send_start;
        
        auto end_time = std::chrono::high_resolution_clock::now();
        total_time += end_time - start_time;
        
        if (i % 100 == 0) {
            std::cout << "Processed " << i << " messages..." << std::endl;
        }
    }
    
    // Print benchmark results
    std::cout << "\nBenchmark Results:" << std::endl;
    std::cout << "Total Time: " << total_time.count() << " ms" << std::endl;
    std::cout << "Average Time per Message: " << total_time.count() / num_messages << " ms" << std::endl;
    std::cout << "HMAC Calculation Time: " << hmac_time.count() << " ms (" 
              << (hmac_time.count() / total_time.count() * 100) << "%)" << std::endl;
    std::cout << "Network I/O Time: " << send_time.count() << " ms (" 
              << (send_time.count() / total_time.count() * 100) << "%)" << std::endl;
    
    // Close the socket
    close(sock);
    
    return 0;
}