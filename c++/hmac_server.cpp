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

// Convert hex string to binary
std::vector<unsigned char> hex_to_bin(const std::string& hex) {
    std::vector<unsigned char> binary;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte = hex.substr(i, 2);
        binary.push_back(static_cast<unsigned char>(std::stoi(byte, nullptr, 16)));
    }
    return binary;
}

int main(int argc, char* argv[]) {
    // Default parameters
    int port = 8080;
    std::string secret_key = "my-secret-key";
    
    // Parse command line arguments
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 < argc) {
            if (strcmp(argv[i], "--port") == 0) port = std::stoi(argv[i + 1]);
            else if (strcmp(argv[i], "--key") == 0) secret_key = argv[i + 1];
        }
    }
    
    // Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set socket options" << std::endl;
        return 1;
    }
    
    // Server address
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    // Bind socket to port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        return 1;
    }
    
    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        std::cerr << "Failed to listen" << std::endl;
        return 1;
    }
    
    std::cout << "Server listening on port " << port << std::endl;
    
    // Accept connections
    int addrlen = sizeof(address);
    int client_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    if (client_socket < 0) {
        std::cerr << "Failed to accept connection" << std::endl;
        return 1;
    }
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
    std::cout << "Client connected: " << client_ip << std::endl;
    
    // Benchmarking variables
    int message_count = 0;
    int valid_hmacs = 0;
    int invalid_hmacs = 0;
    std::chrono::duration<double, std::milli> total_time(0);
    std::chrono::duration<double, std::milli> verify_time(0);
    
    // Buffer for receiving messages
    std::vector<char> buffer(8192);
    
    while (true) {
        // Receive message
        auto start_time = std::chrono::high_resolution_clock::now();
        
        int bytes_received = recv(client_socket, buffer.data(), buffer.size(), 0);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                std::cout << "Client disconnected" << std::endl;
            } else {
                std::cerr << "Error receiving data" << std::endl;
            }
            break;
        }
        
        // Convert to string and parse
        std::string payload(buffer.data(), bytes_received);
        size_t delimiter_pos = payload.find(':');
        
        if (delimiter_pos == std::string::npos) {
            std::cerr << "Invalid message format" << std::endl;
            break;
        }
        
        std::string received_hmac_hex = payload.substr(0, delimiter_pos);
        std::string message = payload.substr(delimiter_pos + 1);
        
        // Verify HMAC
        auto verify_start = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> expected_hmac = calculate_hmac(message, secret_key);
        std::string expected_hmac_hex = bin_to_hex(expected_hmac);
        auto verify_end = std::chrono::high_resolution_clock::now();
        verify_time += verify_end - verify_start;
        
        // Check if HMACs match
        bool hmac_valid = (received_hmac_hex == expected_hmac_hex);
        if (hmac_valid) {
            valid_hmacs++;
        } else {
            invalid_hmacs++;
            std::cerr << "HMAC verification failed for message " << message_count << std::endl;
        }
        
        // Send acknowledgement
        std::string ack = hmac_valid ? "OK" : "FAIL";
        send(client_socket, ack.c_str(), ack.length(), 0);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        total_time += end_time - start_time;
        
        message_count++;
        
        if (message_count % 100 == 0) {
            std::cout << "Processed " << message_count << " messages..." << std::endl;
        }
    }
    
    // Print benchmark results
    std::cout << "\nBenchmark Results:" << std::endl;
    std::cout << "Total messages processed: " << message_count << std::endl;
    std::cout << "Valid HMACs: " << valid_hmacs << std::endl;
    std::cout << "Invalid HMACs: " << invalid_hmacs << std::endl;
    std::cout << "Total Time: " << total_time.count() << " ms" << std::endl;
    
    if (message_count > 0) {
        std::cout << "Average Time per Message: " << total_time.count() / message_count << " ms" << std::endl;
        std::cout << "HMAC Verification Time: " << verify_time.count() << " ms (" 
                  << (verify_time.count() / total_time.count() * 100) << "%)" << std::endl;
    }
    
    // Close sockets
    close(client_socket);
    close(server_fd);
    
    return 0;
}