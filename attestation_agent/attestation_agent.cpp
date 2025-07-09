#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <cstring>
#include <chrono>
#include <thread>
#include <random>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libs/json.hpp"
#include "libs/base64.hpp"

// Include the necessary headers from the keystone driver
#include "../sdk/include/shared/keystone_user.h"

using json = nlohmann::json;

#define KEYSTONE_DEV_PATH "/dev/keystone_enclave"
#define VERIFIER_IP "192.168.100.2"    // QEMU gateway
#define VERIFIER_PORT 8087             // Same port as verifier

// commands
enum class Command : uint8_t {
    PERFORM_ATTESTATION = 0x01,
    GET_DICE_CERT_CHAIN = 0x02,
    UNKNOWN             = 0xFF
};

// Data structure to exchange messages with the verifier
struct Message {
    uint8_t command;
    uint32_t length;
} __attribute__((packed));


class AttestationAgent {
private:
    int keystone_fd;
    int verifier_sock;
    bool connected;

    std::string base64_encode(const unsigned char* buffer, size_t length) {
        return base64::to_base64(std::string(reinterpret_cast<const char*>(buffer), length));
    }

    bool connect_to_verifier() {
        verifier_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (verifier_sock < 0) {
            std::cerr << "[AGENT] Failed to create socket" << std::endl;
            return false;
        }
        
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(VERIFIER_PORT);
        
        if (inet_pton(AF_INET, VERIFIER_IP, &server_addr.sin_addr) <= 0) {
            std::cerr << "[AGENT] Invalid verifier IP address" << std::endl;
            close(verifier_sock);
            return false;
        }
        
        if (connect(verifier_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "[AGENT] Failed to connect to verifier" << std::endl;
            close(verifier_sock);
            return false;
        }
        
        connected = true;
        std::cout << "[AGENT] Connected to verifier at " << VERIFIER_IP << ":" << VERIFIER_PORT << std::endl;
        return true;
    }

    bool send_json(const json& j, bool is_attestation = false) {
        if (!connected)
            return false;
            
        std::string json_str = j.dump();
        uint32_t report_len  = json_str.length();

        // 1. Send the length of the data structure first
        if (send(verifier_sock, &report_len, sizeof(report_len), 0) < 0) {
            std::cerr << "[AGENT] Failed to send payload length" << std::endl;
            connected = false;
            return false;
        }

        // 2. Send the actual data
        ssize_t sent = send(verifier_sock, json_str.c_str(), report_len, 0);
        if (sent < 0 || (uint32_t)sent != report_len) {
            std::cerr << "[AGENT] Failed to send full payload data" << std::endl;
            connected = false;
            return false;
        }

        if (is_attestation)
            std::cout << "[AGENT] Sent attestation report (" << sent << " bytes) to verifier" << std::endl;
        else
            std::cout << "[AGENT] Sent DICE certificate chain (" << sent << " bytes) to verifier" << std::endl;

        return true;
    }

    bool send_dice_cert_chain(const keystone_ioctl_dice_cert_chain& cert_chain) {
        if (!connected) {
            std::cerr << "[AGENT] Not connected to verifier" << std::endl;
            return false;
        }

        json report;
        json certs_array = json::array();
        for (int i = 0; i < 4; ++i) {
            if (cert_chain.certs_len[i] > 0) {
                json cert_obj;
                cert_obj["cert_b64"] = base64_encode(cert_chain.certs[i], cert_chain.certs_len[i]);
                cert_obj["length"] = cert_chain.certs_len[i];
                certs_array.push_back(cert_obj);
            }
        }

        report["dice_cert_chain"]["man"]    = certs_array[0];
        report["dice_cert_chain"]["root"]   = certs_array[1];
        report["dice_cert_chain"]["sm"]     = certs_array[2];
        report["dice_cert_chain"]["lak"]    = certs_array[3];
        report["dice_cert_chain"]["uuid_b64"] = base64_encode(cert_chain.uuid, UUID_LEN);

        return send_json(report, false);
    }
    
    bool send_attestation_report(const keystone_ioctl_runtime_attestation& attestation) {
        if (!connected) {
            std::cerr << "[AGENT] Not connected to verifier" << std::endl;
            return false;
        }

        json report;
        report["enclave"] = {
            {"hash_b64", base64_encode(attestation.enclave.hash, MDSIZE)},
            {"signature_b64", base64_encode(attestation.enclave.signature, SIGNATURE_SIZE)},
            {"uuid_b64", base64_encode(attestation.enclave.uuid, UUID_LEN)},
        };
        report["sm"] = {
            {"hash_b64", base64_encode(attestation.sm.hash, MDSIZE)},
            {"public_key_b64", base64_encode(attestation.sm.public_key, PUBLIC_KEY_SIZE)},
            {"signature_b64", base64_encode(attestation.sm.signature, SIGNATURE_SIZE)}
        };
        report["dev_public_key_b64"] = base64_encode(attestation.dev_public_key, PUBLIC_KEY_SIZE);
        report["nonce_b64"] = base64_encode(attestation.nonce, NONCE_LEN);

        return send_json(report, true);
    }

    bool receive_message(uint8_t& command, std::vector<char>& payload) {
        Message msg;
        ssize_t received = recv(verifier_sock, &msg, sizeof(msg), 0);
        if (received <= 0) {
            if (received == 0)
                std::cout << "[AGENT] Verifier disconnected" << std::endl;
            else
                std::cerr << "[AGENT] Failed to receive command header" << std::endl;
            
            connected = false;
            return false;
        }

        command = msg.command;
        uint32_t length = msg.length;
        
        if (length > 0) {
            payload.resize(length);
            ssize_t payload_received = recv(verifier_sock, payload.data(), length, 0);
            if (payload_received != length) {
                std::cerr << "[AGENT] Failed to receive full payload" << std::endl;
                return false;
            }
        }
        
        std::cout << "[AGENT] Received command " << std::hex << (int)command << " with payload length " << std::dec << length << std::endl;
        return true;
    }

    bool get_dice_cert_chain(const std::string& uuid, keystone_ioctl_dice_cert_chain& cert_chain) {
        memset(&cert_chain, 0, sizeof(cert_chain));

        // Use the UUID received from the verifier
        if (uuid.length() != UUID_LEN - 1) {
            std::cerr << "[AGENT] Invalid UUID provided" << std::endl;
            return false;
        }
        memcpy(cert_chain.uuid, uuid.c_str(), UUID_LEN);

        int ret = ioctl(keystone_fd, KEYSTONE_IOC_GET_LAK_CERT, &cert_chain);
        if (ret < 0)
            std::cerr << "[AGENT] Failed to get DICE certificate chain" << std::endl;
        else
            std::cout << "[AGENT] Successfully retrieved DICE certificate chain" << std::endl;

        return true;
    }

    bool perform_attestation(const std::string& nonce, const std::string& uuid, keystone_ioctl_runtime_attestation& attestation) {
        memset(&attestation, 0, sizeof(attestation));

        if (nonce.length() != NONCE_LEN) {
            std::cerr << "[AGENT] Invalid nonce provided for attestation" << std::endl;
            return false;
        }

        if (uuid.length() != UUID_LEN - 1) {
            std::cerr << "[AGENT] Invalid UUID provided for attestation" << std::endl;
            return false;
        }
        
        memcpy(attestation.nonce, nonce.c_str(), NONCE_LEN);
        memcpy(attestation.enclave.uuid, uuid.c_str(), UUID_LEN);

        int ret = ioctl(keystone_fd, KEYSTONE_IOC_RUNTIME_ATTESTATION, &attestation);
        if (ret < 0)
            std::cerr << "[AGENT] Failed to perform runtime attestation" << std::endl;
        else {
            std::cout << "[AGENT] Runtime attestation round completed [enclave " << "123e4567-e89b-12d3-a456-426614174000]" << std::endl;
            // std::cout << "[AGENT] Enclave hash: ";
            // print_hash(attestation);
        }

        return true;
    }
    
    void print_hash(const keystone_ioctl_runtime_attestation& attestation) {
        for (int i = 0; i < 64; ++i)
            printf("%02x", attestation.enclave.hash[i]);
        std::cout << std::endl;
    }
    
    void cleanup() {
        if (verifier_sock >= 0) {
            close(verifier_sock);
            verifier_sock = -1;
        }
        if (keystone_fd >= 0) {
            close(keystone_fd);
            keystone_fd = -1;
        }
        connected = false;
    }

public:
    AttestationAgent() : keystone_fd(-1), verifier_sock(-1), connected(false) {}
    
    ~AttestationAgent() {
        cleanup();
    }

    bool initialize() {
        // Open Keystone device
        keystone_fd = open(KEYSTONE_DEV_PATH, O_RDWR);
        if (keystone_fd < 0) {
            std::cerr << "[AGENT] Failed to open " << KEYSTONE_DEV_PATH << std::endl;
            return false;
        }
        
        if (!connect_to_verifier())
            return false;
        
        return true;
    }

    void run() {
        std::cout << "[AGENT] Starting attestation agent" << std::endl;
        std::cout << "[AGENT] Waiting for commands from verifier..." << std::endl;
        
        while (true) {
            if (!connected) {
                std::cout << "[AGENT] Not connected, attempting to reconnect..." << std::endl;
                if (!connect_to_verifier()) {
                    std::cout << "[AGENT] Reconnection failed, waiting..." << std::endl;
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }
            }

            // Wait for command
            fd_set readfds;
            struct timeval timeout;
            FD_ZERO(&readfds);
            FD_SET(verifier_sock, &readfds);
            timeout.tv_sec = 1;  // 1 second timeout
            timeout.tv_usec = 0;

            int activity = select(verifier_sock + 1, &readfds, nullptr, nullptr, &timeout);            
            if (activity > 0 && FD_ISSET(verifier_sock, &readfds)) {
                uint8_t command;
                std::vector<char> payload;

                if (receive_message(command, payload)) {
                    if (command == static_cast<uint8_t>(Command::PERFORM_ATTESTATION)) {
                        try {
                            json parsed_payload = json::parse(payload);
                            std::string nonce_b64 = parsed_payload["nonce_b64"];
                            std::string uuid_b64 = parsed_payload["uuid_b64"];
                            
                            keystone_ioctl_runtime_attestation attestation;
                            if (perform_attestation(
                                    base64::from_base64(nonce_b64), 
                                    base64::from_base64(uuid_b64),
                                    attestation
                                )) {
                                send_attestation_report(attestation);
                            }

                        } catch (const json::exception& e) {
                            std::cerr << "[AGENT] Failed to parse attestation command JSON: " << e.what() << std::endl;
                        }

                    } else if (command == static_cast<uint8_t>(Command::GET_DICE_CERT_CHAIN)) {
                        try {
                            json parsed_payload = json::parse(payload);
                            std::string uuid_b64 = parsed_payload["uuid_b64"];

                            keystone_ioctl_dice_cert_chain cert_chain;
                            if (get_dice_cert_chain(base64::from_base64(uuid_b64), cert_chain))
                                send_dice_cert_chain(cert_chain);
                        } catch (const json::exception& e) {
                            std::cerr << "[AGENT] Failed to parse cert chain command JSON: " << e.what() << std::endl;
                        }
                    } else {
                        std::cout << "[AGENT] Unknown command received: 0x" << std::hex << (int)command << std::dec << std::endl;
                    }
                } else {
                    connected = false;
                }
            } else if (activity < 0) {
                std::cerr << "[AGENT] Select error, connection may be lost" << std::endl;
                connected = false;
            }
        }
    }
};

int main() {
    AttestationAgent agent;
    
    if (!agent.initialize()) {
        std::cerr << "[AGENT] Failed to initialize" << std::endl;
        return 1;
    }
    
    try {
        agent.run();
    } catch (const std::exception& e) {
        std::cerr << "[AGENT] Exception: " << e.what() << std::endl;
    }
    
    return 0;
}