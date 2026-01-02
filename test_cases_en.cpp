#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

// Include the single-header file you created
#include "SSLPROXY.hpp"

// ============================================================================
// Test Case Helper Function
// ============================================================================
void print_banner(const std::string& title) {
    std::cout << "\n==================================================" << std::endl;
    std::cout << "[TEST CASE] " << title << std::endl;
    std::cout << "==================================================" << std::endl;
}

// ============================================================================
// CASE 1: Simple TCP Port Forwarding (No SSL)
// Description: Forward incoming connections on local port 8080
//              to google.com:80 (or a specific IP)
// ============================================================================
void test_simple_tcp_forwarding() {
    print_banner("Simple TCP Forwarding");

    try {
        SSLPROXY::Config config;
        
        // Enable debug mode (for behavior verification)
        config.debug = true;
        config.debugLevel = 2;

        // Proxy specification: tcp [listen IP] [listen port] [target IP] [target port]
        // Example: 127.0.0.1:8080 -> 142.250.207.14:80 (Google IP example)
        config.proxySpecs.push_back("tcp 0.0.0.0 8080 142.250.207.14 80");

        // Create proxy object and run
        SSLPROXY proxy(config);
        
        std::cout << "Proxy running on port 8080... (Ctrl+C to stop)" << std::endl;
        proxy.run(); // Blocking call

    } catch (const std::exception& e) {
        std::cerr << "Failed: " << e.what() << std::endl;
    }
}

// ============================================================================
// CASE 2: HTTPS MITM (Man-In-The-Middle) Proxy
// Description: Intercepts and decrypts SSL connections on port 8443
//              (SNI-based routing)
// ============================================================================
void test_https_mitm() {
    print_banner("HTTPS MITM Proxy (SNI Mode)");

    try {
        SSLPROXY::Config config;
        config.debug = true;
        config.debugLevel = 3;

        // Certificate configuration (required)
        config.caCert = "ca.crt";
        config.caKey = "ca.key";
        config.leafCertDir = "./certs"; // Fake certificate storage

        // Proxy specification: https [listen IP] [listen port] sni [target port]
        // Destination server is determined based on client SNI (Server Name Indication)
        config.proxySpecs.push_back("https 0.0.0.0 8443 sni 443");

        SSLPROXY proxy(config);
        
        std::cout << "HTTPS MITM Proxy running on 8443..." << std::endl;
        std::cout << "Try: curl -v -k --resolve example.com:8443:127.0.0.1 https://example.com:8443" << std::endl;
        
        proxy.run();

    } catch (const std::exception& e) {
        std::cerr << "Failed: " << e.what() << std::endl;
        std::cerr << "Hint: Did you generate ca.crt and ca.key?" << std::endl;
    }
}

// ============================================================================
// CASE 3: Transparent Proxy (Linux Netfilter)
// Description: Handles traffic redirected via iptables
//              (Root privileges required)
// ============================================================================
void test_transparent_proxy() {
    print_banner("Transparent Proxy (Requires Root & iptables)");

    if (geteuid() != 0) {
        std::cerr << "Error: This test requires root privileges for NAT lookup." << std::endl;
        return;
    }

    try {
        SSLPROXY::Config config;
        config.debug = true;
        
        // NAT engine configuration
        config.natEngine = "netfilter"; // Linux iptables

        config.caCert = "ca.crt";
        config.caKey = "ca.key";
        
        // Proxy specification: https [listen IP] [listen port]
        // Destination IP is resolved by the NAT engine
        config.proxySpecs.push_back("https 0.0.0.0 3128"); 
        config.proxySpecs.push_back("http 0.0.0.0 3129");

        SSLPROXY proxy(config);
        
        std::cout << "Transparent Proxy running on 3128(HTTPS)/3129(HTTP)..." << std::endl;
        proxy.run();

    } catch (const std::exception& e) {
        std::cerr << "Failed: " << e.what() << std::endl;
    }
}

// ============================================================================
// CASE 4: Full Logging & Forensics (PCAP, Connection Log)
// Description: Saves all traffic to files and PCAP
// ============================================================================
void test_full_logging() {
    print_banner("Full Logging & Forensics");

    try {
        SSLPROXY::Config config;
        config.caCert = "ca.crt";
        config.caKey = "ca.key";
        config.proxySpecs.push_back("https 0.0.0.0 8443 sni 443");

        // Logging configuration
        config.connectLog = "./logs/connect.log";           // Connection summary log
        config.contentLog = "./logs/content/content.log";   // Decrypted payload log
        config.contentLogSpec = "%T-%S-%D.log";             // Log file naming format
        config.pcapLog = "./logs/pcap/traffic.pcap";        // Packet dump (for Wireshark)
        config.masterKeyLog = "./logs/master_keys.log";     // SSL master secrets (Wireshark decryption)

        SSLPROXY proxy(config);
        
        std::cout << "Logging Proxy running..." << std::endl;
        std::cout << "Logs will be saved in ./logs directory" << std::endl;
        
        proxy.run();

    } catch (const std::exception& e) {
        std::cerr << "Failed: " << e.what() << std::endl;
    }
}

// ============================================================================
// CASE 5: Singleton Violation Test (Stability Verification)
// Description: Verifies that creating two instances throws an exception
// ============================================================================
void test_singleton_safety() {
    print_banner("Singleton Safety Check");

    try {
        SSLPROXY::Config config;
        config.proxySpecs.push_back("tcp 0.0.0.0 9000 127.0.0.1 9001");

        std::cout << "Creating 1st Instance..." << std::endl;
        SSLPROXY proxy1(config); // Should succeed

        std::cout << "Creating 2nd Instance (Should Fail)..." << std::endl;
        SSLPROXY proxy2(config); // Should throw exception

    } catch (const std::exception& e) {
        std::cout << "SUCCESS: Caught expected exception: " << e.what() << std::endl;
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <test_case_number>" << std::endl;
        std::cout << "1: Simple TCP Forwarding" << std::endl;
        std::cout << "2: HTTPS MITM Proxy" << std::endl;
        std::cout << "3: Transparent Proxy (Root)" << std::endl;
        std::cout << "4: Full Logging" << std::endl;
        std::cout << "5: Singleton Safety Test" << std::endl;
        return 0;
    }

    int test_case = std::atoi(argv[1]);

    switch (test_case) {
        case 1: test_simple_tcp_forwarding(); break;
        case 2: test_https_mitm(); break;
        case 3: test_transparent_proxy(); break;
        case 4: test_full_logging(); break;
        case 5: test_singleton_safety(); break;
        default: std::cerr << "Invalid test case number." << std::endl;
    }

    return 0;
}
