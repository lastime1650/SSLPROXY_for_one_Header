#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

// 작성해주신 단일 헤더 파일 포함
#include "SSLPROXY.hpp"

// ============================================================================
// 테스트 케이스 도우미 함수
// ============================================================================
void print_banner(const std::string& title) {
    std::cout << "\n==================================================" << std::endl;
    std::cout << "[TEST CASE] " << title << std::endl;
    std::cout << "==================================================" << std::endl;
}

// ============================================================================
// CASE 1: 단순 TCP 포트 포워딩 (SSL 없음)
// 설명: 로컬 8080 포트로 들어오는 연결을 google.com:80(또는 특정 IP)으로 전달
// ============================================================================
void test_simple_tcp_forwarding() {
    print_banner("Simple TCP Forwarding");

    try {
        SSLPROXY::Config config;
        
        // 디버그 모드 활성화 (동작 확인용)
        config.debug = true;
        config.debugLevel = 2;

        // 프록시 스펙: tcp [리스닝IP] [리스닝포트] [대상IP] [대상포트]
        // 예: 127.0.0.1:8080 -> 142.250.207.14:80 (Google IP 예시)
        config.proxySpecs.push_back("tcp 0.0.0.0 8080 142.250.207.14 80");

        // 객체 생성 및 실행
        SSLPROXY proxy(config);
        
        std::cout << "Proxy running on port 8080... (Ctrl+C to stop)" << std::endl;
        proxy.run(); // Blocking Call

    } catch (const std::exception& e) {
        std::cerr << "Failed: " << e.what() << std::endl;
    }
}

// ============================================================================
// CASE 2: HTTPS MITM (Man-In-The-Middle) 프록시
// 설명: 8443 포트로 들어오는 SSL 연결을 가로채고 복호화함 (SNI 기반 라우팅)
// ============================================================================
void test_https_mitm() {
    print_banner("HTTPS MITM Proxy (SNI Mode)");

    try {
        SSLPROXY::Config config;
        config.debug = true;
        config.debugLevel = 3;

        // 인증서 설정 (필수)
        config.caCert = "ca.crt";
        config.caKey = "ca.key";
        config.leafCertDir = "./certs"; // 가짜 인증서 저장소

        // 프록시 스펙: https [리스닝IP] [리스닝포트] sni [대상포트]
        // 클라이언트가 보내는 SNI(Server Name Indication)를 보고 대상 서버 결정
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
// CASE 3: 투명 프록시 (Transparent Proxy, Linux Netfilter)
// 설명: iptables로 리다이렉트된 트래픽을 처리 (Root 권한 필요)
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
        
        // NAT 엔진 설정
        config.natEngine = "netfilter"; // Linux iptables

        config.caCert = "ca.crt";
        config.caKey = "ca.key";
        
        // 프록시 스펙: https [리스닝IP] [리스닝포트] (NAT 엔진이 목적지 IP 조회)
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
// CASE 4: 전체 로깅 및 포렌식 (PCAP, Connection Log)
// 설명: 모든 트래픽을 파일 및 PCAP으로 저장
// ============================================================================
void test_full_logging() {
    print_banner("Full Logging & Forensics");

    try {
        SSLPROXY::Config config;
        config.caCert = "ca.crt";
        config.caKey = "ca.key";
        config.proxySpecs.push_back("https 0.0.0.0 8443 sni 443");

        // 로깅 설정
        config.connectLog = "./logs/connect.log";           // 연결 요약 로그
        config.contentLog = "./logs/content/content.log";   // 복호화된 페이로드 로그
        config.contentLogSpec = "%T-%S-%D.log";             // 로그 파일명 포맷
        config.pcapLog = "./logs/pcap/traffic.pcap";        // 패킷 덤프 (Wireshark용)
        config.masterKeyLog = "./logs/master_keys.log";     // SSL Master Secret (Wireshark 복호화용)

        SSLPROXY proxy(config);
        
        std::cout << "Logging Proxy running..." << std::endl;
        std::cout << "Logs will be saved in ./logs directory" << std::endl;
        
        proxy.run();

    } catch (const std::exception& e) {
        std::cerr << "Failed: " << e.what() << std::endl;
    }
}

// ============================================================================
// CASE 5: 싱글톤 위반 테스트 (안정성 검증)
// 설명: 두 개의 인스턴스를 생성하려 할 때 예외가 발생하는지 확인
// ============================================================================
void test_singleton_safety() {
    print_banner("Singleton Safety Check");

    try {
        SSLPROXY::Config config;
        config.proxySpecs.push_back("tcp 0.0.0.0 9000 127.0.0.1 9001");

        std::cout << "Creating 1st Instance..." << std::endl;
        SSLPROXY proxy1(config); // 성공해야 함

        std::cout << "Creating 2nd Instance (Should Fail)..." << std::endl;
        SSLPROXY proxy2(config); // 예외 발생해야 함

    } catch (const std::exception& e) {
        std::cout << "SUCCESS: Caught expected exception: " << e.what() << std::endl;
    }
}

// ============================================================================
// Main Entry
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