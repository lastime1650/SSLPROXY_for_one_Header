#include "SSLPROXY.hpp"

#include <thread>
int main() {
    try {
        // 1. 설정 객체 생성
        SSLPROXY::Config config;

        // ---------------------------------------------------------
        // 명령어: -k ./NDR_SENSOR-FOR_XDR/Certs/default_sensor_private.key
        // 설명: CA 개인 키 파일 경로 설정
        // ---------------------------------------------------------
        config.caKey = "/root/VATEX/NDR_SENSOR-FOR_XDR/Certs/default_sensor_private.key";

        // ---------------------------------------------------------
        // 명령어: -c ./NDR_SENSOR-FOR_XDR/Certs/default_sensor_cert.crt
        // 설명: CA 인증서 파일 경로 설정
        // ---------------------------------------------------------
        config.caCert = "/root/VATEX/NDR_SENSOR-FOR_XDR/Certs/default_sensor_cert.crt";


        // 가짜 인증서 (필수 Cert의 개인키가 되어도된다. )
        config.leafKey = "/root/VATEX/NDR_SENSOR-FOR_XDR/Certs/default_sensor_private.key";//"/root/VATEX/NDR_SENSOR-FOR_XDR/Certs/default_leaf.key"; // 가상 인증서 ( )

        // ---------------------------------------------------------
        // 명령어: -P
        // 설명: Passthrough 모드 활성화 (복호화 실패 시 통과)
        // ---------------------------------------------------------
        config.passthrough = false;


        config.natEngine = "netfilter";

        // ---------------------------------------------------------
        // 명령어: -o MaxSSLProto=tls12 autossl 0.0.0.0 8443
        // 설명: 프록시 스펙 정의. 
        //       Config 구조체에 MaxSSLProto 필드가 없더라도, 
        //       스펙 문자열 뒤에 옵션을 붙여서 전달할 수 있습니다.
        // ---------------------------------------------------------
        std::string spec = "autossl 0.0.0.0 8443";
        config.proxySpecs.push_back(spec);
        // ---------------------------------------------------------
        // 명령어: -I dummy0
        // 설명: 미러링 인터페이스 설정.
        // 주의: 현재 제공된 SSLPROXY.hpp의 Config 구조체에는 mirrorIf 필드가 
        //       포함되어 있지 않습니다. 이 기능이 꼭 필요하다면 
        //       SSLPROXY.hpp의 Config 구조체와 생성자를 수정해야 합니다.
        // ---------------------------------------------------------
        // config.mirrorIf = "dummy0"; // (헤더 수정 필요)

        
        // 2. 추가 권장 설정 (권한 하락 및 로그)
        // 실제 운영 환경에서는 root 권한으로 포트를 연 뒤 nobody로 권한을 낮추는 것이 좋습니다.
        config.user = "nobody";
        config.group = "nobody";
        
        // 디버그 모드 활성화 (필요시)
        config.debug = true;
        config.debugLevel = 3;


        // 3. SSLPROXY 객체 초기화
        std::cout << "[*] Initializing SSLProxy..." << std::endl;
        std::cout << "    - CA Key: " << config.caKey << std::endl;
        std::cout << "    - CA Cert: " << config.caCert << std::endl;
        std::cout << "    - Passthrough: " << (config.passthrough ? "ON" : "OFF") << std::endl;
        std::cout << "    - Spec: " << spec << std::endl;

        SSLPROXY proxy(config);

        // 4. 프록시 실행 (블로킹 함수)
        std::cout << "[*] Proxy started. Press Ctrl+C to stop." << std::endl;

        proxy.run();

    } catch (const std::exception& e) {
        std::cerr << "[!] Fatal Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}