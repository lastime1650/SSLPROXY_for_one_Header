# What is it? 

This is the one-wrapping to use the [SSLproxy project](https://github.com/sonertari/SSLproxy) as a development environment.

Use Examples:

- 1. Queue-based decryption packet extraction (this is to get decrypted packets as quickly as possible)
- 2. Use in class format
- 3. DPI Deep Packet Inspection with Application Layer

# Explain

`SSLPROXY` 코드를 빌드하고 실행하기 위해서는 **C++ 컴파일러**, **OpenSSL**, **Libevent**, **Libpcap**, **Libnet**, **SQLite3**, 그리고 **PcapPlusPlus** 라이브러리가 필요합니다.



---

# SSLProxy 구축 및 실행 가이드

## 1. 필수 패키지 설치

운영체제별로 패키지 관리자가 다르므로 환경에 맞춰 설치하십시오.

### 🐧 Ubuntu (Debian 계열)

```bash
# 1. 패키지 목록 업데이트
sudo apt-get update

# 2. 빌드 도구 설치 (g++, make, cmake 등)
sudo apt-get install -y build-essential cmake git

# 3. 필수 라이브러리 개발 헤더 설치
# - libssl-dev: OpenSSL
# - libevent-dev: Libevent (비동기 네트워크)
# - libpcap-dev: Libpcap (패킷 캡처)
# - libnet1-dev: Libnet (패킷 생성/미러링)
# - libsqlite3-dev: SQLite3 (사용자 인증 DB)
sudo apt-get install -y libssl-dev libevent-dev libpcap-dev libnet1-dev libsqlite3-dev
```

### 🐂 Rocky Linux / CentOS (RHEL 계열)

RHEL 계열은 일부 패키지(`libnet` 등)가 기본 저장소에 없으므로 **EPEL** 저장소가 필요합니다.

```bash
# 1. EPEL 저장소 및 CRB(Code Ready Builder) 활성화
sudo dnf install -y epel-release
sudo dnf config-manager --set-enabled crb  # Rocky 9 / Alma 9
# (Rocky 8의 경우: sudo dnf config-manager --set-enabled powertools)

# 2. 빌드 도구 설치
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y cmake git

# 3. 필수 라이브러리 개발 헤더 설치
sudo dnf install -y openssl-devel libevent-devel libpcap-devel libnet-devel sqlite-devel
```

---

## 2. PcapPlusPlus 설치 (공통)

**PcapPlusPlus**는 패키지 관리자에서 직접 제공하지 않거나 버전이 낮을 수 있으므로, 소스 코드를 받아 빌드하여 설치하는 것이 가장 확실합니다.

```bash
# 1. 소스 코드 다운로드
git clone https://github.com/seladb/PcapPlusPlus.git
cd PcapPlusPlus

# 2. 구성 (Configuration)
# 리눅스 기본 설정을 따릅니다.
./configure-linux.sh --default

# 3. 빌드 및 설치
make all
sudo make install

# 4. (선택사항) 라이브러리 캐시 갱신
sudo ldconfig
```

---

## 3. 인증서 및 키 생성

SSLProxy가 MitM(Man-in-the-Middle)을 수행하려면 **CA(Certificate Authority)** 인증서와 **Leaf Key(단말 키)**가 필요합니다.

```bash
# 작업 디렉토리 생성 (예시)
mkdir -p certs
cd certs

# 1. CA 개인키 생성 (비밀번호 없이)
openssl genrsa -out ca.key 2048

# 2. CA 인증서 생성 (브라우저에 등록할 파일)
# Common Name 등을 적절히 입력하거나 Enter로 넘깁니다.
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=MyOrg/CN=MySSLProxyCA"

# 3. Leaf Key 생성 (가짜 인증서 발급용 공통 키)
openssl genrsa -out leaf.key 2048
```

> **주의:** 생성된 `ca.crt`, `ca.key`, `leaf.key`의 **절대 경로**를 코드 상의 `config`에 정확히 입력해야 합니다.

---

## 4. 소스 코드 컴파일

작성하신 `main.cpp` (SSLPROXY.hpp 포함)를 컴파일합니다. 링크해야 할 라이브러리가 많습니다.

```bash
# 컴파일 명령어
g++ -o sslproxy main.cpp \
    -lssl -lcrypto \
    -levent -levent_openssl -levent_pthreads \
    -lpcap \
    -lnet \
    -lsqlite3 \
    -lPcap++ -lPacket++ -lCommon++ \
    -lpthread \
    -std=c++17
```

*   **-lssl -lcrypto**: OpenSSL
*   **-levent ...**: Libevent (Core, OpenSSL, Pthreads 모듈)
*   **-lpcap**: Libpcap
*   **-lnet**: Libnet
*   **-lsqlite3**: SQLite3
*   **-lPcap++ ...**: PcapPlusPlus
*   **-lpthread**: POSIX 스레드

---

## 5. 네트워크 설정 (Transparent Proxy)

`config.natEngine = "netfilter"`를 사용하므로, **iptables**를 통해 트래픽을 프록시로 납치(Redirection)해야 합니다.

> **⚠️ 중요:** SSH(22번 포트) 접속이 끊기지 않도록 주의하십시오. 테스트 시에는 가급적 콘솔 접근이 가능한 환경이나 안전장치를 마련하십시오.

```bash
# 1. IP 포워딩 활성화 (필요한 경우)
sudo sysctl -w net.ipv4.ip_forward=1

# 2. iptables 설정 (root 권한 필요)
# 80(HTTP), 443(HTTPS) 트래픽을 8443(프록시 포트)으로 리다이렉트

# [외부에서 들어오는 트래픽 처리 (PREROUTING)]
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8443
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443

# [로컬(나 자신)에서 나가는 트래픽 처리 (OUTPUT)]
# 무한 루프 방지를 위해 SSLProxy를 실행하는 사용자(예: root)는 제외해야 함.
# 만약 SSLProxy를 특정 유저(예: nobody)로 실행한다면 해당 유저를 제외.

# 예: root가 실행하는 경우 (비권장하지만 테스트용) - mark 등을 써야하지만 간단히 owner 모듈 사용
# 주의: 이 설정은 root가 wget/curl을 쓸 때도 납치됩니다. 프록시 프로세스만 제외하려면 복잡해짐.
# 가장 좋은 방법은 프록시를 별도 계정(proxyuser)으로 실행하고 그 유저를 제외하는 것입니다.
# sudo iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner proxyuser --dport 443 -j REDIRECT --to-port 8443

# 3. QUIC(UDP/443) 차단 (브라우저가 TCP로 접속하게 유도)
sudo iptables -I FORWARD -p udp --dport 443 -j DROP
sudo iptables -I OUTPUT -p udp --dport 443 -j DROP
```

---

## 6. 실행

```bash
# root 권한으로 실행 (포트 바인딩 및 iptables 룰 적용을 위해)
sudo ./sslproxy
```

### 실행 전 체크리스트
1.  `config.proxySpecs`에 `"https 0.0.0.0 8443"` 등이 올바르게 설정되었는가?
2.  `config.caKey`, `config.caCert`, `config.leafKey` 경로가 정확한가?
3.  `iptables`가 설정되었고, UDP 443이 차단되었는가?
4.  클라이언트(브라우저)에 `ca.crt`를 **신뢰할 수 있는 루트 인증 기관**으로 등록했는가?