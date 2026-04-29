# SSL-Inspection-pseudocode

SSL inspection 구현에 대하여 연구하면서 만들었던 테스트 소스

## 개요

TLS 통신을 중간에서 가로채어 암/복호화하는 SSL inspection proxy 구현체입니다.
listen port로 연결이 들어오면 connect 주소로 연결을 맺고 TLS handshake를 진행하며 양단의 통신 내용을 중계합니다.

### 주요 기능

- SSL/TLS proxy (Man-in-the-Middle)
- SNI(Server Name Indication) 자동 감지: ClientHello를 peek하여 SNI hostname을 추출하고 per-session SSL_CTX 생성
- 자동 자체 서명 인증서 생성 (cert/key 파일 미지정 시)
- **TLS/TCP 자동 감지 모드** (`--auto-detect-tls`): accept 즉시 upstream TCP 연결 + 클라이언트 첫 바이트 peek를 동시에 수행하여 TLS이면 SSL MITM, non-TLS이면 plain TCP relay로 자동 전환
- AES 암/복호화 독립 구현 (AES-128/192/256, ECB/CFB8/OFB8/CBC/GCM 모드)
- SHA256 및 HMAC-SHA256 독립 구현
- TLS v1.2 Pseudo Random Function (PRF) 구현
- GHASH (GF(2^128) multiplication) 구현
- epoll 기반 다중 세션 처리
- Thread pool (worker별 epoll, CPU 수 기본값)
- kTLS 커널 레벨 암/복호화 오프로드 (OpenSSL 3.x+, Linux kTLS 지원 커널)
- splice(2) 기반 zero-copy 중계 (`--splice`, `--ktls` 필요)
- TPROXY 투명 프록시 모드 (`--tproxy`)
- OpenSSL ASYNC 모드 지원 (`-a`)
- TCP passthrough 모드 (`--nossl`)
- OpenSSL 엔진 지원 (OpenSSL < 3.x)

## 디렉토리 구조

```
ssl-inspection-pseudocode/
├── main.c               # 메인 소스 (thread-pool, epoll, async, SNI, TPROXY, auto-detect)
├── sslid-lib.c          # SSL inspection 라이브러리 (유틸리티, 소켓 헬퍼)
├── aes.c                # AES 암/복호화 구현 (ECB/CFB8/OFB8/CBC)
├── aes-gcm.c            # AES-GCM 구현
├── sha256.c             # SHA256, HMAC-SHA256, TLSv1.2 PRF 구현
├── ghash.c              # GHASH (GF(2^128)) 구현
├── test-vector.c        # 암호화 테스트 벡터
├── signal-handler.c     # 시그널 핸들러
├── include/
│   └── sslid-lib.h      # 공통 헤더 및 구조체 정의
├── misc/                # 참고 자료 (OpenSSL cnf, TLS 패킷 캡처 등)
├── openssl-aes-gcm-test-vector/  # OpenSSL AES-GCM 테스트 벡터 서브 프로젝트
├── Makefile
└── native_build.sh      # 로컬 빌드 스크립트
```

## 빌드 방법

```bash
cd trunk
make
```

병렬 빌드:

```bash
make -j$(nproc)
# 또는
./native_build.sh
```

### 빌드 옵션 (환경 변수)

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `DEF_ENABLE_TEST_VECTOR` | `yes` | 암호화 테스트 벡터 포함 여부 |
| `DEF_ENABLE_DPDK_LCORE` | `no` | DPDK lcore 맵핑 사용 여부 |
| `PKGCONF` | `pkg-config` | pkg-config 명령 경로 |
| `CROSS_COMPILE` | _(없음)_ | 크로스 컴파일 툴체인 prefix (예: `aarch64-marvell-linux-gnu-`) |

예시:

```bash
make -j$(nproc) DEF_ENABLE_TEST_VECTOR=no CROSS_COMPILE=aarch64-linux-gnu-
```

## 실행 방법

### 기본 실행

```bash
# 8443 포트로 수신하여 1.0.0.1:443으로 SSL inspection 중계
./sslid -p 8443 -B 1.0.0.1 -P 443
```

### TLS/TCP 자동 감지 모드 (--auto-detect-tls)

클라이언트가 TLS를 사용하는지 여부를 연결 수립 시 자동으로 판단합니다.

- **TLS 감지** → SSL MITM inspection 수행 (기존 동작과 동일)
- **non-TLS 감지** → plain TCP relay로 자동 전환
- **타임아웃** → 지정 시간 내 클라이언트 데이터가 오지 않으면 TCP relay 전환
  (SMTP/IMAP/POP3 등 서버가 먼저 말하는 프로토콜 대응)

```bash
# 기본 (peek timeout 3000ms)
./sslid -p 8443 -B 1.0.0.1 -P 443 --auto-detect-tls

# timeout 조정 (1초)
./sslid -p 8443 -B 1.0.0.1 -P 443 --auto-detect-tls --peek-timeout=1000

# TPROXY와 함께 사용
sudo ./sslid --tproxy -p 8443 -B 1.0.0.1 -P 443 --auto-detect-tls -v
```

#### 동작 원리 (Approach B: connect-then-peek)

```
Client accept
    │
    ├─── upstream TCP connect 시작 (비동기, 동시)
    │
    └─── client 첫 바이트 peek (MSG_PEEK)
              │
              ├─ TLS ClientHello 감지
              │       │
              │       └─ SSL MITM: per-SNI 인증서 생성 → SSL_accept / SSL_connect
              │
              ├─ non-TLS 데이터 감지
              │       │
              │       └─ TCP relay: 서버 배너(버퍼링된 경우) 포함 양방향 중계
              │
              └─ peek timeout (서버 선행 프로토콜 대응)
                      │
                      └─ TCP relay: 서버 배너 → 클라이언트 전달 후 양방향 중계
```

> **주의:** `--auto-detect-tls`와 `--nossl`은 함께 사용할 수 없습니다.

### TPROXY 투명 프록시 모드

```bash
# CAP_NET_ADMIN 권한 필요 (일반적으로 root)
# -B 가 함께 지정되면 자기 자신으로 오는 트래픽은 -B/-P로 fallback
sudo ./sslid --tproxy -p 8443 -B 1.0.0.1 -P 443 -v
```

`-v` 를 함께 주면 시작 시 아래와 같은 iptables/ip rule/firewalld mangle 설정 힌트를 출력합니다:

```
[TPROXY hint] Suggested mangle rules (bind=[0.0.0.0]:8443, connect=[1.0.0.1]:443):

  # 1. Policy routing (one-time):
  ip rule add fwmark 0x1/0x1 lookup 100
  ip route add local 0.0.0.0/0 dev lo table 100

  # 2. iptables:
  iptables -t mangle -A PREROUTING -p tcp -d 1.0.0.1 --dport 443 \
    -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8443 --on-ip 0.0.0.0

  # 3. firewalld (--direct):
  firewall-cmd --permanent --direct --add-rule ipv4 mangle PREROUTING 0 \
    -p tcp -d 1.0.0.1 --dport 443 \
    -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8443 --on-ip 0.0.0.0
  firewall-cmd --reload
```

### kTLS + splice zero-copy 모드

```bash
# OpenSSL 3.x+ 빌드, Linux kTLS 지원 커널 필요
./sslid -p 8443 -B 1.0.0.1 -P 443 --splice
# --splice 는 --ktls 를 자동으로 활성화합니다
```

## 옵션 전체 목록

```
-h, --help                  도움말
-q, --quiet                 출력 억제
-v, --verbose               상세 출력 (중복 사용 시 단계적으로 더 상세: -v, -vv, -vvv, ...)
-d, --debug=<flags>         디버그 플래그 (비트 마스크, 16진수 가능)
-e, --engine=<name>         OpenSSL 엔진 지정 (OpenSSL < 3.x 전용)
-b, --bind=<address>        바인드 주소 (기본: 0.0.0.0)
-p, --port=<port>           바인드 포트 (기본: 8443)
    --multi-listen          SO_REUSEPORT 사용: 모든 worker가 같은 포트를 공유 (커널 레벨 SYN 로드 밸런싱)
-l, --cipher-list=<string>  Cipher suite 제한 (기본: OpenSSL 기본값)
-c, --cert=<filename>       CA 인증서 파일 (미지정 시 자동 생성)
-k, --key=<filename>        CA 키 파일 (미지정 시 자동 생성)
-B, --connect=<address>     연결 대상 주소 (기본: 1.0.0.1)
                            --tproxy 와 함께 사용 시 self-address fallback 활성화
-P, --connect-port=<port>   연결 대상 포트 (기본: 443)
    --buffer-size=<bytes>   레코드 버퍼 크기 (기본: 16384, TLS 최대 레코드 크기)
-n, --no-thread             단일 worker 모드 (스레드 없음)
    --thread-pool=<count>   Worker 스레드 수 (기본: CPU 개수, 최대: 4096)
    --serialize-lock        SSL handshake 직렬화 잠금 사용
-a, --async                 OpenSSL ASYNC 모드 사용
    --nossl                 TCP proxy 모드 (SSL passthrough, TLS 처리 없음)
    --ktls                  kTLS 활성화: 커널 레벨 암/복호화 오프로드 (OpenSSL 3.x+)
    --splice                splice(2) zero-copy 중계 (--ktls 자동 활성화, OpenSSL 3.x+)
    --tproxy                투명 프록시 모드: accepted socket의 original dst 사용
                            (CAP_NET_ADMIN 필요, iptables TPROXY rule 및 policy routing 필요)
    --auto-detect-tls       연결별 TLS/TCP 자동 감지: accept 즉시 upstream TCP connect를
                            시작하고 동시에 클라이언트 첫 바이트를 peek하여 TLS이면 SSL
                            MITM, non-TLS이면 plain TCP relay로 자동 전환.
                            --nossl 과 함께 사용 불가.
    --peek-timeout=<ms>     --auto-detect-tls 사용 시 클라이언트 데이터 대기 최대 시간
                            (기본: 3000ms, 최대: 3600000ms).
                            타임아웃 시 TCP relay로 전환 (서버 선행 프로토콜 대응).
```

## 요구사항

| 항목 | 최소 버전 | 비고 |
|------|-----------|------|
| Linux | - | |
| GCC | - | |
| OpenSSL | 1.1.0+ | pkg-config로 자동 감지 |
| pthread | - | |
| OpenSSL (kTLS/splice) | 3.x+ | `--ktls`, `--splice` 옵션 |
| Linux 커널 (kTLS) | kTLS 지원 빌드 | `CONFIG_TLS=m/y` |
| DPDK | - | `DEF_ENABLE_DPDK_LCORE=yes` 시에만 필요 |
| CAP_NET_ADMIN | - | `--tproxy` 옵션 시 필요 |

## 라이선스

- Copyright (C) MINZKN.COM - All rights reserved.
- GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

## 저자

JaeHyuk Cho <minzkn@minzkn.com>
