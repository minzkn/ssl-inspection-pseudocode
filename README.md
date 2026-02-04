# SSL-Inspection-pseudocode

SSL inspection 구현에 대하여 연구하면서 만들었던 테스트 소스

## 개요

TLS 통신을 중간에서 가로채어 암/복호화하는 SSL inspection proxy 구현체입니다.
listen port로 연결이 들어오면 connect 주소로 연결을 맺고 TLS handshake를 진행하며 양단의 통신 내용을 중계합니다.

### 주요 기능

- SSL/TLS proxy 기능 (Man-in-the-Middle)
- AES 암/복호화 독립 구현 (AES-128/192/256, ECB/CFB8/OFB8/CBC/GCM 모드)
- SHA256 및 HMAC-SHA256 독립 구현
- TLS v1.2 Pseudo Random Function (PRF) 구현
- GHASH (GF(2^128) multiplication) 구현

## 디렉토리 구조

```
ssl-inspection-pseudocode/
├── main.c               # 메인 소스 (thread-pool, async mode 지원)
├── sslid-lib.c          # SSL inspection 라이브러리
├── aes.c                # AES 암/복호화 구현
├── aes-gcm.c            # AES-GCM 구현
├── sha256.c             # SHA256, HMAC-SHA256, PRF 구현
├── ghash.c              # GHASH 구현
├── test-vector.c        # 암호화 테스트 벡터
├── signal-handler.c     # 시그널 핸들러
├── include/             # 헤더 파일
├── misc/                # 참고 자료
└── openssl-aes-gcm-test-vector/  # OpenSSL AES-GCM 테스트
```

## 빌드 방법

```bash
cd trunk
make

# 환경 변수 옵션
# DEF_ENABLE_TEST_VECTOR=<yes|no>       - Test-Vector 테스트 포함 유무
# DEF_ENABLE_DPDK_LCORE=<yes|no>        - DPDK lcore 맵핑 사용 유무
# PKGCONF=<pkg-config>                  - pkg-config 명령 경로
# CROSS_COMPILE=<toolchain prefix>      - 크로스 컴파일 (예: aarch64-marvell-linux-gnu-)
```

## 실행 방법

### 기본 실행

```bash
# 8443 포트로 수신하여 1.0.0.1:443으로 중계
./sslid -p 8443 -B 1.0.0.1 -P 443
```

### 주요 옵션

```
-h, --help                  도움말
-v, --verbose               상세 출력 (여러 번 사용 시 더 상세)
-b, --bind=<address>        바인드 주소
-p, --port=<port>           바인드 포트
-B, --connect=<address>     연결 대상 주소
-P, --connect-port=<port>   연결 대상 포트
-l, --cipher-list=<string>  Cipher suite 제한
-c, --cert=<filename>       CA 인증서 파일
-k, --key=<filename>        CA 키 파일
```

### trunk 전용 옵션

```
-n, --no-thread             단일 프로세스 모드
--thread-pool=<count>       Thread pool 개수 (기본: CPU 개수)
--multi-listen              Worker별 추가 listen 포트 사용
--serialize-lock            SSL handshake 직렬화
-a, --async                 ASYNC 모드 사용
--nossl                     TCP proxy 모드 (SSL passthrough)
-e, --engine=<name>         OpenSSL 엔진 지정
```

### 예전 tag/20240624 전용 옵션 (kTLS) deprecated

```
--ktls                      kTLS 활성화 (커널 레벨 암/복호화)
```

## 요구사항

- Linux (tag/20240624의 kTLS는 커널 4.19 이상 필요)
- GCC
- OpenSSL 개발 라이브러리 (trunk) 또는 번들 사용 (tag/20240624)
- pthread

## 라이선스

- Copyright (C) MINZKN.COM - All rights reserved.
- GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

## 저자

JaeHyuk Cho <minzkn@minzkn.com>
