# SSL-Inspection-pseudocode

SSL inspection 구현에 대하여 연구하면서 만들었던 테스트 소스
* kTLS 지원 (Linux kernel level 에서 암/복호화를 수행하도록 제어, 최소 Linux kernel v4.19 이상 필요)
* OpenSSL v1.1.1 build 포함
* AES 암/복호화 별도 독립 구현 포함. (AES-GCM 구현 포함)
* SHA256 및 HMAC 독립 구현 포함. (TLS v1.2 pseudo random function 포함)
* 단순 SSL proxy 수준의 구현상태이며 kTLS 동작을 실제로 확인할 수 있는 정도의 구현입니다.
* 소스 빌드 HOWTO
<pre>
    > 요구사항
      1) 동작 환경은 적어도 Linux kernel v4.19.0 이상이 필요합니다.
      2) Ubuntu 18.04 LTS 배포판의 경우 하기 링크를 참고하면 Linux kernel 4.19 로 반영해 볼 수 있습니다.
         http://ubuntuhandbook.org/index.php/2018/10/linux-kernel-4-19-released-install-ubuntu/
      3) OpenSSL 은 현재 첨부 소스내에 "OpenSSL v1.1.1u" 이 함께 빌드내에 포함되어 static link 됩니다.
         OpenSSL 1.1.x 는 현재 kTLS 반영하기 어렵습니다. (handshake 결과에 대한 파라미터를 완전하게 뽑아낼 수 있는 방법이 아직 미지수)
    > 빌드 방법
      $ make
</pre>
* listen port 로 연결이 들어오면 connect 주소로 연결을 맺고 TLS hand shake 를 진행하며 양단의 통신 내용이 그대로 콘솔로 출력되는 정도의 구현체
<pre>
  - 실행방법
    만약 8443 포트로 접속이 들어오면 1.0.0.1:443 으로 연결을 중계하도록 하고 kTLS를 활성화하려면 하기와 같이 실행합니다.
      $ ./sslid -v --ktls -p 8443 -B 1.0.0.1 -P 443

      "-v" 옵션은 내부적으로 EVP interface를 이용한 AES-128-GCM 을 OpenSSL에서 제대로 처리하는지를 검증하는 절차를 수행합니다.
      "--ktls" 옵션은 TCP_ULP 를 활성화 하고 TLS 연결 소켓에 파라미터를 설정하여 커널에서 암/복호화를 수행하도록 하는 주요 기능을 동작하도록 합니다.
      "-p" 옵션은 bind 할 포트번호를 설정합니다.
      "-B" 옵션은 연결하고자 하는 IP 주소를 설정합니다.
      "-P" 옵션은 연결하고자 하는 포트번호를 설정합니다.

$ ./sslid  --help
sslid v0.0.1-0 (Nov 14 2018 03:43:08)
Copyrights (C) MINZKN.COM - All rights reserved.

usage: sslid [<options>]

options:
        -h, --help                  : help
        -v, --verbose               : verbose
        -b, --bind=<address>        : bind address
        -p, --port=<port>           : bind port
        -l, --cipher-list=<string>  : cipher suite list
        -c, --cert=<filename>       : certificate filename
        -k, --key=<filename>        : private key filename
        -B, --connect=<address>     : connect address
        -P, --connect-port=<port>   : connect port
</pre>

