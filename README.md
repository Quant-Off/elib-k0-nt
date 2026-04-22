# None-Triple EntanglementLib Crypto Module

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)

[Rust 기반 얽힘 라이브러리 네이티브 프로젝트](https://github.com/Quant-Off/entlib-native)는 가장 많이 사용되는 아키텍처에 대해 `std`(및 `no_std`)를 지원하며, 고보안 규격(국제적 규제 등 컴플라이언스)을 준수하는 데 초점을 맞춥니다. 이 모듈은 그런 부분에서 합리적입니다.

이 모듈은 격리형 초경량 마이크로커널(Isolation Lightweight Microkernel, ISO-Light-K0)에서 Ring 3 사용자 공간(user space) 내에 데몬(daemon) 형식으로 구동되며 TUI와 IPC 메시지를 통해 암호화 통신합니다. 데몬은 Ring 0 커널 공간(kernel space) 속 IPC 엔드포인트 라우터로 데이터를 전송하는 방식으로 동작합니다.

`entlib-native` 암호 모듈의 NT을 타게팅한 만큼 100% Rust 언어로 작성되며, 가벼워졌음에도 여전히 강한 보안성을 보입니다.

> [!IMPORTANT]
> 이 프로젝트는 `entlib-native`에서처럼 각 암호 기능에 대해 복잡한 정형 문서(또는 기술 명세)를 작성하지 않습니다. 대신, 가능의 API 시그니처와 사용법은 1차적으로 Rust 문서 주석으로 설명되어 있으며, 이를 요약한 내용을 기능이 제공되는 모듈(또는 크레이트)에 `README.md`로 게시하겠습니다.

# 릴리즈 구현 및 목표

얽힘 라이브러리에서 주력으로 사용되던 단일 병목점 관리 구조체인 `SecureBuffer`의 생명주기 컨트롤이 그리워지는 구현이 포함되어 있습니다. 버전 초기화 때에는 개별 기능을 단일 모듈에 포함시키려 했지만, 크레이트 단위로 관리하는 편이 제게는 더 수월한 것 같아 루트를 가상 매니페스트 구조를 선택했습니다.

이 릴리즈 `1.0.0`의 구현 목표는 다음과 같습니다.

- Post-Quantum Cryptography(ML-DSA, ML-KEM)

현재 다음 기능이 구현되었습니다.

- [Constant-time Ops](./constant-time)
- Hash([SHA2](./sha2), [SHA3](./sha3), [SHAKE](./sha3), [BLAKE2](./blake))
- RNG([Hash DRBG](./rng))
- Digital Signature([Ed25519](./ed25519), [Ed448](./ed448))
- Key Establishment Protocol([X25519](./x25519), [X448](./x448))
- AEAD, BlockCipher([AES](./aes), [ChaCha20-Poly1305](./chacha20))

위 기능을 모두 구현하고 하면 각 크레이트에 `README.md` 파일을 통해 기능 사용법을 명확히 작성하는 데 초점을 맞추려고 합니다.

이 릴리즈에서는 우선 암호 기능을 구현하고 정상적으로 작동하는지 테스트를 거치는 것을 목표로 하겠습니다. 커널과 정상적인 상호 작용을 수행하는지에 대한 상세 기능 구현 및 테스트는 다음 알파 버전으로 공개하겠습니다.

# 라이선스

이 프로젝트는 [MIT LICENSE](LICENSE)하에 있습니다.