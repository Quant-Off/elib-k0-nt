# None-Triple EntanglementLib Crypto Module

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)

[Rust 기반 얽힘 라이브러리 네이티브 프로젝트](https://github.com/Quant-Off/entlib-native)는 가장 많이 사용되는 아키텍처에 대해 `std`(및 `no_std`)를 지원하며, 고보안 규격(국제적 규제 등 컴플라이언스)을 준수하는 데 초점을 맞춥니다. 이 모듈은 그런 부분에서 합리적입니다.

이 모듈은 격리형 초경량 마이크로커널 K0(Isolation Lightweight Microkernel K0, ISO-LIGHT-K0)에서 Ring 3 사용자 공간(user space) 내에 데몬(daemon) 형식으로 구동되며 TUI와 IPC 메시지를 통해 암호화 통신합니다. 데몬은 Ring 0 커널 공간(kernel space) 속 IPC 엔드포인트 라우터로 데이터를 전송하는 방식으로 동작합니다.

`entlib-native` 암호 모듈의 NT을 타게팅한 만큼 100% Rust 언어로 작성되며, 가벼워졌음에도 여전히 강한 보안성을 보입니다.

> [!IMPORTANT]
> 이 프로젝트는 `entlib-native`에서처럼 각 암호 기능에 대해 복잡한 정형 문서(또는 기술 명세)를 작성하지 않습니다. 대신, 가능의 API 시그니처와 사용법은 1차적으로 Rust 문서 주석으로 설명되어 있으며, 이를 요약한 내용을 기능이 제공되는 모듈(또는 크레이트)에 `README.md`로 게시하겠습니다.

여러분은 언제나 프로젝트를 소개한 문서인 [INTRODUCTION.md](INTRODUCTION.md) 파일을 참고할 수 있습니다!

# 라이선스

이 프로젝트는 [MIT LICENSE](LICENSE)하에 있습니다.