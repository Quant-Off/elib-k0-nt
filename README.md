# None-Triple EntanglementLib Crypto Module

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://github.com/Quant-Off/)

[Rust 기반 얽힘 라이브러리 네이티브 프로젝트](https://github.com/Quant-Off/entlib-native)는 가장 많이 사용되는 아키텍처에 대해 `std`(및 `no_std`)를 지원하며, 고보안 규격(국제적 규제 등 컴플라이언스)을 준수하는 데 초점을 맞춥니다. 이 모듈은 그런 부분에서 합리적입니다.

이 모듈은 격리형 초경량 마이크로커널 K0(Isolation Lightweight Microkernel K0, ISO-LIGHT-K0)에서 Ring 3 사용자 공간(user space) 내에 데몬(daemon) 형식으로 구동되며 TUI와 IPC 메시지를 통해 암호화 통신합니다. 데몬은 Ring 0 커널 공간(kernel space) 속 IPC 엔드포인트 라우터로 데이터를 전송하는 방식으로 동작합니다.

`entlib-native` 암호 모듈의 NT을 타게팅한 만큼 100% Rust 언어로 작성되며, 가벼워졌음에도 여전히 강한 보안성을 보입니다.

> [!IMPORTANT]
> 이 프로젝트는 `entlib-native`에서처럼 각 암호 기능에 대해 복잡한 정형 문서(또는 기술 명세)를 작성하지 않습니다. 대신, 가능의 API 시그니처와 사용법은 1차적으로 Rust 문서 주석으로 설명되어 있으며, 이를 요약한 내용을 기능이 제공되는 모듈(또는 크레이트)에 `README.md`로 게시하겠습니다.

여러분은 언제나 프로젝트를 소개한 문서인 [INTRODUCTION.md](INTRODUCTION.md) 파일을 참고할 수 있습니다!

# AI 에이전트 적용 범위

저는 이 암호 모듈의 다양한 암호 기능과 기술적인 작동 방식을 상세화한 명세를 '제 지식선에서 정리하려고' 노력합니다만, 작성된 결과물을 '이해하기 쉽게' 만드는 데(Mermaid 다이어그램을 생성하거나, 명세의 가독성 향상을 위한 맥락, 설명체 등의 간결화 작업과 영문 번역 등), Docstring 및 일반 주석을 추가하기 위해 [Claude Code](http://claude.ai/)의 Sonnet 4.6 모델을 사용합니다. 또한, [ISO-LIGHT-K0](https://github.com/Quant-Off/iso-light-k0) 마이크로커널과의 통합을 위해 기능적으로 어떤 부분이 필요한지 점검하고, 누락됐거나 개선이 필요한 부분에 대해 피드백(리뷰) 받기 위해 Claude Code의 opus 4.7 모델을 사용합니다. 또한, 암호 알고리즘이 국제적 표준을 준수하는지 확인하기 위해 NIST FIPS 140-2 또는 3의 pdf 문서를 파악하는 데 사용합니다. 이 분야의 전문가를 통해 교차 검증하는 것을 절대 잊지 않습니다.

이 프로젝트는 (핑계일 수 있겠지만) 1인 개발이기 때문에 기본적으로 위와 같은 '문서 작업'에만 에이전트를 적용합니다. Claude Code가 이 프로젝트의 파일을 수정하는 부분은 `.md` 파일만임이 확실하며, **민감한 기능**(암호 알고리즘의 구현 등)에 대해서는 절대적으로 접근할 수 없도록 제한합니다. 저는 바이브 코더가 아니며, 다소 구시대적인 개발자일 뿐입니다. 이 명시는 AI를 활용하여 다양한 자동화 작업이나, 개발, 보안 감사를 진행하는 사람들에 대해 비아냥거리기 위해 작성된 것이 아닙니다. 발전하는 AI 시대에 맞게 AI 사용 범위를 인간을 위해 명시했을 뿐입니다.

각 암호 알고리즘 크레이트, `README.md`(이 파일!), `INTRODUCTION.md`는 [EntanglementLib](https://github.com/Quant-Off/entanglementlib)의 Rust 네이티브를 개발할 때 부터 사람이 직접 엄밀한 검토와 함께 작성했으며, 노멀(소개) 문서에 대한 영문 번역본(`*_EN.md`)은 Claude Code의 Sonnet 4.6 모델이 작성했음을 분명히 알립니다.

# 라이선스

이 프로젝트는 [MIT LICENSE](LICENSE)하에 있습니다.