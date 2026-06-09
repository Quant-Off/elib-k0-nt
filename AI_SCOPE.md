# AI 에이전트 적용 범위

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](AI_SCOPE_EN.md)

저는 이 암호 모듈의 다양한 암호 기능과 기술적인 작동 방식을 상세화한 명세나 모듈과 함수 등의 기능 작동 사항에 대한 다이렉트 주석을 제가 직접 작성하려고 최대한 노력합니다만, 작성된 결과물을 '이해하기 쉽게' 만드는 데(Mermaid 다이어그램을 생성하거나, 명세의 가독성 향상을 위한 맥락, 설명체 등의 간결화 작업과 영문 번역 등) [Claude Code](http://claude.ai/)의 Sonnet 4.6 모델을 적극적으로 사용합니다.

추가적으로, [ISO-LIGHT-K0](https://github.com/Quant-Off/iso-light-k0) 마이크로커널과의 통합을 위해 기능적으로 어떤 부분이 필요한지 점검하고, 누락됐거나 개선이 필요한 부분에 대해 피드백(리뷰) 받고, 암호 알고리즘이 국제적 표준을 준수하는지 확인하기 위해 [NIST FIPS 140-2 또는 3](https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards)의 명세를 파악하기 위해 Claude Code의 Opus 4.6, 4.8, [Gemini 3.1 Pro](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/gemini/3-1-pro?hl=ko), [Qwen 3.7 Max](https://qwen.ai/blog?id=qwen3.7) 모델을 사용합니다. 모든 작업을 이 분야의 전문가를 통해 교차 검증하는 것을 절대 잊지 않습니다.

이 프로젝트는 1인 개발임에 따라 '문서 작업', '주석 작업'에 에이전트를 적극 활용하고 있습니다. 에이전트가 이 프로젝트의 파일을 수정하는 부분은 `.md` 파일과 작성된 모듈, 함수의 주석 추가를 위한 `.rs` 파일입니다. **민감한 기능**(암호 알고리즘의 구현 등)에 대해서는 절대적으로 접근할 수 없도록 제한하고 있습니다. 저는 바이브 코더가 아니며, 다소 구시대적인 개발자일 뿐입니다. 이 명시는 AI를 활용하여 다양한 자동화 작업이나, 개발, 보안 감사를 진행하는 사람들에 대해 비아냥거리기 위해 작성된 것이 아닙니다. 발전하는 AI 시대에 맞게 AI 사용 범위를 인간을 위해 명시했을 뿐입니다.

## 지침과 사용 프롬프트에 관해

CLAUDE.md 지침 문서엔 주로 주석 작성 방법, 결과물 동작 및 구현 검증을 위한 로컬 샌드박스 작동 환경, 생태계 이해를 위한 설명이 작성되어 있습니다.

알고리즘 구현 1차적 검증 작업은 [GSD(Git-Ship-Done) Core](https://github.com/open-gsd/gsd-core)를, 폐쇄형 샌드박스에서 작동하는 에이전트가 프로젝트를 원활히 학습할 수 있도록 정형 문서화 작업 및 제2의 뇌 구축 작업엔 [Graphify](https://github.com/safishamsi/graphify)를 사용하고 있습니다. `CLAUDE.md` 파일, `.planning` 디렉토리에는 환경에 대한 설명과 실제 경로 등이 포함되어 있어 보안을 위해 이그노어링됩니다.

Claude Code의 경우, 문서화와 주석 작성을 위해 "@path/to/module 에 Docstring을 추가해.", "해당 모듈은 ~역할을 맡는 모듈로서, ... 주석을 작성 및 수정해."와 같은 톤과 맥락을 사용합니다. 모듈이 기술적으로 동작하는 데에는 "해당 모듈에 작성된 주석을 바탕으로 현재 모듈의 기술적 작동 방식을 검증하고 결과를 @path/to/target.md 에 작성해."나 "@path/to/pdf FIPS 202 명세에 따른 SHA3 구현 중, 이 모듈의 ~기능이 상태 배열에 대한 레이블링 규칙을 준수하는지 확인해."와 같은 톤을 유지합니다. **이 과정에서 Claude Code가 문서를 "신규 작성"할 뿐, 구현을 직접 수정하지 않습니다.**

커밋은 단순히 "현재 변경 사항을 n개로 나눠 커밋해." 를 사용합니다.

## 추가적으로

이 프로젝트에 적용되는 AI에 대해 여러분은 언제든 자신의 의견을 내어 주실 수 있습니다. <qtfelix@qu4nt.space> 이메일 또는 [저장소 논의](https://github.com/Quant-Off/elib-k0-nt/discussions)에서 "AI Scope" 카테고리를 적극적으로 사용해주세요.
