# 기여

[![Language](https://img.shields.io/badge/CONTRIBUTING-English_Ver-blue?style=for-the-badge)](CONTRIBUTING_EN.md)

*가장 먼저, 기여해주시는 모든 여러분께 감사 인사를 드립니다. 여러분의 기여는 아주 큰 힘이 됩니다.*

기여에 앞서 몇 가지 주의 사항을 알려드리고자 합니다. 불편하시겠지만, 엄중한 보안성을 위해 철저히 지켜주시길 바랍니다. 아시다시피 저희는 크게 다음 두 가지 보안 원칙을 준수합니다.

- 제로 트러스트 (Zero-Trust)
- 폐쇄 동작 (Air-Gapped)

이는 외부로부터 들여오는 모든 소스에 대해 기본적으로 신뢰하지 않으며, 모든 기능은 Sandbox-like 으로 바이너리 독립적으로 동작 가능해야 함을 의미합니다. 여러분이 저희 프로젝트에 특별한 소스를 첨가하기 위해선 위 원칙은 매우 중요합니다.

또는 단순히 **문서의 오타 수정**, **Docstring 작성 또는 수정**, **구체적 아이디어 제공**, **보안 소스 제공** 등과 같은 부문에 대해서 기여하실 수 있습니다. 사소한 변경이라도 "좋은 설명"을 첨부해주시길 바랍니다. 이는 저희가 여러분의 기여를 빠르게 이해하는 데 도움이 됩니다.

## 보안 취약점 보고

프로젝트 내에 잔존하는 **잠재적 위협**, 실제 릴리즈(또는 스냅샷)에서 발생하는 **치명적이거나 다소 복합적인 문제**, **암호 기능의 잘못된 구현**, **하드웨어적 발견** 등과 일관된 종류인 기여에 대해선 <qtfelix@qu4nt.space>에게 연락주시길 바랍니다. 양식은 신경쓰지 않으나, 관련 부분(문제)에 대한 명확한 브레이크 포인트 및 구체적 설명(발생 경위, 근거 등)을 첨가해주세요. 원하시는 경우 기술, 정형적 문서 제공도 가능합니다.

## 검토

모든 기여는 직접 확인한 후 심각성, 규모 등을 고려하고 현재 버전에 배포하겠습니다. 그리고 원하시는 경우 기여자 목록에 추가하겠습니다(선택적으로 익명도 가능하고, 실명 또는 이메일을 게시해도 됩니다).

---

## 개발 환경 / Development Environment

본 저장소는 ISO-LIGHT-K0 마이크로커널 위 Ring-3 사용자 공간 데몬 라이브러리입니다.
커널 친화 빌드 프로파일이 기본이므로, 호스트에서 테스트를 실행하려면 명시적인
타깃 오버라이드가 필요합니다.

### 빌드 / Build

워크스페이스 기본 빌드 타깃은 **`x86_64-unknown-none`** (bare-metal) 입니다
(`/.cargo/config.toml` 으로 고정). 따라서 워크스페이스 루트에서 `cargo build`
를 실행하면 자동으로 베어메탈 타깃으로 컴파일됩니다.

```bash
# 베어메탈 (기본)
cargo build --workspace

# AArch64 베어메탈
cargo build --workspace --target aarch64-unknown-none
```

### 테스트 / Test

`cargo test` 는 호스트 OS 의 표준 하네스 (std) 가 필요하므로, 호스트 타깃을
명시적으로 지정해야 합니다.

```bash
# macOS Intel 호스트
cargo test --workspace --target x86_64-apple-darwin

# Apple Silicon
cargo test --workspace --target aarch64-apple-darwin

# Linux x86_64
cargo test --workspace --target x86_64-unknown-linux-gnu
```

`elib-k0d-core` 와 `constant-time` 는 각자 `.cargo/config.toml` 에서 호스트
타깃 오버라이드가 이미 설정되어 있어, 단일 크레이트 테스트 실행 시 `--target`
생략이 가능합니다 (예: `cargo test -p elib-k0d-core`).

### 린트 / Lint

모든 커밋에서 다음이 무경고로 통과해야 합니다 (CLAUDE.md 헌장 §"로직 구현"):

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --target x86_64-apple-darwin -- -D warnings
cargo clippy --workspace --target x86_64-unknown-none -- -D warnings
```

새로운 `#![allow(clippy::*)]` 추가는 원칙적으로 금지입니다. 클리피 경고는 코드를
바꿔서 해결하세요.

### 코멘트 / Comment Convention

CLAUDE.md §"주석" 정책 요약:

- **기본:** 코멘트 없음. 코드는 자기 설명적으로.
- `#[test]` 위에는 한 줄 한국어 의도 코멘트 (왜 이 테스트가 존재하는지).
- Docstring 은 사용자 요청 시에만. 형식은 `CLAUDE.md` 참조.
- 표준 (FIPS / RFC / NIST SP) 인용이나 매직 상수 주석은 영어 가능.

### 보안 / Security

본 저장소의 모든 변경은 다음 헌장 위에서 이루어집니다:

- **Zero-Trust:** 외부 crate 의존성 0 개. `Cargo.toml [dependencies]` 는
  workspace path-only.
- **`alloc` 금지:** 동적 할당 없음. 모든 버퍼는 고정 크기 스택 배열.
- **`zeroize` 의무:** 비밀 데이터는 사용 후 즉시 `zeroize::Secret<T>` 또는
  명시적 `.zeroize()` 호출로 소거.
- **Constant-time:** 비밀 의존 분기 금지. `constant-time` 크레이트의
  `Choice` / `CtSelOps` / `CtEqOps` 사용.
- **`panic = "abort"`:** 패닉 = 데몬 종료. 모든 패닉 가능 경로는 `Result`
  로 변환.

### 신규 크레이트 추가 / Adding a New Crate

1. 워크스페이스 루트 `<name>/` 디렉토리 생성, `Cargo.toml` + `src/lib.rs`.
2. `Cargo.toml [package]` 메타데이터: `version.workspace = true`,
   `edition.workspace = true`, `authors.workspace = true`,
   `license.workspace = true`.
3. `[dependencies]` 는 path-only `workspace = true` 만 사용 — 외부 crate
   추가는 절대 금지 (Zero-Trust 헌장).
4. 워크스페이스 루트 `Cargo.toml [workspace] members` 와
   `[workspace.dependencies]` 양쪽에 추가:
   ```toml
   [workspace.dependencies]
   <name> = { path = "<name>", version = "1.0.0" }
   ```
5. 비밀 데이터를 다루면 `zeroize.workspace = true`, 상수시간 비교가
   필요하면 `constant-time.workspace = true`.
6. `lib.rs` 첫 줄: `#![cfg_attr(not(test), no_std)]` (또는 `#![no_std]`
   for foundation crates).
