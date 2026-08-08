# 기여

[![Language](https://img.shields.io/badge/CONTRIBUTING-English_Ver-blue?style=for-the-badge)](CONTRIBUTING_EN.md)

*가장 먼저, 기여해주시는 모든 여러분께 감사 인사를 드립니다. 여러분의 기여는 아주 큰 힘이 됩니다.*

포괄적인 감사(audit)를 요청하는 건 아닙니다. 각 모듈은 독립적인 크레이트이므로, 관심 있는 알고리즘 하나만 골라 다음 중 하나에 집중해 주셔도 충분합니다.

- 특정 구현이 참조 사양(FIPS/RFC/관련 논문)과 정확히 일치하는지
- 분기(branch)나 배열 인덱싱이 비밀 데이터에 의존해 타이밍 차이를 만드는지
- `zeroize` 호출이 실제로 스코프를 벗어나기 전에 메모리를 (정상적으로) 지우는지, 컴파일러 최적화로 제거되지 않는지
- API가 안전하지 않은 사용(예를 들어, nonce 재사용 등)을 컴파일 타임 또는 런타임에 막고 있는지

발견 사항은 이슈로 등록해 주시면 되고, 코드 수정이 필요 없는 "이 부분이 의심스럽다"는 지적만으로도 충분한 기여입니다.

이어서 기여에 앞서 몇 가지 주의 사항을 알려드리고자 합니다. 아시다시피 저희는 크게 다음 두 가지 보안 원칙을 준수합니다.

- 제로 트러스트 (Zero-Trust)
- 폐쇄 동작 (Air-Gapped)

이는 외부로부터 들여오는 모든 소스에 대해 기본적으로 신뢰하지 않으며, 모든 기능은 Sandbox-like으로 바이너리 독립적으로 동작 가능해야 함을 의미합니다.

여러분은 **문서의 오타 수정**, **Docstring 작성 또는 수정**, **구체적 아이디어 제공**, **보안 소스 제공** 등과 같은 비교적 간단한 부문에 대해 기여하실 수 있습니다. 사소한 변경이라도 "좋은 설명"을 첨부해주시면 감사하겠습니다. 이는 저희가 여러분의 기여를 빠르게 이해하는 데 도움이 됩니다.

## AI 에이전트 사용

저희는 여러분이 이 프로젝트 기여에 AI 에이전트를 사용하는 것에 아무런 불만을 가지고 있지 않습니다. [AI_SCOPE.md](AI_SCOPE.md)문서는 저희가 어떤 부분에 AI를 사용했는지 명시되어 있습니다. 이는 여러분의 기여에서 규칙으로 작용하기도 합니다. **만약 여러분이 AI를 통해 기여하신다면 이 문서에 적용된 범위(스코프)를 명시해주시길 부탁드립니다.** (필요하신 경우, `Co-authored-by`와 같은 트레일러를 커밋에 추가하실 수도 있습니다.) 해당 문서에 직접 명시하신다면, 다음 형식을 따라주시길 바랍니다.

```
### <변경 크레이트명>

- <변경 내용> (<사용 에이전트 또는 모델명>) <변경자 Github 태그>
  - [필요한 경우 추가 설명]
```

깃허브 태그가 생략된 경우는 저장소 메인테이너에 의해 작성된 것임을 인지해주시면 됩니다.

그리고 **AI가 다음 항목에 대한 이슈 또는 PR을 작성하는 경우는 철저히 금지**시켜 주시길 바랍니다.

- 잠재적 위협 또는 실제 발견된 보안 취약점에 대한 이슈 또는 PR
- CI 문제에 대한 이슈 또는 PR

이 규칙으로 번거롭게 해 죄송스러운 마음입니다.

---

## 개발 환경

[K0 마이크로커널](https://github.com/Quant-Off/iso-light-k0)에서 Ring 3(사용자 공간) 데몬 라이브러리로써, 해당 커널의 암호학적 기능 제공 목적으로 시작된 프로젝트인 점을 이해해주시길 바랍니다.

커널 친화 빌드 프로파일이 기본이므로, 호스트에서 테스트를 실행하려면 명시적인 타겟 오버라이드가 필요합니다.

### 빌드

워크스페이스 기본 빌드 타겟은 **`x86_64-unknown-none`** (bare-metal) 입니다(`/.cargo/config.toml` 으로 고정). 따라서 워크스페이스 루트에서 `cargo build`를 실행하면 자동으로 베어메탈 타겟으로 컴파일됩니다.

```bash
# 베어메탈 (기본)
$ cargo build --workspace

# AArch64 베어메탈
$ cargo build --workspace --target aarch64-unknown-none
```

### 테스트

`cargo test`는 호스트 OS의 표준 하네스(std)가 필요하므로, 호스트 타겟을 명시적으로 지정해야 합니다.

```bash
# macOS Intel 호스트
$ cargo test --workspace --target x86_64-apple-darwin

# Apple Silicon
$ cargo test --workspace --target aarch64-apple-darwin

# Linux x86_64
$ cargo test --workspace --target x86_64-unknown-linux-gnu
```

`elib-k0d-core`와 `constant-time`는 각자 `.cargo/config.toml` 에서 호스트 타겟 오버라이드가 이미 설정(macOS로)되어 있어, 단일 크레이트 테스트 실행 시 `--target` 생략이 가능합니다(예: `cargo test -p elib-k0d-core`).

### 린트

모든 커밋에서 다음 명령이 경고 없이 통과해야 합니다.

```bash
$ cargo fmt --check
$ cargo clippy --workspace --all-targets --all-features --target x86_64-apple-darwin -- -D warnings
$ cargo clippy --workspace --target x86_64-unknown-none -- -D warnings
```

새로운 `#![allow(clippy::*)]` 추가는 원칙적으로 금지됩니다. clippy 경고는 코드를 변경하여 해결해야 합니다.

### 코멘트

저희는 CLAUDE.md와 같은 파일에 주석에 관한 지침을 다음과 같이 추가해두었습니다(요약). 

- **기본:** 코멘트 없음. 코드는 자기 설명적으로.
- `#[test]` 위에는 한 줄 한국어 의도 코멘트(왜 이 테스트가 존재하는지).
- Docstring은 사용자 요청 시에만. 형식은 `CLAUDE.md` 참조.
- 표준안(FIPS / RFC / SP) 인용이나 매직 상수 주석은 영어 가능.

### 보안

본 저장소의 모든 변경은 다음 규칙 하에 이루어져야 합니다.

- **제로 트러스트:** 외부 크레이트의 의존성 미사용, `Cargo.toml`의 `[dependencies]`는 워크스페이스 경로만 가능
- **`alloc` 금지:** 동적 할당 미사용, 모든 버퍼는 고정 크기의 스택 배열
- **`zeroize` 의무:** 비밀 데이터는 사용 후 즉시 `zeroize::Secret<T>` 또는 명시적 `.zeroize()` 함수 호출로 소거
- **상수-시간:** 비밀 의존 분기 금지, `constant-time` 크레이트의 `Choice` / `CtSelOps` / `CtEqOps` 등 프리미티브 사용
- **`panic = "abort"`:** 패닉 = 데몬 종료, 모든 패닉 가능 경로는 `Result`로 변환.

### 신규 크레이트 추가 시

1. 워크스페이스 루트 `<name>/` 디렉토리 생성 후 `Cargo.toml` 및 `src/lib.rs` 등 초기 소스코드 작성
2. `Cargo.toml`의 `[package]` 메타데이터는 `version.workspace = true`, `edition.workspace = true`, `authors.workspace = true`, `license.workspace = true`으로 설정
3. `[dependencies]`는 `workspace = true`(경로만)를 적용하며 외부 크레이트 의존 금지
4. 워크스페이스 루트 `Cargo.toml`에 다음과 같이 멤버 명시:
   ```toml
   [workspace.dependencies]
   <name> = { path = "<name>", version = "1.0.0" }
   ```
5. 비밀 데이터를 다루는 경우 `zeroize` 사용, 상수-시간 비교가 필요한 경우 `constant-time` 사용
6. `lib.rs` 첫 줄은 `#![cfg_attr(not(test), no_std)]`(또는 `#![no_std]`) 명시

> [!IMPORTANT]
> `elib` 으로 시작하는 크레이트는 K0 커널을 위해 준비된 크레이트임을 의미합니다.

## 치명적 문제 보고

프로젝트 내에 잔존하는 **잠재적 위협**, 실제 릴리즈(또는 스냅샷)에서 발생하는 **치명적이거나 다소 복합적인 문제**, **암호 기능의 잘못된 구현**, **하드웨어적 발견** 등과 일관된 종류인 기여에 대해선 <qtfelix@qu4nt.space>에게 연락주시길 바랍니다. 양식은 신경쓰지 않으나, 관련 부분(문제)에 대한 명확한 브레이크 포인트 및 구체적 설명(발생 경위, 근거 등)을 첨가해주세요. 필요하신 경우 기술, 정형적 문서(명세) 제공도 가능하십니다.

## 검토

이메일을 통해 보고해주신 문제를 포함해 이슈 및 PR은 저희가 직접 확인한 후 심각성, 규모 등을 고려하고 (수정 후) 현재 버전에 배포(병합)하겠습니다. 그리고 원하시는 경우 기여자 목록에 추가하겠습니다(선택적으로 익명도 가능하고, 실명 또는 이메일을 게시해도 됩니다).