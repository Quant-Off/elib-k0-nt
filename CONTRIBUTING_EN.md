# Contributing

[![Language](https://img.shields.io/badge/CONTRIBUTING-Korean_Ver-blue?style=for-the-badge)](CONTRIBUTING.md)

*First of all, thank you to everyone contributing. Your contributions are a huge help.*

We're not asking for a comprehensive audit. Since each module is an independent crate, it's more than enough to pick a single algorithm you're interested in and focus on one of the following.

- Whether a specific implementation exactly matches the reference specification (FIPS/RFC/related papers)
- Whether a branch or array indexing depends on secret data and creates a timing difference
- Whether a `zeroize` call actually wipes memory (properly) before it goes out of scope, and isn't eliminated by compiler optimization
- Whether the API prevents unsafe usage (e.g., nonce reuse) at compile time or runtime

Please file any findings as an issue. Even a "this part looks suspicious" observation that needs no code fix is a sufficient contribution.

Before you contribute, we'd like to flag a few things. As you may know, we broadly follow two security principles.

- Zero-Trust
- Air-Gapped operation

This means we do not trust any source brought in from outside by default, and every feature must be able to operate Sandbox-like, independent of any binary.

You're welcome to contribute to relatively simple areas such as **fixing typos in documentation**, **writing or revising docstrings**, **providing concrete ideas**, and **providing security sources**. Even for a trivial change, we'd appreciate a "good explanation" attached, since it helps us understand your contribution quickly.

## Using AI Agents

We have no objection to your using AI agents to contribute to this project. The [AI_SCOPE.md](AI_SCOPE.md) document specifies which parts we've used AI for, and it also serves as a rule for your contributions. **If you contribute through AI, please specify the scope applied, per this document.** (If you'd like, you may also add a trailer such as `Co-authored-by` to your commit.) If you specify it directly in that document, please follow this format.

```
### <Name of the changed crate>

- <Description of the change> (<Agent or model name used>) <Contributor's GitHub handle>
  - [Additional explanation if needed]
```

If the GitHub handle is omitted, you can take it to mean the change was made by a repository maintainer.

And please **strictly refrain from having AI write issues or PRs** for the following.

- Issues or PRs about potential threats, or about security vulnerabilities that were actually discovered
- Issues or PRs about CI problems

Sorry for the inconvenience this rule causes.

---

## Development Environment

Please keep in mind that this project started as a Ring 3 (user space) daemon library on the [K0 microkernel](https://github.com/Quant-Off/iso-light-k0), for the purpose of providing that kernel's cryptographic functionality.

Since the kernel-friendly build profile is the default, running tests on the host requires an explicit target override.

### Build

The workspace's default build target is **`x86_64-unknown-none`** (bare-metal), fixed via `/.cargo/config.toml`. So running `cargo build` at the workspace root automatically compiles for the bare-metal target.

```bash
# Bare-metal (default)
$ cargo build --workspace

# AArch64 bare-metal
$ cargo build --workspace --target aarch64-unknown-none
```

### Testing

`cargo test` requires the host OS's standard harness (std), so you must explicitly specify the host target.

```bash
# macOS Intel host
$ cargo test --workspace --target x86_64-apple-darwin

# Apple Silicon
$ cargo test --workspace --target aarch64-apple-darwin

# Linux x86_64
$ cargo test --workspace --target x86_64-unknown-linux-gnu
```

`elib-k0d-core` and `constant-time` each already have a host target override set (to macOS) in their own `.cargo/config.toml`, so `--target` can be omitted when running a single crate's tests (e.g., `cargo test -p elib-k0d-core`).

### Lint

The following commands must pass with no warnings on every commit.

```bash
$ cargo fmt --check
$ cargo clippy --workspace --all-targets --all-features --target x86_64-apple-darwin -- -D warnings
$ cargo clippy --workspace --target x86_64-unknown-none -- -D warnings
```

Adding a new `#![allow(clippy::*)]` is prohibited in principle. Clippy warnings must be resolved by changing the code.

### Comments

We've added guidance on comments to files like CLAUDE.md, summarized as follows.

- **Default:** No comments. Code should be self-explanatory.
- Above `#[test]`: a one-line Korean intent comment (why this test exists).
- Docstrings only when the user requests them. See `CLAUDE.md` for the format.
- Comments quoting a standard (FIPS / RFC / SP), or annotating a magic constant, may be in English.

### Security

Every change to this repository must follow these rules.

- **Zero-Trust:** No dependency on external crates; `[dependencies]` in `Cargo.toml` may only use workspace paths
- **No `alloc`:** No dynamic allocation; every buffer is a fixed-size stack array
- **`zeroize` is mandatory:** Secret data must be wiped immediately after use, via `zeroize::Secret<T>` or an explicit `.zeroize()` call
- **Constant-time:** No branching on secret-dependent values; use the `constant-time` crate's `Choice` / `CtSelOps` / `CtEqOps` and other primitives
- **`panic = "abort"`:** A panic means the daemon terminates, so every panic-capable path must be converted into a `Result`.

### When Adding a New Crate

1. Create the `<name>/` directory at the workspace root, then write the initial source, including `Cargo.toml` and `src/lib.rs`.
2. Set the `[package]` metadata in `Cargo.toml` to `version.workspace = true`, `edition.workspace = true`, `authors.workspace = true`, `license.workspace = true`.
3. Apply `workspace = true` (path-only) to `[dependencies]`; no external crate dependencies allowed.
4. Declare the member in the workspace root `Cargo.toml` as follows:
   ```toml
   [workspace.dependencies]
   <name> = { path = "<name>", version = "1.0.0" }
   ```
5. Use `zeroize` when handling secret data, and `constant-time` when constant-time comparison is needed.
6. The first line of `lib.rs` must declare `#![cfg_attr(not(test), no_std)]` (or `#![no_std]`).

> [!IMPORTANT]
> A crate whose name begins with `elib` is a crate prepared for the K0 kernel.

## Reporting Critical Issues

For contributions of a kind consistent with **potential threats** remaining in the project, **critical or somewhat complex issues** arising in an actual release (or snapshot), **incorrect implementations of cryptographic functionality**, **hardware-level findings**, and the like, please contact <qtfelix@qu4nt.space>. We don't mind the format, but please include a clear break point for the relevant issue and a concrete explanation (how it occurred, its basis, etc.). If needed, you're also welcome to provide technical or formal documentation (specifications).

## Review

For issues and PRs, including problems reported by email, we'll review them ourselves, weigh severity and scope, and (after a fix) deploy (merge) them into the current version. If you'd like, we'll also add you to the contributor list (you may optionally stay anonymous, or publish your real name or email).
