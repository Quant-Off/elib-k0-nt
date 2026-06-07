# AI Agent Scope

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](AI_SCOPE.md)

I personally write detailed specifications covering the cryptographic features and technical workings of this module, along with inline comments on the behavior of individual modules and functions. That said, I actively use the [Claude Code](http://claude.ai/) Sonnet 4.6 model to make the produced artifacts **easier to understand** — generating Mermaid diagrams, condensing context and explanations for improved readability in specifications, and handling English translation.

In addition, I use Opus 4.6 / 4.8 (via Claude Code), [Gemini 3.1 Pro](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/gemini/3-1-pro?hl=en), and [Qwen 3.7 Max](https://qwen.ai/blog?id=qwen3.7) to review which functional pieces are needed for integration with the [ISO-LIGHT-K0](https://github.com/Quant-Off/iso-light-k0) microkernel, receive feedback on missing or improvable areas, and cross-check whether the cryptographic algorithms comply with international standards such as [NIST FIPS 140-2 / 140-3](https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards). All results are cross-validated by human domain experts.

Because this is a solo project, I rely heavily on AI agents for **documentation and comment writing**. Agents are permitted to modify only `.md` files and `.rs` files, and solely for the purpose of adding comments to existing modules and functions. Access to **sensitive logic** — such as cryptographic algorithm implementations — is strictly restricted. I am not a vibe coder; I am simply a developer who still believes in doing things the old-fashioned way. This statement is not meant to ridicule those who use AI for automation, development, or security auditing. It is simply a disclosure of where AI assistance ends and human judgment begins, for the benefit of anyone reading this project.

## Guidelines and Prompt Conventions

The `CLAUDE.md` instruction document primarily covers: comment-writing conventions, the local sandbox environment used for verifying outputs and implementations, and contextual explanations of the ecosystem.

For first-pass algorithm implementation verification, I use [GSD (Git-Ship-Done) Core](https://github.com/open-gsd/gsd-core). For structured documentation and second-brain construction — so that agents running inside a closed sandbox can learn the project efficiently — I use [Graphify](https://github.com/safishamsi/graphify). The `CLAUDE.md` file and the `.planning` directory contain environment descriptions and real local paths, so they are gitignored for security.

For documentation and comment work in Claude Code, prompts such as the following are used: *"Add a Docstring to @path/to/module."* or *"This module serves the role of ~; write and revise its comments accordingly."* For technical verification of how a module operates, prompts follow the pattern: *"Based on the comments in this module, verify the technical behavior and write the result to @path/to/target.md."* or *"Check whether the [feature] in this SHA3 implementation conforms to the state-array labeling rules defined in the FIPS 202 spec at @path/to/pdf."* **In this process, Claude Code only creates new documentation — it never directly modifies implementations.**

Commits are initiated simply with: *"Split the current changes into n commits."*

## Additional Notes

You are welcome to share your thoughts on the AI usage in this project at any time. Please use the <qtfelix@qu4nt.space> email or the [repository discussions](https://github.com/Quant-Off/elib-k0-nt/discussions) under the "AI Scope" category.
