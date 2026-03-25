# ZeroKit V3

Plug-and-play skill layer that turns AI agents into whitebox pentesters.

Built for OpenCode first. Claude Code, Codex, and GitHub Copilot are
secondary targets as long as they can read files and run shell commands.

## How It Works

The agent provides reasoning. ZeroKit provides methodology, tools, and
evidence contracts. Not an automated scan chain -- the agent decides.

## 6-Phase Flow
`Intake > Surface > Static > Verify > RCA > Report`

## Setup
```bash
pip install -e ".[dev]"
make test
```

## Rules
- No proof, no vulnerability.
- Agent decides; scripts execute.
- Contract-aligned artifacts required at every phase gate.
- Primary targets: .NET, TypeScript/JavaScript, Java, Go, Python.
