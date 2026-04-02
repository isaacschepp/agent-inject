# agent-inject

[![CI](https://github.com/isaacschepp/agent-inject/actions/workflows/ci.yml/badge.svg)](https://github.com/isaacschepp/agent-inject/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/isaacschepp/agent-inject/badge)](https://scorecard.dev/viewer/?uri=github.com/isaacschepp/agent-inject)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12353/badge)](https://www.bestpractices.dev/projects/12353)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/12353/baseline)](https://www.bestpractices.dev/projects/12353)

Offensive testing framework for AI agent systems.

Unlike existing tools that test LLM text output, `agent-inject` tests the **interaction layer** between agents, tools, infrastructure, and users — observing tool calls, parameter manipulation, and state changes.

## Install

```bash
uv add agent-inject
# With provider support:
uv add "agent-inject[openai]"
uv add "agent-inject[anthropic]"
uv add "agent-inject[all-providers]"
```

## Quick Start

```bash
agent-inject scan https://my-agent.example.com --goal "say HACKED" --attack direct
agent-inject list-attacks
```

## Development

```bash
uv sync --group dev
uv run pytest --cov
uv run ruff check .
uv run pyright
```

## License

MIT
