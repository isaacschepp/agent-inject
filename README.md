# agent-inject

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
agent-inject scan https://my-agent.example.com --attack direct
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

