# Roadmap

This document describes the intended direction for agent-inject over the next
year. Plans may change based on community feedback and research developments.

## Q2 2026 (April - June)

**Core framework hardening**

- Complete supply chain security (SLSA L3, SBOM in wheel via PEP 770)
- Bump provider SDK version floors (anthropic >=0.77, add upper bounds)
- Multi-turn attack orchestration and adaptive strategies
- LLM-as-judge scorer implementation

## Q3 2026 (July - September)

**Provider adapters (Phase 15)**

- OpenAI Assistants API adapter
- OpenAI Agents SDK adapter
- Anthropic tool_use adapter
- MCP Client/Server adapter
- Custom REST/WebSocket adapter
- LangChain / LangGraph adapter
- CrewAI adapter

## Q4 2026 (October - December)

**Attack modules**

- Direct and indirect prompt injection payloads (YAML-driven)
- Function call / tool abuse attacks
- MCP tool poisoning and description injection
- RAG document poisoning
- Cross-agent and deputy attacks
- Memory poisoning attacks

## Q1 2027 (January - March)

**Reporting and ecosystem**

- Report generation (HTML, JSON, PDF)
- Metrics dashboard and trend tracking
- Benchmark alignment (AgentDojo, ASB, InjecAgent)
- Documentation site (MkDocs)

## Out of Scope

- Building or hosting AI agents (agent-inject tests them, not runs them)
- General-purpose LLM benchmarking (text quality, hallucination rates)
- Production monitoring or guardrails (agent-inject is an offensive tool)
- GUI or web interface (CLI and Python API only)
