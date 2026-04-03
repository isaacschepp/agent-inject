# Architecture

High-level design of agent-inject.

## Overview

agent-inject follows a pipeline architecture: attacks generate payloads,
evasion transforms encode them, adapters deliver them to target agents,
and scorers evaluate the results.

```
Single-turn:
  Attacks ──> Evasion ──> Engine ──> Adapter ──> Target Agent
                            │                        │
                            │<── AttackResult ────────┘
                            │
                         Scorers ──> Score

Multi-turn:
  Strategy ──> loop: generate prompt ──> Adapter ──> Target Agent
      │                                                  │
      │<── score ── Scorer <── AttackResult ──────────────┘
      │
      └── decide: escalate / backtrack / success / abort
```

## Components

### Attacks (`attacks/`)

Generate `PayloadInstance` objects from templates. Two paths:

- **Python classes** — subclass `FixedJailbreakAttack`, define templates and
  metadata as class variables. Auto-discovered via `importlib` scanning.
- **YAML payloads** — data-driven definitions in `data/payloads/`. Loaded by
  `loader.py`, which dynamically creates attack classes at runtime.

Both are registered in a thread-safe global registry (`registry.py`).

### Evasion (`evasion/`)

Encode or obfuscate payloads to bypass defenses. Eight built-in transforms
(Base64, ROT13, Leetspeak, CharSpacing, Homoglyph, Fullwidth, ZeroWidth,
TextReversal). Transforms compose via `TransformChain` — apply sequentially,
prepend decoder instructions where applicable.

### Engine (`engine.py`)

Orchestrates a scan:

1. Health-check the adapter
2. Collect payloads from selected attacks
3. Apply evasion chains (optional)
4. Deliver payloads concurrently (bounded by semaphore)
5. Score each result with all scorers
6. Return immutable `ScanResult`

Concurrency is configurable (1-50, default 5). Timeouts enforced per request.

### Harness / Adapters (`harness/`)

Deliver payloads to target agents and observe responses. All adapters extend
`BaseAdapter` (async context manager) with:

- `send_payload()` — deliver a payload, return `AttackResult`
- `observe_tool_calls()` — extract tool call data from results
- `health_check()` — verify target is reachable

Current adapter: `RestAdapter` (HTTP POST via `httpx.AsyncClient`). Future
adapters planned for OpenAI, Anthropic, LangChain, MCP, CrewAI, and others
(issues #254-#265).

### Scorers (`scorers/`)

Evaluate whether an attack succeeded. Each scorer is an async function
returning a `Score` (name, passed, value 0-1, rationale). Ten scorers:

| Scorer | What It Detects |
|--------|----------------|
| CanaryMatchScorer | Canary string in output (fuzzy) |
| SubstringMatchScorer | Target substring in output |
| UnauthorizedToolCallScorer | Tool calls outside expected set |
| PrefixMatchScorer | Output starts with expected prefix |
| SystemPromptLeakScorer | System prompt fragments in output |
| ParameterTamperingScorer | Attacker values in tool arguments |
| DataExfiltrationScorer | Sensitive data patterns in output/tools |
| StateModificationScorer | Unauthorized environment changes |
| UtilityPreservedScorer | Legitimate task still completed |
| RefusalAnalysisScorer | Refusal behavior (5-level: full refusal to full compliance) |

### Strategies (`strategies/`)

Multi-turn attack orchestration. Strategies wrap the existing adapter and
scorer to execute multi-turn conversations, separate from the single-turn
pipeline.

- `BaseMultiTurnStrategy` — abstract base with `execute()` loop
- `CrescendoStrategy` — graduated escalation with 6-tier template sequence,
  refusal detection, and backtracking (based on USENIX Security 2025 paper)
- `ConversationState` — immutable snapshot with `add_turn()`, `backtrack()`,
  `mark_success()` for functional state management
- `MultiTurnResult` / `MultiTurnScanResult` — result types with ASR property

### Models (`models.py`)

Immutable, frozen dataclasses defining the domain:

- `DeliveryVector` — how payloads reach agents (10 values)
- `TargetOutcome` — what attacks achieve (14 values, mapped to OWASP ASI)
- `PayloadTier` — sophistication level (6 values)
- `Payload` — attack template with MITRE ATLAS and OWASP IDs
- `PayloadInstance` — fully rendered payload ready for delivery
- `AttackResult` — result of a single attack execution
- `ToolCall` — observed tool/function call
- `Score` — single scoring judgment

### CLI (`cli.py`)

Typer-based CLI exposing `scan`, `list-attacks`, and `version` commands.
Entry point: `agent-inject` (installed via `pyproject.toml` scripts).

### Configuration (`config.py`)

Pydantic `BaseSettings` with `AGENT_INJECT_` env prefix. Loads from
environment variables and `.env` file. API keys stored as `SecretStr`.

## Data Flow

```
1. CLI parses args (target, goal, attacks)
2. Registry resolves attack names to classes
3. Each attack generates PayloadInstances
4. Engine optionally applies evasion transforms
5. Engine sends payloads via adapter (concurrent, bounded)
6. Adapter POSTs to target, parses response into AttackResult
7. Scorers evaluate each AttackResult independently
8. Engine aggregates into ScanResult
9. CLI writes JSON output
```

## Design Principles

- **Immutability** — all domain objects are frozen dataclasses
- **Data-driven** — attacks defined in YAML, not just code
- **Async-first** — engine, adapters, and scorers are all async
- **Composable** — evasion transforms chain, scorers stack independently
- **Extensible** — new attacks, adapters, and scorers via registry + plugins
