"""``mcp-rbac-gateway`` command-line interface."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich import box
from rich.console import Console, Group
from rich.logging import RichHandler
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .audit import AuditLog, AuditSummary
from .config import SentinelConfig, load_config
from .models import AuditDecision

app = typer.Typer(
    name="mcp-rbac-gateway",
    help="Security, RBAC and audit gateway for MCP servers and AI agents.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
# stdout belongs to the MCP protocol in `wrap`; everything human-facing goes to stderr.
err = Console(stderr=True)
out = Console()

ConfigOpt = Annotated[
    Path,
    typer.Option("--config", "-c", help="Path to sentinel.yaml.", envvar="SENTINEL_CONFIG"),
]


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=err, show_path=False, rich_tracebacks=True)],
        force=True,
    )


def _load(config: Path) -> SentinelConfig:
    if not config.exists():
        err.print(f"[red]config file not found:[/] {config}")
        raise typer.Exit(2)
    try:
        return load_config(config)
    except Exception as exc:
        err.print(Panel(str(exc), title=f"invalid config: {config}", border_style="red"))
        raise typer.Exit(2) from exc


def _version_cb(value: bool) -> None:
    if value:
        out.print(f"mcp-rbac-gateway {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool, typer.Option("--version", callback=_version_cb, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    pass


# --------------------------------------------------------------------- wrap


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def wrap(
    ctx: typer.Context,
    config: ConfigOpt = Path("sentinel.yaml"),
    agent: Annotated[
        str | None, typer.Option("--agent", "-a", help="Agent identity for this session.")
    ] = None,
    approval_port: Annotated[
        int | None,
        typer.Option(help="Also serve the approval API on this port (webhook HITL mode)."),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run a stdio MCP server behind the gateway.

    The upstream command comes from [bold]upstream.command[/] in the config,
    or from everything after [bold]--[/]:

        mcp-rbac-gateway wrap -c sentinel.yaml --agent researcher -- python -m my_server
    """
    _setup_logging(verbose)
    cfg = _load(config)
    command = list(ctx.args) or cfg.upstream.command
    if not command:
        err.print("[red]no upstream command:[/] set upstream.command or pass it after --")
        raise typer.Exit(2)

    from .gateway import Sentinel
    from .proxy import StdioProxy

    sentinel = Sentinel(cfg)
    proxy = StdioProxy(
        sentinel, command, agent_id=agent, env=cfg.upstream.env, cwd=cfg.upstream.cwd
    )
    logging.getLogger("mcp_rbac_gateway").info(
        "mcp-rbac-gateway guarding [bold]%s[/] as agent [bold]%s[/]",
        " ".join(command),
        sentinel.agent_or_default(agent),
        extra={"markup": True},
    )

    async def main() -> int:
        server_task = None
        if approval_port:
            server_task = asyncio.create_task(_serve_approvals(sentinel, cfg, approval_port))
        try:
            return await proxy.run()
        finally:
            if server_task:
                server_task.cancel()

    try:
        code = asyncio.run(main())
    except KeyboardInterrupt:
        code = 130
    finally:
        sentinel.close()
    raise typer.Exit(code)


async def _serve_approvals(sentinel: Any, cfg: SentinelConfig, port: int) -> None:
    import uvicorn
    from fastapi import FastAPI

    from .hitl import create_approval_router

    token_env = cfg.hitl.webhook.token_env
    api = FastAPI(title="mcp-rbac-gateway approvals")
    api.include_router(
        create_approval_router(sentinel.broker, os.environ.get(token_env) if token_env else None)
    )
    server = uvicorn.Server(uvicorn.Config(api, host="127.0.0.1", port=port, log_level="warning"))
    await server.serve()


# -------------------------------------------------------------------- serve


@app.command()
def serve(
    config: ConfigOpt = Path("sentinel.yaml"),
    upstream_url: Annotated[
        str | None, typer.Option(help="Upstream MCP endpoint (defaults to upstream.url).")
    ] = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    path: Annotated[str, typer.Option(help="Path for the Streamable HTTP endpoint.")] = "/mcp",
    agent: Annotated[
        str | None, typer.Option("--agent", "-a", help="Agent used when no header is sent.")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run an HTTP (Streamable HTTP + legacy SSE) reverse proxy in front of an MCP server."""
    _setup_logging(verbose)
    cfg = _load(config)
    url = upstream_url or cfg.upstream.url
    if not url:
        err.print("[red]no upstream URL:[/] set upstream.url or pass --upstream-url")
        raise typer.Exit(2)
    import uvicorn

    from .gateway import Sentinel
    from .proxy import HttpProxy

    sentinel = Sentinel(cfg)
    token_env = cfg.hitl.webhook.token_env
    proxy = HttpProxy(
        sentinel,
        url,
        path=path,
        default_agent=agent,
        headers=cfg.upstream.headers,
        approval_token=os.environ.get(token_env) if token_env else None,
    )
    err.print(
        Panel.fit(
            f"[bold]mcp-rbac-gateway[/] {__version__}\n"
            f"proxy    http://{host}:{port}{path}  (legacy SSE: /sse)\n"
            f"upstream {url}\n"
            f"approvals http://{host}:{port}/approvals",
            border_style="cyan",
        )
    )
    try:
        uvicorn.run(proxy.build_app(), host=host, port=port, log_level="warning")
    finally:
        sentinel.close()


@app.command("proxy-http")
def proxy_http(
    config: ConfigOpt = Path("sentinel.yaml"),
    upstream_url: Annotated[
        str | None, typer.Option(help="Upstream MCP endpoint (defaults to upstream.url).")
    ] = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    path: Annotated[str, typer.Option(help="Path for the MCP endpoint.")] = "/mcp",
    agent: Annotated[
        str | None, typer.Option("--agent", "-a", help="Agent used when no header is sent.")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run a stateless Streamable HTTP proxy (MCP 2026-07-28: no initialize, no sessions)."""
    _setup_logging(verbose)
    cfg = _load(config)
    url = upstream_url or cfg.upstream.url
    if not url:
        err.print("[red]no upstream URL:[/] set upstream.url or pass --upstream-url")
        raise typer.Exit(2)
    import uvicorn

    from .gateway import Sentinel
    from .mcp import SUPPORTED_STATELESS_VERSIONS
    from .proxy import StatelessHttpProxy

    sentinel = Sentinel(cfg)
    token_env = cfg.hitl.webhook.token_env
    proxy = StatelessHttpProxy(
        sentinel,
        url,
        path=path,
        default_agent=agent,
        headers=cfg.upstream.headers,
        approval_token=os.environ.get(token_env) if token_env else None,
    )
    err.print(
        Panel.fit(
            f"[bold]mcp-rbac-gateway[/] {__version__} (stateless)\n"
            f"proxy    http://{host}:{port}{path}  "
            f"(MCP {', '.join(SUPPORTED_STATELESS_VERSIONS)})\n"
            f"upstream {url}\n"
            f"approvals http://{host}:{port}/approvals",
            border_style="cyan",
        )
    )
    try:
        uvicorn.run(proxy.build_app(), host=host, port=port, log_level="warning")
    finally:
        sentinel.close()


# ------------------------------------------------------------------- report

_SINCE_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([smhdw])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

_DECISION_STYLE = {
    AuditDecision.ALLOWED.value: "green",
    AuditDecision.APPROVED.value: "cyan",
    AuditDecision.BLOCKED_POLICY.value: "red",
    AuditDecision.BLOCKED_INJECTION.value: "magenta",
    AuditDecision.DENIED_BY_HUMAN.value: "yellow",
    AuditDecision.APPROVAL_TIMEOUT.value: "yellow",
    AuditDecision.ERROR.value: "bright_red",
    AuditDecision.PENDING_APPROVAL.value: "blue",
}


def parse_since(value: str | None) -> float | None:
    """``"24h"`` -> unix timestamp 24 hours ago. ``None``/``"all"`` -> no limit."""
    if value is None or value == "all":
        return None
    match = _SINCE_RE.match(value.strip().lower())
    if not match:
        raise typer.BadParameter("use a duration like 30m, 24h, 7d or 'all'")
    return time.time() - float(match.group(1)) * _UNITS[match.group(2)]


def _fmt_ms(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:,.1f} ms" if value < 10_000 else f"{value / 1000:,.1f} s"


def _bar(part: int, total: int, width: int = 20) -> str:
    if total == 0:
        return ""
    filled = round(width * part / total)
    return "█" * filled + "░" * (width - filled)


def render_report(log: AuditLog, *, since: float | None, agent: str | None, limit: int) -> Group:
    summary: AuditSummary = log.summary(since=since, agent_id=agent)
    blocked = sum(n for d, n in summary.by_decision.items() if AuditDecision(d).is_block)
    allowed = summary.by_decision.get("allowed", 0) + summary.by_decision.get("approved", 0)

    def stamp(ts: float | None) -> str:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "-"

    header = Table.grid(padding=(0, 3))
    for _ in range(5):
        header.add_column(justify="center")
    header.add_row(
        Text(f"{summary.total:,}", style="bold"),
        Text(f"{allowed:,}", style="bold green"),
        Text(f"{blocked:,}", style="bold red"),
        Text(f"{summary.redactions:,}", style="bold yellow"),
        Text(f"{summary.injections:,}", style="bold magenta"),
    )
    header.add_row("calls", "allowed", "blocked", "redactions", "injection hits")
    window = f"{stamp(summary.first_ts)} → {stamp(summary.last_ts)}"
    overview = Panel(
        header, title="[bold]mcp-rbac-gateway report[/]", subtitle=window, border_style="cyan"
    )

    decisions = Table(title="Decisions", box=box.SIMPLE_HEAVY, expand=True)
    decisions.add_column("decision")
    decisions.add_column("count", justify="right")
    decisions.add_column("share")
    for name, count in sorted(summary.by_decision.items(), key=lambda kv: -kv[1]):
        style = _DECISION_STYLE.get(name, "white")
        decisions.add_row(
            Text(name, style=style), f"{count:,}", Text(_bar(count, summary.total), style=style)
        )

    agents = Table(title="Agents", box=box.SIMPLE_HEAVY, expand=True)
    for col, justify in (
        ("agent", "left"),
        ("calls", "right"),
        ("blocked", "right"),
        ("approved", "right"),
        ("block rate", "right"),
    ):
        agents.add_column(col, justify=justify)  # type: ignore[arg-type]
    for a in summary.agents:
        rate = a.blocked / a.calls if a.calls else 0
        agents.add_row(
            Text(a.agent_id),
            f"{a.calls:,}",
            f"{a.blocked:,}",
            f"{a.approvals:,}",
            Text(f"{rate:.0%}", style="red" if rate >= 0.25 else "green"),
        )

    tools = Table(title="Tools", box=box.SIMPLE_HEAVY, expand=True)
    for col, justify in (
        ("tool", "left"),
        ("calls", "right"),
        ("blocked", "right"),
        ("avg latency", "right"),
        ("p95 latency", "right"),
    ):
        tools.add_column(col, justify=justify)  # type: ignore[arg-type]
    for t in summary.tools:
        tools.add_row(
            Text(t.tool),
            f"{t.calls:,}",
            f"{t.blocked:,}",
            _fmt_ms(t.avg_latency_ms),
            _fmt_ms(t.p95_latency_ms),
        )

    recent = Table(title=f"Last {limit} events", box=box.SIMPLE, expand=True)
    for col in ("time", "agent", "tool", "decision", "latency", "reason"):
        recent.add_column(col, overflow="fold")
    for e in log.query(since=since, agent_id=agent, limit=limit):
        recent.add_row(
            datetime.fromtimestamp(e.ts).strftime("%H:%M:%S"),
            Text(e.agent_id),
            Text(e.tool),
            Text(e.decision.value, style=_DECISION_STYLE.get(e.decision.value, "white")),
            _fmt_ms(e.latency_ms),
            Text(e.reason[:160]),
        )

    return Group(overview, decisions, agents, tools, recent)


@app.command()
def report(
    db: Annotated[
        Path | None, typer.Option(help="Audit database (defaults to audit.path in config).")
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="sentinel.yaml to read audit.path from."),
    ] = None,
    since: Annotated[str, typer.Option(help="Time window: 30m, 24h, 7d or 'all'.")] = "24h",
    agent: Annotated[str | None, typer.Option("--agent", "-a")] = None,
    limit: Annotated[int, typer.Option(help="Number of recent events to show.")] = 15,
    as_json: Annotated[bool, typer.Option("--json", help="Print the summary as JSON.")] = False,
    watch: Annotated[
        float | None, typer.Option(help="Refresh every N seconds (live dashboard).")
    ] = None,
) -> None:
    """Show a dashboard of tool calls, blocks, approvals and latency from the audit trail."""
    path = db
    if path is None:
        cfg_path = config or Path("sentinel.yaml")
        path = Path(_load(cfg_path).audit.path) if cfg_path.exists() else Path(".sentinel/audit.db")
    if not path.exists():
        err.print(f"[yellow]no audit database at {path} yet[/] - run some tool calls first.")
        raise typer.Exit(1)
    window = parse_since(since)
    with AuditLog(path) as log:
        if as_json:
            payload: dict[str, Any] = log.summary(since=window, agent_id=agent).model_dump()
            payload["recent"] = [
                e.model_dump(mode="json")
                for e in log.query(since=window, agent_id=agent, limit=limit)
            ]
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
            return
        if watch:
            from rich.live import Live

            with Live(console=out, refresh_per_second=4, screen=False) as live:
                try:
                    while True:
                        live.update(
                            render_report(log, since=parse_since(since), agent=agent, limit=limit)
                        )
                        time.sleep(watch)
                except KeyboardInterrupt:
                    return
        out.print(render_report(log, since=window, agent=agent, limit=limit))


# ----------------------------------------------------------------- validate


@app.command()
def validate(config: ConfigOpt = Path("sentinel.yaml")) -> None:
    """Validate a sentinel.yaml and print the effective policy per agent."""
    cfg = _load(config)
    from .policy import PolicyEngine
    from .scanner import Scanner

    Scanner(cfg.scanner)  # validates detector names
    engine = PolicyEngine(cfg)
    table = Table(title=f"{config} is valid ✓", box=box.ROUNDED, title_style="bold green")
    for col in ("agent", "allow", "deny", "approval", "arg rules", "methods", "skills"):
        table.add_column(col, overflow="fold")

    def rules(allow: list[str], deny: list[str]) -> Text:
        parts = []
        if allow:
            parts.append("+" + ", +".join(dict.fromkeys(allow)))
        if deny:
            parts.append("-" + ", -".join(dict.fromkeys(deny)))
        return Text(", ".join(parts) or "-")

    for name in cfg.agents:
        eff = engine.effective_policy(name)
        table.add_row(
            escape(name) + (" [dim](default)[/]" if name == cfg.default_agent else ""),
            Text(", ".join(dict.fromkeys(eff.allow)) or "-"),
            Text(", ".join(dict.fromkeys(eff.deny)) or "-"),
            Text(", ".join(dict.fromkeys(eff.require_approval)) or "-"),
            str(sum(len(c) for _, c in eff.arguments)),
            rules(eff.method_allow, eff.method_deny),
            rules(eff.skill_allow, eff.skill_deny),
        )
    out.print(table)
    out.print(
        f"default_action=[bold]{cfg.default_action}[/]  hitl=[bold]{cfg.hitl.mode}[/]"
        f"{'' if cfg.hitl.enabled else ' (disabled)'}  "
        f"injection=[bold]{cfg.scanner.prompt_injection.action}[/]@"
        f"{cfg.scanner.prompt_injection.threshold}  audit=[bold]{cfg.audit.path}[/]"
    )


# ------------------------------------------------------------- check-policy


@app.command("check-policy")
def check_policy(
    config: Annotated[Path, typer.Argument(help="Path to sentinel.yaml.")] = Path("sentinel.yaml"),
    tools: Annotated[
        list[str] | None,
        typer.Option("--tool", "-t", help="Also show the decision for this tool (repeatable)."),
    ] = None,
    agent: Annotated[
        list[str] | None, typer.Option("--agent", "-a", help="Only these agents (repeatable).")
    ] = None,
) -> None:
    """Show each agent's effective allow/deny after inheritance.

    Deny always wins: a tool denied anywhere in an agent's inheritance chain
    stays denied even if the agent itself allows it. With [bold]--tool[/], prints
    the decision (allow / deny / approval) per agent for each tool, with no
    arguments.
    """
    cfg = _load(config)
    from .hitl import ApprovalGate
    from .policy import PolicyEngine

    engine = PolicyEngine(cfg)
    gate = ApprovalGate(cfg.hitl, approver=_NoopApprover())
    names = agent or list(cfg.agents)
    unknown = [n for n in names if n not in cfg.agents]
    if unknown:
        raise typer.BadParameter(f"unknown agent(s): {', '.join(unknown)}")

    table = Table(title=f"effective policy: {config}", box=box.ROUNDED)
    for col in ("agent", "inherits", "allow", "deny", "approval"):
        table.add_column(col, overflow="fold")
    for tool in tools or []:
        table.add_column(escape(tool), justify="center")
    marks = {"allow": "[green]allow[/]", "deny": "[red]deny[/]", "approval": "[yellow]approval[/]"}
    for name in names:
        eff = engine.effective_policy(name)
        row: list[str | Text] = [
            escape(name) + (" [dim](default)[/]" if name == cfg.default_agent else ""),
            Text(" > ".join(eff.chain[1:]) or "-"),
            Text(", ".join(dict.fromkeys(eff.allow)) or "-"),
            Text(", ".join(dict.fromkeys(eff.deny)) or "-"),
            Text(", ".join(dict.fromkeys(eff.require_approval)) or "-"),
        ]
        for tool in tools or []:
            decision = engine.evaluate(name, tool, {})
            if not decision.allowed:
                row.append(marks["deny"])
            elif gate.approval_reason(tool, {}, decision):
                row.append(marks["approval"])
            else:
                row.append(marks["allow"])
        table.add_row(*row)
    out.print(table)
    out.print(
        f"default_action=[bold]{cfg.default_action}[/] (tools no rule matches)  "
        "deny wins over allow along the inheritance chain"
    )


# -------------------------------------------------------------------- check


@app.command()
def check(
    tool: Annotated[str, typer.Argument(help="Tool name.")],
    arguments: Annotated[str, typer.Argument(help="JSON object of arguments.")] = "{}",
    config: ConfigOpt = Path("sentinel.yaml"),
    agent: Annotated[str | None, typer.Option("--agent", "-a")] = None,
) -> None:
    """Dry-run: show what the gateway would decide for a call (no approval prompt, no audit)."""
    cfg = _load(config)
    from .hitl import ApprovalGate
    from .policy import PolicyEngine
    from .scanner import Scanner

    try:
        args = json.loads(arguments)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"arguments must be JSON: {exc}") from exc
    engine = PolicyEngine(cfg)
    who = agent or cfg.default_agent
    decision = engine.evaluate(who, tool, args)
    approval = ApprovalGate(cfg.hitl, approver=_NoopApprover()).approval_reason(
        tool, args, decision
    )
    scan = Scanner(cfg.scanner).scan_input(args)
    verdict = "require_approval" if decision.allowed and approval else decision.action.value
    style = {"allow": "green", "deny": "red", "require_approval": "yellow"}[verdict]
    reason = approval if approval and decision.allowed else decision.reason
    out.print(
        Panel(
            f"agent    {escape(engine.resolve_agent(who))}\n"
            f"decision [bold {style}]{verdict}[/]\n"
            f"reason   {escape(reason)}\n"
            f"rule     {escape(decision.rule or '-')}\n"
            f"forwarded args {escape(json.dumps(scan.payload))}",
            title=escape(tool),
            border_style=style,
        )
    )
    raise typer.Exit(0 if decision.allowed else 1)


class _NoopApprover:
    async def request_approval(self, request: Any) -> Any:  # pragma: no cover
        raise RuntimeError("dry run")


# --------------------------------------------------------------------- init

SAMPLE_CONFIG = """\
# mcp-rbac-gateway configuration. Docs: https://github.com/pavankalyan-Maturi/mcp-rbac-gateway
version: 1

# Agents not listed below are governed by this agent's policy.
default_agent: guest
# What happens to tools no allow/deny rule mentions.
default_action: deny

agents:
  guest:
    description: Unknown callers can only read.
    allow: ["read_*", "list_*", "search_*"]

  researcher:
    description: Read-only research agent.
    inherits: [guest]
    allow: ["fetch_url"]
    arguments:
      read_file:
        path:
          pattern: '/workspace/.*'     # must fully match
          deny_pattern: '\\.\\./'         # no path traversal
      fetch_url:
        url:
          pattern: 'https://.*'
    skills:                          # MCP skills extension: globs on skill://<path>/SKILL.md
      allow: ["research/*"]
    methods:                         # any JSON-RPC method except tools/call
      deny: ["tasks/cancel"]

  operator:
    description: Can change things, with a human in the loop.
    inherits: [researcher]
    allow: ["*"]
    deny: ["drop_database"]
    require_approval: ["delete_*", "write_file", "send_email"]
    token_env: OPERATOR_TOKEN        # HTTP proxy: X-Sentinel-Token must match

scanner:
  redact_inputs: true
  redact_outputs: true
  custom_patterns:
    - name: employee_id
      pattern: 'EMP-\\d{6}'
  prompt_injection:
    action: block                    # or "warn"
    threshold: 0.7

hitl:
  mode: cli                          # cli | webhook | auto_approve | auto_deny
  timeout_seconds: 120
  tools: ["shell_exec"]
  rules:
    - tool: run_sql
      when: { query: '(?i)\\b(drop|delete|truncate|alter)\\b' }
      reason: destructive SQL
  webhook:
    url: ${SENTINEL_WEBHOOK_URL:-}
    callback_base_url: http://127.0.0.1:8765

audit:
  path: .sentinel/audit.db
  log_arguments: true

tasks:
  bind_to_agent: true                # only the creating agent may poll/cancel a task

upstream:
  command: ["python", "-m", "my_mcp_server"]
  # url: http://127.0.0.1:8000/mcp
"""


@app.command()
def init(
    path: Annotated[Path, typer.Argument(help="Where to write the config.")] = Path(
        "sentinel.yaml"
    ),
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Overwrite an existing file.")
    ] = False,
) -> None:
    """Write a commented starter sentinel.yaml."""
    if path.exists() and not force:
        err.print(f"[yellow]{path} already exists[/] (use --force to overwrite)")
        raise typer.Exit(1)
    path.write_text(SAMPLE_CONFIG, encoding="utf-8")
    SentinelConfig.from_yaml_string(SAMPLE_CONFIG)  # sanity check
    out.print(f"[green]wrote[/] {path}. Next: [bold]mcp-rbac-gateway validate -c {path}[/]")


def main() -> None:  # pragma: no cover - console script entry point
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
