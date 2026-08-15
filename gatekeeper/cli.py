"""Command line entry point.

    gatekeeper triage            run the agent; writes an audit log
    gatekeeper log <file>        read an audit log as a decision tree
    gatekeeper verify <file>     re-hash an audit log and check the chain
    gatekeeper eval              score the classifier against the labelled corpus
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from gatekeeper.audit import AuditLog, EventKind, read_events, verify_chain
from gatekeeper.config import load_settings
from gatekeeper.planner import Planner
from gatekeeper.profile import Profile
from gatekeeper.screening import Action
from gatekeeper.sources import BOARDS, CassetteMiss, Fetcher, Mode

console = Console()

ACTION_STYLE = {
    "ACT": "bold green",
    "IGNORE": "dim",
    "FLAG": "bold yellow",
    "REJECT": "bold red",
}


def cmd_triage(args: argparse.Namespace) -> int:
    settings = load_settings(budget_limit=args.budget)
    mode = Mode(args.mode)

    boards = args.boards or list(BOARDS)
    unknown = [b for b in boards if b not in BOARDS]
    if unknown:
        console.print(f"[red]Unknown board(s):[/red] {', '.join(unknown)}")
        console.print(f"Available: {', '.join(BOARDS)}")
        return 2

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    log_path = settings.run_dir / f"{run_id}.jsonl"

    console.print(f"[bold]gatekeeper[/bold]  mode={mode.value}  boards={', '.join(boards)}")
    console.print(
        f"model budget: {settings.budget.limit} call(s), "
        + ("[green]key present[/green]" if settings.llm_available
           else "[yellow]no GEMINI_API_KEY — rules only, ambiguous items will FLAG[/yellow]")
    )

    try:
        with AuditLog(log_path, run_id=run_id) as audit:
            audit.emit(
                EventKind.RUN_START,
                summary=f"triage {', '.join(boards)} (mode={mode.value})",
                step_id="run",
                findings=[
                    ("task", f"find postings matching profile: {args.profile_name or Profile().name}"),
                    (
                        "llm",
                        f"adjudicator {'available' if settings.llm_available else 'unavailable'}; "
                        f"budget {settings.budget.limit}",
                    ),
                ],
                data={
                    "boards": boards,
                    "mode": mode.value,
                    "limit": args.limit,
                    "budget": settings.budget.limit,
                    "llm_available": settings.llm_available,
                },
            )

            profile = Profile.load(Path(args.profile) if args.profile else None)
            planner = Planner(
                settings=settings,
                audit=audit,
                fetcher=Fetcher(settings.cassette_dir, mode, audit),
                profile=profile,
                board_ids=boards,
                limit=args.limit,
                target=args.target,
                inject=args.inject,
            )
            state = planner.run()

            audit.emit(
                EventKind.RUN_END,
                summary=(
                    f"{len(state.decisions)} decision(s) over {planner.step} planning step(s); "
                    f"{settings.budget.spent} model call(s) spent"
                ),
                step_id="run",
                data={
                    "decisions": len(state.decisions),
                    "steps": planner.step,
                    "model_calls": settings.budget.spent,
                    "trust": dict(state.trust),
                    "external_fetches": state.external_fetches,
                },
            )
    except CassetteMiss as exc:
        console.print(f"[red]Cassette miss:[/red] {exc}")
        return 1

    _report(state, planner)
    console.print(f"\nAudit log: [cyan]{log_path}[/cyan]")
    console.print(f"  read it:   [dim]gatekeeper log {log_path}[/dim]")
    console.print(f"  verify it: [dim]gatekeeper verify {log_path}[/dim]")
    return 0


def _report(state, planner) -> None:
    by_action: dict[str, list] = {}
    for d in state.decisions.values():
        by_action.setdefault(d.action.value, []).append(d)

    table = Table(title="Triage outcome", show_lines=False)
    table.add_column("Action")
    table.add_column("n", justify="right")
    table.add_column("Meaning")
    for action, meaning in (
        ("ACT", "shortlisted: safe, coherent, and relevant"),
        ("IGNORE", "safe but not a match for the profile"),
        ("FLAG", "held for a human: unverified or incoherent"),
        ("REJECT", "hostile content; quarantined"),
    ):
        items = by_action.get(action, [])
        table.add_row(f"[{ACTION_STYLE[action]}]{action}[/]", str(len(items)), meaning)
    console.print()
    console.print(table)

    for action in ("REJECT", "FLAG", "ACT"):
        items = by_action.get(action, [])
        if not items:
            continue
        console.print(f"\n[{ACTION_STYLE[action]}]{action}[/] ({len(items)})")
        for d in items[:8]:
            console.print(f"  [bold]{d.label[:72]}[/bold]  [dim]{d.ref}[/dim]")
            console.print(f"    {d.rationale[:300]}")
        if len(items) > 8:
            console.print(f"  [dim]… and {len(items) - 8} more (see the audit log)[/dim]")

    if state.trust:
        console.print()
        for src, score in state.trust.items():
            style = "green" if score >= 60 else "red"
            # escape: rich would read a bare [remoteok] as a style tag
            console.print(f"  trust\\[{src}] = [{style}]{score}[/{style}]")


def cmd_log(args: argparse.Namespace) -> int:
    path = Path(args.log)
    if not path.exists():
        console.print(f"[red]No such log:[/red] {path}")
        return 1

    kinds = set(args.kind or [])
    for event in read_events(path):
        if kinds and event.kind not in kinds:
            continue
        if args.ref and args.ref not in event.step_id and args.ref not in event.summary:
            continue

        colour = {
            "PLAN": "magenta",
            "SCREEN": "cyan",
            "DECIDE": "bold",
            "CONSISTENCY": "blue",
            "FETCH": "dim",
            "RUN_START": "bold green",
            "RUN_END": "bold green",
        }.get(event.kind, "white")

        console.print(
            f"[dim]{event.seq:>4}[/dim] [{colour}]{event.kind:<12}[/{colour}] "
            f"[dim]{event.step_id}[/dim]  {event.summary}"
        )
        if not args.quiet:
            for f in event.findings:
                console.print(f"        [dim]·[/dim] [italic]{f['code']}[/italic]: {f['detail']}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.log)
    if not path.exists():
        console.print(f"[red]No such log:[/red] {path}")
        return 1
    ok, message = verify_chain(path)
    if ok:
        console.print(f"[green]chain OK[/green] — {message}")
        return 0
    console.print(f"[red]CHAIN BROKEN[/red] — {message}")
    return 1


def cmd_eval(args: argparse.Namespace) -> int:
    from gatekeeper.evaluate import run_eval

    return run_eval(console, use_llm=args.llm, budget=args.budget)


def main() -> int:
    parser = argparse.ArgumentParser(prog="gatekeeper", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    t = sub.add_parser("triage", help="run the agent over the job boards")
    t.add_argument("--mode", choices=[m.value for m in Mode], default=Mode.AUTO.value,
                   help="auto: replay when cached else fetch. replay: never touch the network.")
    t.add_argument("--boards", nargs="*", help=f"subset of: {', '.join(BOARDS)}")
    t.add_argument("--limit", type=int, default=25, help="cap postings taken per board")
    t.add_argument("--budget", type=int, default=25, help="max model calls for this run")
    t.add_argument("--target", type=int, default=3,
                   help="stop once this many candidates are shortlisted; a productive "
                        "first board then leaves later sources unfetched")
    t.add_argument("--inject", type=int, default=0, metavar="N",
                   help="splice N labelled synthetic attacks from corpus/adversarial.jsonl "
                        "into the first board. Every one is marked synthetic in the log.")
    t.add_argument("--profile", help="path to a profile JSON")
    t.add_argument("--profile-name", help=argparse.SUPPRESS)
    t.set_defaults(func=cmd_triage)

    l = sub.add_parser("log", help="read an audit log")
    l.add_argument("log")
    l.add_argument("--kind", nargs="*", help="filter to event kinds, e.g. PLAN SCREEN")
    l.add_argument("--ref", help="filter to one item reference")
    l.add_argument("--quiet", action="store_true", help="summaries only, no findings")
    l.set_defaults(func=cmd_log)

    v = sub.add_parser("verify", help="re-hash an audit log and check the chain")
    v.add_argument("log")
    v.set_defaults(func=cmd_verify)

    e = sub.add_parser("eval", help="score the classifier against the labelled corpus")
    e.add_argument("--llm", action="store_true", help="also run the LLM tier (needs a key)")
    e.add_argument("--budget", type=int, default=40)
    e.set_defaults(func=cmd_eval)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
