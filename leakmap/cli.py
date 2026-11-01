"""leakmap command line."""

import argparse
import json
import sys
import tempfile
import webbrowser
from pathlib import Path

from . import __version__, report
from .policy import ConfigError, check, load_config, read_lock, write_lock
from .runner import ProxyError, run
from .vendors import catalog_size, resolve

OUT = Path(".leakmap")


def _load_run(path: Path) -> dict:
    if not path.exists():
        sys.exit(f"leakmap: {path} not found. Run `leakmap run -- <your tests>` first.")
    return json.loads(path.read_text())


def _print_issues(issues: list[dict]) -> int:
    marks = {"fail": "✗", "warn": "!", "info": "·"}
    for issue in issues:
        print(f"  {marks[issue['level']]} {issue['message']}")
    fails = [i for i in issues if i["level"] == "fail"]
    if fails:
        print(f"\nleakmap check failed: {len(fails)} new or denied data flow(s).")
        print("If these flows are intended, review them and run `leakmap baseline` to accept.")
        return 1
    print("leakmap check passed: no new data flows.")
    return 0


def _run_check(run_data: dict, lock_path: Path, config: dict) -> int:
    if not lock_path.exists():
        print(f"leakmap: no baseline at {lock_path}. Review the report, then run `leakmap baseline`.")
        return 2
    return _print_issues(check(run_data, read_lock(lock_path), config))


def cmd_run(args) -> int:
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        sys.exit("usage: leakmap run [options] -- <command> [args...]")
    config = load_config(Path(args.config))
    code, summary = run(command, Path(args.out), stub=args.stub, ner=args.ner,
                        min_confidence=config["min_confidence"], ignore_hosts=tuple(config["ignore_hosts"]))
    print(report.terminal(summary, config["home_country"]), end="")
    print(f"\n  Saved {args.out}/run.json · `leakmap report --format html` for the full report")
    if args.check:
        result = _run_check(summary, Path(args.lock), config)
        return code or result
    return code


def cmd_report(args) -> int:
    config = load_config(Path(args.config))
    text = report.render(_load_run(Path(args.run)), args.format, config["home_country"])
    if args.output:
        Path(args.output).write_text(text)
        print(f"Wrote {args.output}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_baseline(args) -> int:
    lock = write_lock(_load_run(Path(args.run)), Path(args.lock))
    n = sum(1 for p in lock["processors"].values() if p["data"])
    print(f"Wrote {args.lock}: {len(lock['processors'])} third parties, {n} receiving personal data. Commit it.")
    return 0


def cmd_check(args) -> int:
    config = load_config(Path(args.config))
    return _run_check(_load_run(Path(args.run)), Path(args.lock), config)


def cmd_vendors(args) -> int:
    if not args.hosts:
        print(f"{catalog_size()} vendors in the catalog. Pass hostnames to look them up.")
        return 0
    for host in args.hosts:
        v = resolve(host)
        print(f"{host}: {v.name} ({v.country}, {v.kind})" if v.kind != "unclassified" else f"{host}: not in catalog")
    return 0


def cmd_demo(args) -> int:
    with tempfile.TemporaryDirectory(prefix="leakmap-demo-") as tmp:
        code, summary = run([sys.executable, "-m", "leakmap.demo_app"], Path(tmp), stub=True)
    if code != 0:
        print(f"leakmap: demo app exited with {code}", file=sys.stderr)
        return code
    print(report.terminal(summary, "IN"), end="")
    out = Path(args.output).resolve()
    out.write_text(report.html_report(summary, "IN"))
    print(f"\n  Full report: {out}")
    print("  Everything above was fake data, answered locally. Nothing left your machine.")
    print("  Try it on your app: leakmap run -- pytest")
    if args.open:
        webbrowser.open(out.as_uri())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakmap",
        description="See what personal data your app sends to third parties. Fail CI when a new flow appears.",
    )
    parser.add_argument("--version", action="version", version=f"leakmap {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(p, lock=False):
        p.add_argument("--config", default="leakmap.yaml", help="settings and deny rules (default: leakmap.yaml)")
        p.add_argument("--run", default=str(OUT / "run.json"), help="run file (default: .leakmap/run.json)")
        if lock:
            p.add_argument("--lock", default="leakmap.lock", help="baseline file (default: leakmap.lock)")

    p = sub.add_parser("run", help="run a command and record what it sends out")
    p.add_argument("--stub", action="store_true", help="answer every request locally; nothing reaches the network")
    p.add_argument("--check", action="store_true", help="after the run, compare against the baseline and fail on new flows")
    p.add_argument("--ner", action="store_true", help="also find names and addresses with the optional model (leakmap[ner])")
    p.add_argument("--out", default=str(OUT), help="output directory (default: .leakmap)")
    p.add_argument("--config", default="leakmap.yaml")
    p.add_argument("--lock", default="leakmap.lock")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- command to run")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("report", help="render the last run")
    common(p)
    p.add_argument("--format", choices=["terminal", "md", "html", "dpdp", "json"], default="terminal")
    p.add_argument("-o", "--output", help="write to a file instead of stdout")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("baseline", help="accept the current flows into leakmap.lock")
    common(p, lock=True)
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("check", help="fail if the last run has flows not in leakmap.lock")
    common(p, lock=True)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("vendors", help="look up which company a hostname belongs to")
    p.add_argument("hosts", nargs="*")
    p.set_defaults(func=cmd_vendors)

    p = sub.add_parser("demo", help="see a report on a fake app in a few seconds, fully offline")
    p.add_argument("-o", "--output", default="leakmap-demo.html")
    p.add_argument("--open", action="store_true", help="open the HTML report in a browser")
    p.set_defaults(func=cmd_demo)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ConfigError, ProxyError) as exc:
        print(f"leakmap: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
