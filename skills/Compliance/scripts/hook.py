#!/usr/bin/env python3
"""Claude Code hook for the Compliance skill: one script, two events. Stdlib only.

PostToolUse (Write, Edit, MultiEdit): run the line rules on the text Claude just
wrote (not the whole file, so it never nags about code that was already there),
remember which file changed, and hand any finding back to Claude as
additionalContext. Fast and never blocking.

Stop: if the turn changed code (or a manifest changed since the last scan), scan
the project. New critical/high findings in files touched this turn block the stop
once, so Claude fixes them or tells the user. Anything else still open at
critical/high, and new mediums, become one warning line for the user. The first
scan of a project only reports; it never makes Claude rework old code unasked.

Silent when there is nothing to say. Off switches: COMPLIANCE_DISABLE=1, or
"hooks": false in the project's .compliance/profile.json.
"""
import datetime as dt
import fnmatch
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scan  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
MARKERS = (".compliance", ".git", "package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml",
           "Gemfile", "composer.json", "pubspec.yaml", "Dockerfile", "index.html")
MANIFESTS = ("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt", "pyproject.toml",
             "Pipfile", "go.mod", "Cargo.toml", "Gemfile", "composer.json", "Dockerfile", ".dockerignore", "nginx.conf")
EDIT_SHOW = ("critical", "high", "medium")
BLOCK = ("critical", "high")


def project_root(path):
    """Nearest folder with a project marker. Never the home folder or above it."""
    home = os.path.abspath(os.path.expanduser("~"))
    d = os.path.abspath(path if os.path.isdir(path) else os.path.dirname(path))
    while d != home:
        if any(os.path.exists(os.path.join(d, m)) for m in MARKERS):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent
    return None


def skipped(path):
    p = os.path.abspath(path)
    own = (os.path.join(os.path.expanduser("~"), ".claude"), PLUGIN_ROOT)
    return any(p == o or p.startswith(o + os.sep) for o in own)


def hooks_off(root):
    prof = scan.load_json(os.path.join(root, scan.STATE_DIR, "profile.json"), {})
    return isinstance(prof, dict) and prof.get("hooks") is False


def session_file(session):
    base = os.path.join(tempfile.gettempdir(), "claude-compliance")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, re.sub(r"[^A-Za-z0-9_.-]", "_", session or "default") + ".json")


def waived(root, f):
    today = dt.date.today().isoformat()
    for w in scan.load_json(os.path.join(root, scan.STATE_DIR, "waivers.json"), []):
        if isinstance(w, dict) and w.get("rule") in (f["rule"], "*") and fnmatch.fnmatch(f["path"], w.get("path", "*")) \
                and str(w.get("until", "9999-12-31")) >= today:
            return True
    return False


def bullet(f, with_path=True):
    loc = scan.where(f) if with_path else ("line {}".format(f["line"]) if f["line"] else "project")
    return "- [{}] {} {}: {}\n  Fix: {}\n  Breaks: {}".format(f["severity"].upper(), f["rule"], loc, f["title"], f["fix"],
                                                          scan.display_maps(f["maps"]))


def on_edit(data):
    tool, inp = data.get("tool_name", ""), data.get("tool_input") or {}
    path = inp.get("file_path") or ""
    if tool not in ("Write", "Edit", "MultiEdit") or not path or skipped(path) or scan.ftype(path) not in scan.SCANNABLE:
        return None
    root = project_root(path)
    if not root or hooks_off(root):
        return None
    rel = os.path.relpath(os.path.abspath(path), root).replace(os.sep, "/")
    state_path = session_file(data.get("session_id", ""))
    state = scan.load_json(state_path, {})
    state = state if isinstance(state, dict) else {}
    touched = state.setdefault("touched", {}).setdefault(root, [])
    if rel not in touched:
        touched.append(rel)
    if tool == "Write":
        new = inp.get("content", "")
    elif tool == "Edit":
        new = inp.get("new_string", "")
    else:
        new = "\n".join(e.get("new_string", "") for e in inp.get("edits") or [] if isinstance(e, dict))
    warned = set(state.get("warned", []))
    fresh = [f for f in scan.scan_text(rel, new or "") if f["severity"] in EDIT_SHOW and f["fingerprint"] not in warned
             and not waived(root, f)]
    state["warned"] = sorted(warned | {f["fingerprint"] for f in fresh})
    scan.save_json(state_path, state)
    if not fresh:
        return None
    lines = (scan.read(os.path.abspath(path)) or "").split("\n")
    for f in fresh:  # line numbers in the file, not in the edited fragment
        probe = f["snippet"].split("…")[0][:60]
        f["line"] = next((i + 1 for i, l in enumerate(lines) if probe and probe in l.strip()), f["line"])
    msg = ["Compliance check on {} (the code you just wrote):".format(rel)] + [bullet(f, False) for f in fresh[:6]]
    if len(fresh) > 6:
        msg.append("- ... {} more".format(len(fresh) - 6))
    msg.append("Fix these now if the fix is mechanical and in scope. If it needs the user's decision, tell them rather "
               "than guessing. For a false positive, add `compliance-ignore: RULE-ID reason` on that line.")
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "\n".join(msg)}}


def manifests_changed(root):
    try:
        last = os.path.getmtime(os.path.join(scan.report_dir(root), "state.json"))
    except OSError:
        return False  # never scanned: a turn that edited nothing doesn't start a first scan
    return any(os.path.getmtime(p) > last for p in (os.path.join(root, m) for m in MANIFESTS) if os.path.exists(p))


def on_stop(data):
    if data.get("stop_hook_active"):
        return None  # Claude is already continuing because of a stop hook; don't loop
    state_path = session_file(data.get("session_id", ""))
    state = scan.load_json(state_path, {})
    state = state if isinstance(state, dict) else {}
    roots = {r: v for r, v in (state.get("touched") or {}).items() if os.path.isdir(r)}
    here = project_root(data.get("cwd") or os.getcwd())
    if here and here not in roots and manifests_changed(here):
        roots[here] = [m for m in MANIFESTS if os.path.exists(os.path.join(here, m))]
    state["touched"] = {}
    scan.save_json(state_path, state)
    blocking, notes = [], []
    for root, rels in sorted(roots.items()):
        if hooks_off(root):
            continue
        r = scan.scan_project(root)
        name = os.path.basename(root) or root
        open_ = [f for f in r["findings"] if f["status"] == "open"]
        serious = {k: v for k, v in scan.counts(open_).items() if k in ("critical", "high", "medium")}
        if r["first_scan"]:
            if serious:
                notes.append("first scan of {} found {} already in the code; report: {}".format(
                    name, scan.fmt_counts(serious), r["report"]))
            continue
        mine = [f for f in open_ if f["new"] and f["severity"] in BLOCK and (not f["path"] or f["path"] in rels)]
        blocking += [(name, r["report"], f) for f in mine]
        mine_fps = {f["fingerprint"] for f in mine}
        rest = scan.counts([f for f in open_ if f["fingerprint"] not in mine_fps and f["severity"] in BLOCK])
        new_med = sum(1 for f in open_ if f["new"] and f["severity"] == "medium")
        if rest or new_med:
            parts = ["{} still open".format(scan.fmt_counts(rest))] if rest else []
            parts += ["{} new medium".format(new_med)] if new_med else []
            notes.append("{}: {}; report: {}".format(name, ", ".join(parts), r["report"]))
    out = {}
    if blocking:
        sev = scan.fmt_counts(scan.counts([f for _, _, f in blocking]))
        reports = sorted({rep for _, rep, _ in blocking})
        lines = ["Compliance check: this turn introduced {} that break compliance requirements.".format(sev), ""]
        lines += [bullet(f) for _, _, f in blocking[:10]]
        if len(blocking) > 10:
            lines.append("- ... {} more in the report".format(len(blocking) - 10))
        lines += ["", "Fix what is mechanical now. If a fix needs the user's call (legal text, removing a feature, "
                  "accepting a risk), don't guess: tell them plainly what is non-compliant and why. A leaked key "
                  "must be rotated by the user even after you remove it; say so. Report: " + ", ".join(reports) +
                  " (the Compliance skill has the fix playbook). Then continue with the user's original request."]
        out = {"decision": "block", "reason": "\n".join(lines),
               "systemMessage": "Compliance: {} introduced this turn; Claude is addressing them.".format(sev)}
        if notes:
            out["systemMessage"] += " Also: " + " | ".join(notes)
    elif notes:
        out = {"systemMessage": "Compliance: " + " | ".join(notes)}
    return out or None


def main():
    if os.environ.get("COMPLIANCE_DISABLE") == "1":
        return 0
    try:
        data = json.load(sys.stdin)
    except ValueError:
        return 0
    event = data.get("hook_event_name", "")
    try:
        out = on_edit(data) if event == "PostToolUse" else on_stop(data) if event == "Stop" else None
    except Exception as exc:  # a broken hook must never break the session
        sys.stderr.write("compliance hook: {}\n".format(exc))
        return 0
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
