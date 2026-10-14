#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from pathlib import Path
from typing import Any


def patch_edits(payload: dict[str, Any]) -> list[dict[str, Any]]:
    response = payload.get("tool_response", "")
    if not isinstance(response, str) or not response.startswith("Exit code: 0\n"):
        return []
    _, delimiter, output = response.partition("\nOutput:\n")
    if not delimiter or not output.startswith("Success. Updated the following files:"):
        return []
    tool_input = payload.get("tool_input", {})
    patch = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
    if not isinstance(patch, str):
        return []
    edits = []
    path = None
    added: list[str] = []
    cwd = Path(payload.get("cwd") or os.getcwd())

    def append_edit() -> None:
        if path is not None:
            edits.append({**payload, "tool_name": "Edit", "tool_input": {
                "file_path": str((cwd / path).resolve()),
                "new_string": "\n".join(added),
            }})

    for line in patch.splitlines():
        if line.startswith(("*** Add File: ", "*** Update File: ", "*** Delete File: ")):
            append_edit()
            path = line.partition(": ")[2]
            added = []
        elif line.startswith("*** Move to: "):
            path = line.partition(": ")[2]
        elif line == "*** End Patch":
            append_edit()
            path = None
        elif path is not None and line.startswith("+"):
            added.append(line[1:])
    return edits


def invoke_hook(hook: Any, payload: dict[str, Any]) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    original_stdin = sys.stdin
    exit_code = 0
    try:
        sys.stdin = io.StringIO(json.dumps(payload))
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                hook.main()
            except SystemExit as exc:
                exit_code = exc.code if isinstance(exc.code, int) else 1
    finally:
        sys.stdin = original_stdin
    return exit_code, stdout.getvalue(), stderr.getvalue()


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    if not isinstance(payload, dict):
        return 0

    os.environ["SG_AGENTIC_COMMIT_REVIEW"] = "0"
    import security_reminder_hook as hook

    # Codex has no Claude SDK lifecycle, including the PostToolUse rescue path.
    hook._maybe_bootstrap_agent_sdk_async = lambda: None
    event = payload.get("hook_event_name")
    if event == "PostToolUse" and payload.get("tool_name") == "apply_patch":
        invocations = patch_edits(payload)
    else:
        if payload.get("tool_name") == "Bash" and isinstance(payload.get("tool_response"), str):
            payload = {**payload, "tool_response": {
                "stdout": payload["tool_response"], "stderr": "", "interrupted": False,
            }}
        invocations = [payload]

    context, reasons, messages = [], [], []
    exit_code = 0
    for invocation in invocations:
        code, stdout, stderr = invoke_hook(hook, invocation)
        exit_code = max(exit_code, code)
        if stderr:
            sys.stderr.write(stderr)
        for line in stdout.splitlines():
            row = json.loads(line)
            specific = row.get("hookSpecificOutput", {})
            if specific.get("additionalContext"):
                context.append(specific["additionalContext"])
            if row.get("decision") == "block" and row.get("reason"):
                reasons.append(row["reason"])
            if row.get("systemMessage"):
                messages.append(row["systemMessage"])
        if code == 2 and stderr and event == "PostToolUse":
            context.append(stderr)

    output: dict[str, Any] = {}
    if context:
        output["hookSpecificOutput"] = {
            "hookEventName": event,
            "additionalContext": "\n\n".join(dict.fromkeys(context)),
        }
    if reasons:
        output.update(decision="block", reason="\n\n".join(dict.fromkeys(reasons)))
    if messages:
        output["systemMessage"] = "\n\n".join(dict.fromkeys(messages))
    if output:
        print(json.dumps(output))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
