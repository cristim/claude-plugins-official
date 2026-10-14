import json
import os
import subprocess
import sys

import pytest

from conftest import (
    HOOKS_DIR, STUB_VULN, VULN_PY, bash_payload, commit_file, git,
    metrics_of, run_hook, stop_payload, ups_payload,
)


@pytest.fixture
def codex_env(hook_env):
    return {**{k: v for k, v in hook_env.items()
               if not k.startswith(("CODEX", "SG_AGENTIC", "ANTHROPIC_CUSTOM"))},
            "SG_AGENTIC_COMMIT_REVIEW": "0"}


def invoke(payload, env):
    result = subprocess.run(
        [sys.executable, str(HOOKS_DIR / ("security_reminder_hook.py" if env.get("SG_TEST_ORIGINAL_HOOK") else "codex_hook.py"))],
        input=payload if isinstance(payload, str) else json.dumps(payload),
        capture_output=True, text=True, env=env, timeout=120,
    )
    assert result.returncode in (0, 2), result.stderr
    output = json.loads(result.stdout) if result.stdout.strip() else {}
    assert set(output) <= {"hookSpecificOutput", "decision", "reason", "systemMessage"}
    return result.returncode, output, result.stderr


def patch_payload(cwd, patch, response="Success. Updated the following files:"):
    return {"session_id": "patch", "cwd": str(cwd),
            "hook_event_name": "PostToolUse", "tool_name": "apply_patch",
            "tool_input": {"command": patch}, "tool_response": response}


def context(output):
    return output.get("hookSpecificOutput", {}).get("additionalContext", "")


@pytest.mark.parametrize("payload", ["{invalid", "[]", "null"])
def test_malformed_input_is_empty(payload, codex_env):
    assert invoke(payload, codex_env)[:2] == (0, {})


def test_clean_bash_and_disabled_are_empty(workspace, codex_env):
    _, repo = workspace
    payload = bash_payload(repo, "echo hello")
    payload["tool_response"] = "hello\n"
    assert invoke(payload, codex_env)[:2] == (0, {})
    payload = patch_payload(repo, "*** Begin Patch\n*** Add File: app.py\n+" + VULN_PY.replace("\n", "\n+").rstrip("+") + "*** End Patch")
    assert invoke(payload, {**codex_env, "SECURITY_GUIDANCE_DISABLE": "1"})[:2] == (0, {})


@pytest.mark.parametrize("compound", [False, True])
def test_raw_bash_commit_findings_and_dedup(workspace, codex_env, stub_api, compound):
    _, repo = workspace
    stub_api.vulns = [STUB_VULN]
    _, out = commit_file(repo, "app.py", VULN_PY)
    payload = bash_payload(repo, "git commit -m change" + ("; false" if compound else ""),
                           tool_use_id="commit-1")
    payload["tool_response"] = out + ("\nfailed later\n" if compound else "")
    rc, output, stderr = invoke(payload, {**codex_env, "SG_AGENTIC_COMMIT_REVIEW": "0" if codex_env.get("SG_TEST_ORIGINAL_HOOK") else "1"})
    assert rc == 2 and "command_injection" in context(output)
    assert "command_injection" in stderr
    assert stub_api.calls
    assert invoke(payload, codex_env)[:2] == (0, {})


def test_push_sweep_findings(workspace, codex_env, stub_api):
    _, repo = workspace
    stub_api.vulns = [STUB_VULN]
    base = git(repo, "rev-parse", "HEAD").strip()
    sha, _ = commit_file(repo, "app.py", VULN_PY)
    payload = bash_payload(repo, "git push origin main")
    payload["tool_response"] = f"To /local/remote\n   {base[:7]}..{sha[:7]}  main -> main\n"
    rc, output, _ = invoke(payload, codex_env)
    assert rc == 2 and "command_injection" in context(output)


def test_stop_findings_preserve_block(workspace, codex_env, stub_api):
    _, repo = workspace
    invoke(ups_payload(repo), codex_env)
    (repo / "app.py").write_text(VULN_PY)
    stub_api.vulns = [STUB_VULN]
    rc, output, _ = invoke(stop_payload(repo), codex_env)
    assert rc == 2 and output["decision"] == "block"
    assert "command_injection" in output["reason"]


def test_multiple_patch_paths_and_added_content_only(workspace, codex_env):
    _, repo = workspace
    patch = """*** Begin Patch
*** Add File: added.py
+import pickle
+pickle.loads(user)
*** Update File: app.py
@@
-print('hi')
+subprocess.call(user, shell=True)
*** Update File: before.py
*** Move to: moved.py
@@
-safe = True
+yaml.load(user)
*** Delete File: deleted.py
*** Update File: cleaned.py
@@
-subprocess.call(user, shell=True)
+safe = True
*** End Patch
"""
    rc, output, _ = invoke(patch_payload(repo, patch), codex_env)
    text = context(output)
    assert rc == 0
    assert "pickle" in text and "shell=True" in text and "yaml" in text
    state_files = list(__import__("pathlib").Path(codex_env["SECURITY_WARNINGS_STATE_DIR"]).glob("*.json"))
    state = "\n".join(p.read_text() for p in state_files)
    assert str(repo / "moved.py") in state
    assert str(repo / "deleted.py") in state
    assert str(repo / "cleaned.py") in state
    assert "cleaned.py-command" not in state
    assert invoke(patch_payload(repo, patch), codex_env)[:2] == (0, {})


@pytest.mark.parametrize("response", ["Failed to find expected lines", "Error: patch failed", ""])
def test_failed_patch_does_not_scan(workspace, codex_env, response):
    _, repo = workspace
    patch = "*** Begin Patch\n*** Add File: app.py\n+subprocess.call(user, shell=True)\n*** End Patch"
    assert invoke(patch_payload(repo, patch, response), codex_env)[:2] == (0, {})


def test_adapter_never_bootstraps_sdk(monkeypatch, capsys):
    import codex_hook
    import security_reminder_hook as hook
    import io

    monkeypatch.setenv("SG_AGENTIC_COMMIT_REVIEW", "1")
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(bash_payload(os.getcwd(), "echo ok"))))
    monkeypatch.setattr(hook, "_maybe_bootstrap_agent_sdk_async", lambda: pytest.fail("bootstrap started"))
    assert codex_hook.main() == 0
    assert os.environ["SG_AGENTIC_COMMIT_REVIEW"] == "0"
    assert capsys.readouterr().out == ""


def test_claude_output_still_contains_telemetry(workspace, hook_env):
    _, repo = workspace
    payload = bash_payload(repo, "git commit -m change")
    _, stdout, _ = run_hook(payload, hook_env)
    assert metrics_of(stdout) is not None


def test_review_error_preserves_exit_and_guidance(workspace, codex_env, stub_api):
    _, repo = workspace
    stub_api.status = 401
    _, out = commit_file(repo, "app.py", VULN_PY)
    payload = bash_payload(repo, "git commit -m change")
    payload["tool_response"] = out
    rc, output, stderr = invoke(payload, codex_env)
    assert rc == 2 and "HTTP 401" in context(output) and "HTTP 401" in stderr
