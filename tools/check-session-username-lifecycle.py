#!/usr/bin/env python3
"""Capture and validate session-username lifecycle progress evidence."""

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time


PROGRESS_ENV = "WYL_TEST_SESSION_USERNAME_LIFECYCLE_PROGRESS"
GATE_ENV = "WYL_TEST_SESSION_USERNAME_LIFECYCLE_GATE"
PREFIX = "WYL_SESSION_USERNAME_LIFECYCLE"
EXPECTED_IDS = (
    "close-persists-closed-state",
    "logout-preserves-locked-and-revoked-principals",
    "logout-logs-out-principal",
    "close-inserts-session-fired",
    "close-deactivates-decision-scope",
    "close-rejects-invalid-args",
    "elevate-persists-elevated-state",
    "transitions-insert-session-fired",
    "drop-elevation-persists-active-state",
    "elevated-remains-active-decision-scope",
    "elevated-close-deactivates-decision-scope",
    "idle-timeout-persists-idle-state",
    "idle-deactivates-decision-scope",
    "elevated-idle-timeout-deactivates-scope",
    "expire-persists-expiring-state",
    "expiring-deactivates-decision-scope",
    "expiring-expire-persists-closed-state",
    "expiry-inserts-session-fired",
    "elevated-expire-persists-expiring-state",
    "elevation-rejects-invalid-args",
)
BEGIN_RE = re.compile(
    rf"^{PREFIX} BEGIN id=([a-z0-9-]+) "
    r"ordinal=([1-9][0-9]*) elapsed_ms=(0|[1-9][0-9]*)$"
)
END_RE = re.compile(
    rf"^{PREFIX} END id=([a-z0-9-]+) "
    r"ordinal=([1-9][0-9]*) elapsed_ms=(0|[1-9][0-9]*) "
    r"duration_ms=(0|[1-9][0-9]*) rc=(0|-?[1-9][0-9]*)$"
)


class EvidenceError(RuntimeError):
    """A classified evidence-capture failure."""

    def __init__(self, classification: str, detail: str):
        super().__init__(detail)
        self.classification = classification
        self.detail = detail


@dataclass(frozen=True)
class ProgressRecord:
    phase: str
    check_id: str
    ordinal: int
    elapsed_ms: int
    duration_ms: int | None = None
    rc: int | None = None


class ProgressParser:
    """Validate the exact ordered 20-check progress contract."""

    def __init__(self) -> None:
        self.records: list[ProgressRecord] = []
        self.completed: list[ProgressRecord] = []
        self.active: ProgressRecord | None = None
        self.last_elapsed_ms = 0

    def consume(self, line: str) -> ProgressRecord:
        begin = BEGIN_RE.fullmatch(line)
        if begin is not None:
            return self._consume_begin(begin)
        end = END_RE.fullmatch(line)
        if end is not None:
            return self._consume_end(end)
        raise EvidenceError(
            "diagnostic_contract",
            "malformed or privacy-unsafe lifecycle progress record",
        )

    def _consume_begin(self, match: re.Match[str]) -> ProgressRecord:
        if self.active is not None:
            raise EvidenceError(
                "diagnostic_contract", "BEGIN arrived while a check is active"
            )
        ordinal = int(match.group(2))
        expected_ordinal = len(self.completed) + 1
        if ordinal != expected_ordinal or ordinal > len(EXPECTED_IDS):
            raise EvidenceError(
                "diagnostic_contract", "BEGIN ordinal is missing or reordered"
            )
        check_id = match.group(1)
        if check_id != EXPECTED_IDS[ordinal - 1]:
            raise EvidenceError(
                "diagnostic_contract", "BEGIN static check ID does not match"
            )
        elapsed_ms = int(match.group(3))
        if elapsed_ms < self.last_elapsed_ms:
            raise EvidenceError(
                "diagnostic_contract", "BEGIN elapsed time moved backwards"
            )
        record = ProgressRecord("BEGIN", check_id, ordinal, elapsed_ms)
        self.active = record
        self.records.append(record)
        self.last_elapsed_ms = elapsed_ms
        return record

    def _consume_end(self, match: re.Match[str]) -> ProgressRecord:
        if self.active is None:
            raise EvidenceError(
                "diagnostic_contract", "END arrived without an active BEGIN"
            )
        check_id = match.group(1)
        ordinal = int(match.group(2))
        elapsed_ms = int(match.group(3))
        duration_ms = int(match.group(4))
        rc = int(match.group(5))
        if check_id != self.active.check_id or ordinal != self.active.ordinal:
            raise EvidenceError(
                "diagnostic_contract", "END does not match the active BEGIN"
            )
        if elapsed_ms < self.last_elapsed_ms:
            raise EvidenceError(
                "diagnostic_contract", "END elapsed time moved backwards"
            )
        observed_delta = elapsed_ms - self.active.elapsed_ms
        if observed_delta not in (duration_ms, duration_ms + 1):
            raise EvidenceError(
                "diagnostic_contract", "END duration disagrees with elapsed time"
            )
        record = ProgressRecord(
            "END", check_id, ordinal, elapsed_ms, duration_ms, rc
        )
        self.records.append(record)
        self.completed.append(record)
        self.active = None
        self.last_elapsed_ms = elapsed_ms
        return record

    def validate_success(self) -> None:
        if self.active is not None:
            raise EvidenceError(
                "diagnostic_incomplete", "process exited with an active check"
            )
        failed = next((record for record in self.completed if record.rc), None)
        if failed is not None:
            raise EvidenceError(
                "check_failure",
                f"check ordinal {failed.ordinal} returned rc {failed.rc}",
            )
        if len(self.completed) != len(EXPECTED_IDS):
            raise EvidenceError(
                "diagnostic_incomplete", "successful run did not complete 20 checks"
            )
        if len(self.records) != 2 * len(EXPECTED_IDS):
            raise EvidenceError(
                "diagnostic_contract", "successful run did not emit 20 pairs"
            )


@dataclass(frozen=True)
class LifecycleResult:
    classification: str
    returncode: int
    total_duration_ms: int
    records: list[dict[str, object]]
    last_entered: str | None
    last_completed: str | None
    progress_observed_before_exit: bool


@dataclass(frozen=True)
class CompanionResult:
    returncode: int
    duration_ms: int
    stdout_bytes: int
    stderr_bytes: int


def _reader(
    stream: object,
    stream_name: str,
    events: queue.Queue[tuple[str, str, object]],
) -> None:
    try:
        while True:
            line = stream.readline()  # type: ignore[attr-defined]
            if line == "":
                break
            events.put(("line", stream_name, line))
    except BaseException as error:  # delivered to the coordinator thread
        events.put(("error", stream_name, repr(error)))
    finally:
        events.put(("eof", stream_name, None))


def _spawn(
    command: list[str], env: dict[str, str], stdin: int | None = subprocess.PIPE
) -> subprocess.Popen[str]:
    creationflags = 0
    start_new_session = os.name != "nt"
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        return subprocess.Popen(
            command,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            bufsize=1,
            env=env,
            start_new_session=start_new_session,
            creationflags=creationflags,
        )
    except OSError as error:
        raise EvidenceError("spawn_failure", type(error).__name__) from error


def _terminate_process_tree(
    process: subprocess.Popen[object], timeout_seconds: float = 10.0
) -> None:
    if process.poll() is not None:
        return
    deadline = time.monotonic() + timeout_seconds
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(0.1, deadline - time.monotonic()),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EvidenceError(
                "termination_failure", type(error).__name__
            ) from error
        if result.returncode != 0 and process.poll() is None:
            raise EvidenceError(
                "termination_failure", "taskkill did not terminate the process tree"
            )
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=max(0.1, min(2.0, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    try:
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as error:
        raise EvidenceError(
            "termination_failure", "process tree remained alive after termination"
        ) from error


def run_lifecycle(
    command: list[str],
    timeout_seconds: float,
    mode: str = "run",
    base_env: dict[str, str] | None = None,
) -> LifecycleResult:
    env = dict(os.environ if base_env is None else base_env)
    env[PROGRESS_ENV] = "1"
    env.pop(GATE_ENV, None)
    if mode == "prove-pre-exit":
        env[GATE_ENV] = f"end:{len(EXPECTED_IDS)}"
    elif mode == "prove-termination":
        env[GATE_ENV] = "begin:1"
    elif mode != "run":
        raise EvidenceError("harness_usage", "unknown lifecycle run mode")

    process = _spawn(command, env)
    assert process.stdout is not None
    assert process.stderr is not None
    events: queue.Queue[tuple[str, str, object]] = queue.Queue()
    readers = (
        threading.Thread(
            target=_reader, args=(process.stdout, "stdout", events), daemon=True
        ),
        threading.Thread(
            target=_reader, args=(process.stderr, "stderr", events), daemon=True
        ),
    )
    for reader in readers:
        reader.start()

    parser = ProgressParser()
    started = time.monotonic()
    deadline = started + timeout_seconds
    eof_streams: set[str] = set()
    unexpected_output = False
    observed_before_exit = False
    intentional_termination = False
    try:
        while len(eof_streams) != 2 or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process_tree(process)
                active = parser.active.check_id if parser.active else "none"
                raise EvidenceError(
                    "child_timeout", f"bounded timeout; active check {active}"
                )
            try:
                kind, stream_name, payload = events.get(
                    timeout=min(0.25, remaining)
                )
            except queue.Empty:
                continue
            if kind == "eof":
                eof_streams.add(stream_name)
                continue
            if kind == "error":
                raise EvidenceError(
                    "stream_failure", f"{stream_name} reader failed: {payload}"
                )
            line = str(payload).rstrip("\r\n")
            if not line:
                continue
            if stream_name != "stderr" or not line.startswith(PREFIX + " "):
                unexpected_output = True
                continue
            record = parser.consume(line)
            if mode == "prove-pre-exit" and record.phase == "END" \
                    and record.ordinal == len(EXPECTED_IDS):
                if process.poll() is not None:
                    raise EvidenceError(
                        "pre_exit_proof_failure",
                        "final END was not observed while the child was alive",
                    )
                observed_before_exit = True
                assert process.stdin is not None
                process.stdin.write("continue\n")
                process.stdin.flush()
                process.stdin.close()
            elif mode == "prove-termination" and record.phase == "BEGIN":
                if process.poll() is not None:
                    raise EvidenceError(
                        "termination_proof_failure",
                        "BEGIN was not observed while the child was alive",
                    )
                _terminate_process_tree(process)
                intentional_termination = True

        for reader in readers:
            reader.join(timeout=1.0)
            if reader.is_alive():
                raise EvidenceError(
                    "stream_failure", "reader remained alive after process exit"
                )
    except BaseException:
        if process.poll() is None:
            _terminate_process_tree(process)
        raise
    finally:
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()

    if unexpected_output:
        raise EvidenceError(
            "unexpected_output", "child emitted output outside the record grammar"
        )
    returncode = process.returncode
    assert returncode is not None
    total_duration_ms = int((time.monotonic() - started) * 1000)
    if mode == "prove-termination":
        if not intentional_termination or returncode == 0:
            raise EvidenceError(
                "termination_proof_failure", "external termination was not observed"
            )
        if parser.active is None or parser.active.ordinal != 1:
            raise EvidenceError(
                "termination_proof_failure", "active check was not identifiable"
            )
        if parser.completed:
            raise EvidenceError(
                "termination_proof_failure", "terminated check emitted an END"
            )
        classification = "intentional_external_termination"
    else:
        parser.validate_success()
        if returncode != 0:
            raise EvidenceError(
                "child_exit_failure", f"child returned {returncode} after 20 checks"
            )
        if mode == "prove-pre-exit" and not observed_before_exit:
            raise EvidenceError(
                "pre_exit_proof_failure", "pre-exit milestone was not observed"
            )
        classification = "healthy"

    return LifecycleResult(
        classification=classification,
        returncode=returncode,
        total_duration_ms=total_duration_ms,
        records=[asdict(record) for record in parser.records],
        last_entered=(
            parser.active.check_id
            if parser.active is not None
            else parser.completed[-1].check_id if parser.completed else None
        ),
        last_completed=(parser.completed[-1].check_id if parser.completed else None),
        progress_observed_before_exit=observed_before_exit,
    )


def _companion_command(
    command: list[str],
    env: dict[str, str],
    timeout_seconds: float,
) -> CompanionResult:
    started = time.monotonic()
    process = _spawn(command, env, stdin=subprocess.DEVNULL)
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        _terminate_process_tree(process)
        raise EvidenceError("companion_timeout", "companion timed out") from error
    duration_ms = int((time.monotonic() - started) * 1000)
    if process.returncode != 0:
        raise EvidenceError(
            "companion_exit_failure", f"companion returned {process.returncode}"
        )
    return CompanionResult(
        process.returncode,
        duration_ms,
        len(stdout.encode("utf-8")),
        len(stderr.encode("utf-8")),
    )


def run_pair(
    lifecycle_command: list[str],
    companion_command: list[str] | None,
    pair_mode: str,
    timeout_seconds: float,
) -> dict[str, object]:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="wyl-lifecycle-evidence-") as root:
        env = dict(os.environ)
        env.update({"TMPDIR": root, "TMP": root, "TEMP": root})
        companion_result: CompanionResult | None = None
        if companion_command is None:
            lifecycle = run_lifecycle(
                lifecycle_command, timeout_seconds, base_env=env
            )
        elif pair_mode == "serial":
            companion_result = _companion_command(
                companion_command, env, timeout_seconds
            )
            lifecycle = run_lifecycle(
                lifecycle_command, timeout_seconds, base_env=env
            )
        elif pair_mode == "parallel":
            companion = _spawn(
                companion_command, env, stdin=subprocess.DEVNULL
            )
            try:
                lifecycle = run_lifecycle(
                    lifecycle_command, timeout_seconds, base_env=env
                )
                remaining = timeout_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(companion_command, 0)
                companion_stdout, companion_stderr = companion.communicate(
                    timeout=remaining
                )
            except subprocess.TimeoutExpired as error:
                _terminate_process_tree(companion)
                raise EvidenceError(
                    "companion_timeout", "parallel companion timed out"
                ) from error
            except BaseException:
                if companion.poll() is None:
                    _terminate_process_tree(companion)
                raise
            if companion.returncode != 0:
                raise EvidenceError(
                    "companion_exit_failure",
                    f"parallel companion returned {companion.returncode}",
                )
            companion_result = CompanionResult(
                companion.returncode,
                int((time.monotonic() - started) * 1000),
                len(companion_stdout.encode("utf-8")),
                len(companion_stderr.encode("utf-8")),
            )
        else:
            raise EvidenceError("harness_usage", "invalid pair mode")
    return {
        "classification": "healthy",
        "pair_mode": pair_mode if companion_command is not None else "isolated",
        "pair_total_duration_ms": int((time.monotonic() - started) * 1000),
        "companion": (
            None
            if companion_result is None
            else asdict(companion_result)
        ),
        "lifecycle": asdict(lifecycle),
    }


def _valid_transcript(count: int = len(EXPECTED_IDS)) -> list[str]:
    lines: list[str] = []
    elapsed = 0
    for ordinal, check_id in enumerate(EXPECTED_IDS[:count], 1):
        lines.append(
            f"{PREFIX} BEGIN id={check_id} ordinal={ordinal} "
            f"elapsed_ms={elapsed}"
        )
        elapsed += ordinal
        lines.append(
            f"{PREFIX} END id={check_id} ordinal={ordinal} "
            f"elapsed_ms={elapsed} duration_ms={ordinal} rc=0"
        )
    return lines


def _expect_parser_failure(lines: list[str], finish: bool = True) -> None:
    parser = ProgressParser()
    try:
        for line in lines:
            parser.consume(line)
        if finish:
            parser.validate_success()
    except EvidenceError:
        return
    raise AssertionError("mutated progress stream was accepted")


def _fake_child_source() -> str:
    return f"""
import os
import sys
import time

ids = {EXPECTED_IDS!r}
gate = os.environ.get({GATE_ENV!r})
started = time.monotonic_ns()
for ordinal, check_id in enumerate(ids, 1):
    elapsed = (time.monotonic_ns() - started) // 1_000_000
    print({PREFIX!r} + f" BEGIN id={{check_id}} ordinal={{ordinal}} "
          f"elapsed_ms={{elapsed}}", file=sys.stderr, flush=True)
    if gate == f"begin:{{ordinal}}":
        sys.stdin.readline()
    ended = (time.monotonic_ns() - started) // 1_000_000
    duration = ended - elapsed
    rc = 7 if os.environ.get("WYL_FAKE_LIFECYCLE_FAIL") == str(ordinal) else 0
    print({PREFIX!r} + f" END id={{check_id}} ordinal={{ordinal}} "
          f"elapsed_ms={{ended}} duration_ms={{duration}} rc={{rc}}",
          file=sys.stderr, flush=True)
    if gate == f"end:{{ordinal}}":
        sys.stdin.readline()
    if rc:
        raise SystemExit(rc)
""".lstrip()


def self_test() -> int:
    parser = ProgressParser()
    for line in _valid_transcript():
        parser.consume(line)
    parser.validate_success()

    mutations: list[list[str]] = []
    valid = _valid_transcript()
    mutations.append(valid[:-1])
    mutations.append([valid[0], valid[0], *valid[1:]])
    mutations.append([valid[2], valid[3], valid[0], valid[1], *valid[4:]])
    mutations.append([valid[0], valid[1].replace(EXPECTED_IDS[0], EXPECTED_IDS[1]),
                      *valid[2:]])
    mutations.append([valid[1], *valid[2:]])
    mutations.append([valid[0] + " username=forbidden", *valid[1:]])
    mutations.append([valid[0], valid[1].replace("duration_ms=1", "duration_ms=9"),
                      *valid[2:]])
    mutations.append([valid[0], valid[1].replace("rc=0", "rc=+1"), *valid[2:]])
    mutations.append([valid[0][:-1]])
    mutations.append(_valid_transcript(19))
    mutations.append([*valid,
                      f"{PREFIX} BEGIN id=unexpected ordinal=21 elapsed_ms=999"])
    for mutation in mutations:
        _expect_parser_failure(mutation)

    nonzero = _valid_transcript()
    nonzero[-1] = nonzero[-1].replace("rc=0", "rc=7")
    _expect_parser_failure(nonzero)

    with tempfile.TemporaryDirectory(prefix="wyl-lifecycle-self-test-") as root:
        child = Path(root) / "child.py"
        child.write_text(_fake_child_source(), encoding="utf-8")
        command = [sys.executable, str(child)]
        normal = run_lifecycle(command, 10.0)
        if len(normal.records) != 2 * len(EXPECTED_IDS):
            raise AssertionError("normal child did not produce exactly 20 pairs")
        pre_exit = run_lifecycle(command, 10.0, mode="prove-pre-exit")
        if not pre_exit.progress_observed_before_exit:
            raise AssertionError("pre-exit proof did not observe the final END")
        terminated = run_lifecycle(command, 10.0, mode="prove-termination")
        if terminated.last_entered != EXPECTED_IDS[0] \
                or terminated.last_completed is not None:
            raise AssertionError("termination proof lost the active check")
        failing_env = dict(os.environ)
        failing_env["WYL_FAKE_LIFECYCLE_FAIL"] = "1"
        try:
            run_lifecycle(command, 10.0, base_env=failing_env)
        except EvidenceError as error:
            if error.classification != "check_failure":
                raise
        else:
            raise AssertionError("nonzero check was accepted")
    return 0


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--companion", type=Path)
    parser.add_argument(
        "--pair-mode", choices=("serial", "parallel"), default="serial"
    )
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--mode",
        choices=("run", "prove-pre-exit", "prove-termination"),
        default="run",
    )
    return parser


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    args = argument_parser().parse_args(argv)
    if args.repeat < 1 or args.timeout <= 0:
        print("repeat and timeout must be positive", file=sys.stderr)
        return 2
    if args.mode != "run" and (args.repeat != 1 or args.companion is not None):
        print("proof modes require one unpaired run", file=sys.stderr)
        return 2
    for binary in (args.binary, args.companion):
        if binary is not None and (not binary.is_file() or not os.access(binary, os.X_OK)):
            print("test executable is missing or not executable", file=sys.stderr)
            return 2

    failures = 0
    lifecycle_command = [str(args.binary)]
    companion_command = None if args.companion is None else [str(args.companion)]
    for iteration in range(1, args.repeat + 1):
        try:
            if args.mode == "run":
                result: dict[str, object] = run_pair(
                    lifecycle_command,
                    companion_command,
                    args.pair_mode,
                    args.timeout,
                )
            else:
                result = asdict(
                    run_lifecycle(
                        lifecycle_command, args.timeout, mode=args.mode
                    )
                )
            result["iteration"] = iteration
            print(json.dumps(result, sort_keys=True), flush=True)
        except EvidenceError as error:
            failures += 1
            print(
                json.dumps(
                    {
                        "classification": error.classification,
                        "detail": error.detail,
                        "iteration": iteration,
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
