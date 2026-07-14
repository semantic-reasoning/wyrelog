#!/usr/bin/env python3
"""Adversarial self-test for the service-session reference guard."""

import json
import hashlib
import importlib.util
import contextlib
import io
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading

PROTECTED = (
    "wyl_session_new_service_detached",
    "wyl_session_get_auth_method_private",
    "wyl_session_is_active_private",
    "wyl_session_copy_persistent_id_private",
    "wyl_session_dup_service_jti_private",
    "wyl_session_dup_service_subject_private",
    "wyl_session_dup_service_tenant_private",
    "wyl_session_dup_service_credential_id_private",
    "wyl_session_get_service_credential_generation_private",
    "wyl_session_get_service_issued_at_seconds_private",
    "wyl_session_get_service_expires_at_seconds_private",
)


def invoke(guard: Path, root: Path, symbol: str, manifest: dict,
           compiler_id: str, compiler: list[str], expect_ok: bool,
           build_root: Path | None = None) -> None:
    arguments = [
        sys.executable, str(guard), str(root), "--fixture-symbol", symbol,
        "--fixture-manifest", json.dumps(manifest), "--compiler-id",
        compiler_id,
    ]
    if build_root is not None:
        arguments.extend(["--build-root", str(build_root)])
    result = subprocess.run(arguments + ["--", *compiler], check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    if (result.returncode == 0) != expect_ok:
        raise RuntimeError(f"unexpected guard result {result.returncode}: "
                           + result.stderr)


def forced_include_arguments(compiler_id: str, path: Path) -> list[str]:
    if compiler_id in {"msvc", "clang-cl"}:
        return ["/FI" + str(path)]
    return ["-include", str(path)]


def include_arguments(compiler_id: str, path: Path) -> list[str]:
    if compiler_id in {"msvc", "clang-cl"}:
        return ["/I" + str(path)]
    return ["-I", str(path)]


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        return 2
    guard = Path(sys.argv[1]).resolve()
    compiler_id = sys.argv[3]
    compiler = sys.argv[4:]
    if not compiler:
        return 2
    spec = importlib.util.spec_from_file_location("boundary_guard", guard)
    if spec is None or spec.loader is None:
        return 2
    guard_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard_module)
    assert guard_module.worker_count("gcc") == 1
    assert 1 <= guard_module.worker_count("clang-cl") <= 4
    heartbeats = []
    waits = iter((False, False, True))
    synthetic = guard_module.HeartbeatReporter(
        10, heartbeats.append, waiter=lambda _interval: next(waits))
    synthetic.update("distill", "stat", file=1, files=2)
    synthetic._run()
    assert len(heartbeats) == 2
    assert heartbeats[0][-2:] == (0, 0)
    assert heartbeats[1][-2:] == (1, 10)
    assert all(isinstance(value, int) or value in guard_module.REPORT_PHASES
               or value in guard_module.REPORT_OPS
               for report in heartbeats for value in report)
    assert "privacy" not in repr(heartbeats) and "secret" not in repr(heartbeats)
    failing_waits = iter((False, True))
    failing = guard_module.HeartbeatReporter(
        10, lambda _report: (_ for _ in ()).throw(RuntimeError("emit")),
        waiter=lambda _interval: next(failing_waits))
    failing._run()
    assert failing.disabled
    class BrokenThread:
        def __init__(self, **_kwargs):
            pass
        def start(self):
            raise RuntimeError("start")
        def join(self, _timeout):
            raise RuntimeError("join")
    broken = guard_module.HeartbeatReporter(thread_factory=BrokenThread)
    broken.start()
    broken.stop()
    assert broken.disabled
    factory_failure = guard_module.make_reporter(
        lambda: (_ for _ in ()).throw(RuntimeError("factory")))
    factory_failure.start()
    factory_failure.update("raw", "check", file=1)
    factory_failure.stop()
    class FailingDouble:
        expansion_calls = property(
            lambda _self: (_ for _ in ()).throw(RuntimeError("property")))
        def start(self):
            raise RuntimeError("start")
        def update(self, *_args, **_kwargs):
            raise RuntimeError("update")
        def note_expansion(self, **_kwargs):
            raise RuntimeError("expansion")
        def stop(self):
            raise RuntimeError("stop")
    guarded_failure = guard_module.ReporterGuard(FailingDouble())
    guarded_failure.start()
    guarded_failure.update("raw", "check")
    guarded_failure.note_expansion()
    assert guarded_failure.expansion_calls == 0
    guarded_failure.stop()
    expansion_watchdog = guard_module.HeartbeatReporter()
    for _ in range(256):
        expansion_watchdog.note_expansion(tasks=7)
    assert expansion_watchdog.snapshot[1:3] == ("distill", "expand")
    assert expansion_watchdog.snapshot[
        guard_module.HeartbeatReporter.FIELDS["expansion_calls"]] == 256
    with tempfile.TemporaryDirectory() as cache_directory:
        cache_root = Path(cache_directory)
        canonical_root = cache_root.resolve()
        common = cache_root / "common.h"
        first = cache_root / "first.h"
        second = cache_root / "second.h"
        main_source = cache_root / "main.c"
        common.write_text("#define SHARED harmless\n", encoding="utf-8")
        first.write_text('#include "common.h"\n', encoding="utf-8")
        second.write_text('#include "common.h"\n', encoding="utf-8")
        main_source.write_text(
            '#include "first.h"\n#include "second.h"\nSHARED\n',
            encoding="utf-8")
        snapshot = guard_module.IncludeSnapshot((canonical_root,))
        main_path = main_source.resolve()
        output = guard_module.distilled_source(
            "main.c", main_source.read_text(encoding="utf-8"), main_path,
            [canonical_root], [canonical_root], (canonical_root,), snapshot)
        original_resolve = Path.resolve
        try:
            Path.resolve = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("warm distillation resolved a filesystem path"))
            warm_output = guard_module.distilled_source(
                "main.c", main_source.read_text(encoding="utf-8"), main_path,
                [canonical_root], [canonical_root], (canonical_root,), snapshot)
        finally:
            Path.resolve = original_resolve
        assert output == warm_output
        reference = guard_module.distilled_source(
            "main.c", main_source.read_text(encoding="utf-8"), main_path,
            [canonical_root], [canonical_root], (canonical_root,),
            guard_module.IncludeSnapshot((canonical_root,)))
        assert hashlib.sha256(output.encode()).digest() == hashlib.sha256(
            reference.encode()).digest()
        assert output.count("SHARED") == reference.count("SHARED")
        assert snapshot.expansion_hits > 0
        assert snapshot.reads == 3
        cap_snapshot = guard_module.IncludeSnapshot((canonical_root,), 0)
        cap_output = guard_module.distilled_source(
            "main.c", main_source.read_text(encoding="utf-8"), main_path,
            [canonical_root], [canonical_root], (canonical_root,), cap_snapshot)
        assert cap_output == reference
        assert not cap_snapshot.expansions
        assert cap_snapshot.expansion_cap_rejections > 0
        common_path = common.resolve()
        intersection = guard_module.IncludeSnapshot((canonical_root,))
        common_raw = common.read_text(encoding="utf-8")
        guard_module.distilled_expansion(
            "common.h", common_raw, common_path, [canonical_root],
            [canonical_root], (canonical_root,), intersection)
        guard_module.distilled_expansion(
            "common.h", common_raw, common_path, [canonical_root],
            [canonical_root], (canonical_root,), intersection,
            (str(common_path),))
        assert intersection.expansion_bypasses == 1
        cycle_a = cache_root / "cycle-a.h"
        cycle_b = cache_root / "cycle-b.h"
        cycle_a.write_text('#include "cycle-b.h"\nA\n', encoding="utf-8")
        cycle_b.write_text('#include "cycle-a.h"\nB\n', encoding="utf-8")
        cycle_snapshot = guard_module.IncludeSnapshot((cache_root.resolve(),))
        cycle_output = guard_module.distilled_source(
            "cycle-a.h", cycle_a.read_text(encoding="utf-8"), cycle_a.resolve(),
            [canonical_root], [canonical_root], (canonical_root,), cycle_snapshot)
        assert "A" in cycle_output and "B" in cycle_output
        assert not cycle_snapshot.expansions
        assert cycle_snapshot.expansion_backedges > 0
        direct = cache_root / "direct.h"
        direct.write_text('#include "direct.h"\nDIRECT\n', encoding="utf-8")
        direct_snapshot = guard_module.IncludeSnapshot((canonical_root,))
        direct_output = guard_module.distilled_source(
            "direct.h", direct.read_text(encoding="utf-8"), direct.resolve(),
            [canonical_root], [canonical_root], (canonical_root,),
            direct_snapshot)
        assert direct_output.count("DIRECT") == 2
        assert not direct_snapshot.expansions
        negative = guard_module.IncludeSnapshot((cache_root.resolve(),))
        assert negative.resolve(cache_root, '"', "appears.h", [cache_root],
                                "negative.c") is None
        (cache_root / "appears.h").write_text("appeared\n", encoding="utf-8")
        try:
            negative.validate()
            raise AssertionError("negative include mutation was accepted")
        except guard_module.BoundaryError:
            pass
        changing = guard_module.IncludeSnapshot((cache_root.resolve(),))
        changing.read_local(common)
        common.write_text("#define SHARED changed\n", encoding="utf-8")
        try:
            changing.validate()
            raise AssertionError("include mutation was accepted")
        except guard_module.BoundaryError:
            pass
        invalid = cache_root / "invalid.h"
        invalid.write_bytes(b"\xff")
        invalid_snapshot = guard_module.IncludeSnapshot((cache_root.resolve(),))
        for _ in range(2):
            try:
                invalid_snapshot.read_local(invalid)
                raise AssertionError("invalid UTF-8 include was accepted")
            except guard_module.BoundaryError:
                pass
        regular_snapshot = guard_module.IncludeSnapshot((cache_root.resolve(),))
        assert regular_snapshot.resolve(
            cache_root, '"', "common.h", [cache_root],
            "regular.c") == common.resolve()
        warm_identity_resolves = regular_snapshot.identity_resolves
        unused_root = cache_root / "unused-root"
        unused_root.mkdir()
        regular_snapshot.canonical_identity(unused_root)
        expected_common = common.resolve()
        original_resolve = Path.resolve
        try:
            Path.resolve = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("warm include cache resolved a filesystem path"))
            assert regular_snapshot.resolve(
                cache_root, '"', "common.h", [cache_root, unused_root],
                "regular.c") == expected_common
        finally:
            Path.resolve = original_resolve
        assert regular_snapshot.resolution_hits == 0
        assert regular_snapshot.candidate_hits == 1
        assert regular_snapshot.identity_resolves == warm_identity_resolves + 1
        try:
            selected_link = cache_root / "selected-link.h"
            selected_link.symlink_to(common)
            broken_link = cache_root / "broken-link.h"
            broken_link.symlink_to(cache_root / "missing-target.h")
            real_directory = cache_root / "real-directory"
            real_directory.mkdir()
            (real_directory / "nested.h").write_text("nested\n", encoding="utf-8")
            intermediate_link = cache_root / "intermediate-link"
            intermediate_link.symlink_to(real_directory, target_is_directory=True)
            for name in ("selected-link.h", "broken-link.h",
                         "intermediate-link/nested.h"):
                linked_snapshot = guard_module.IncludeSnapshot(
                    (cache_root.resolve(),))
                for attempt in range(2):
                    owner = f"linked-{attempt}.c"
                    try:
                        linked_snapshot.resolve(
                            cache_root, '"', name, [cache_root], owner)
                        raise AssertionError("local symlink include was accepted")
                    except guard_module.BoundaryError as error:
                        assert owner in str(error)
                assert linked_snapshot.resolution_errors
            with tempfile.TemporaryDirectory() as external_directory:
                external_root = Path(external_directory)
                external_target = external_root / "target.h"
                external_target.write_text("external\n", encoding="utf-8")
                external_link = external_root / "external-link.h"
                external_link.symlink_to(external_target)
                external_broken = external_root / "external-broken.h"
                external_broken.symlink_to(external_root / "absent.h")
                external_real = external_root / "real"
                external_real.mkdir()
                (external_real / "nested.h").write_text(
                    "nested\n", encoding="utf-8")
                external_intermediate = external_root / "linked-directory"
                external_intermediate.symlink_to(
                    external_real, target_is_directory=True)
                for name in ("external-link.h", "external-broken.h",
                             "linked-directory/nested.h"):
                    external_snapshot = guard_module.IncludeSnapshot(
                        (cache_root.resolve(),))
                    for _ in range(2):
                        try:
                            external_snapshot.resolve(
                                cache_root, '<', name,
                                [external_root, cache_root], "external.c")
                            raise AssertionError(
                                "external symlink include was accepted")
                        except guard_module.BoundaryError:
                            pass
                    assert external_snapshot.resolution_errors
                regular_external = guard_module.IncludeSnapshot(
                    (cache_root.resolve(),))
                assert regular_external.resolve(
                    cache_root, '<', "target.h", [external_root, cache_root],
                    "external.c") == external_target.resolve()
                transient = external_root / "transient.h"
                transient.write_text("external\n", encoding="utf-8")
                transient_snapshot = guard_module.IncludeSnapshot(
                    (cache_root.resolve(),))
                assert transient_snapshot.resolve(
                    cache_root, '<', "transient.h",
                    [external_root, cache_root],
                    "external.c") == transient.resolve()
                transient.unlink()
                try:
                    transient_snapshot.validate()
                    raise AssertionError(
                        "external include disappearance was accepted")
                except guard_module.BoundaryError:
                    pass
                later_local = guard_module.IncludeSnapshot(
                    (cache_root.resolve(),))
                assert later_local.resolve(
                    cache_root, '<', "common.h", [external_root, cache_root],
                    "external.c") == common.resolve()
                (external_root / "common.h").write_text(
                    "appeared\n", encoding="utf-8")
                try:
                    later_local.validate()
                    raise AssertionError(
                        "earlier external include appearance was accepted")
                except guard_module.BoundaryError:
                    pass
        except OSError:
            # Symlink creation may require privileges on native Windows.
            pass
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        allowed = root / "allowed.c"
        (root / "noise.h").write_text(
            "# define @PREFIX@COMPILER_VERSION @VERSION@\n"
            "#if 0\n#define CONDITIONAL_MACRO invalid\n"
            "#else\n#define CONDITIONAL_MACRO valid\n#endif\n"
            "#undef CONDITIONAL_MACRO\n"
            "#define CONDITIONAL_MACRO final\n",
            encoding="utf-8")
        integration_symbol = PROTECTED[0]
        integration_manifest = {integration_symbol: {"allowed.c": 1}}
        allowed.write_text(
            f"void {integration_symbol}(void) {{}}\n", encoding="utf-8")
        original_inspect_probe = guard_module.inspect_probe
        original_validate = guard_module.IncludeSnapshot.validate
        def integration_run(factory):
            trace = []
            validation_trace = []
            def counters(snapshot):
                return (
                    len(snapshot.resolutions), len(snapshot.resolution_errors),
                    len(snapshot.text), len(snapshot.fingerprints),
                    len(snapshot.negative_paths), len(snapshot.candidates),
                    len(snapshot.logical_lines), len(snapshot.expansions),
                    snapshot.expansion_bytes, snapshot.expansion_hits,
                    snapshot.expansion_bypasses, snapshot.expansion_backedges,
                    snapshot.expansion_cap_rejections, snapshot.reads,
                    snapshot.resolution_hits, snapshot.identity_resolves,
                    snapshot.candidate_checks, snapshot.candidate_hits)
            def validating(snapshot):
                validation_trace.append(("before", counters(snapshot)))
                result = original_validate(snapshot)
                validation_trace.append(("after", counters(snapshot)))
                return result
            def collect(rel, probe, _protected, _compiler, _kind, semantics):
                flattened = guard_module.flatten_expansion(probe)
                trace.append((
                    rel, hashlib.sha256(flattened.encode()).hexdigest(),
                    hashlib.sha256(json.dumps(semantics).encode()).hexdigest()))
            guard_module.inspect_probe = collect
            guard_module.IncludeSnapshot.validate = validating
            stdout = io.StringIO()
            stderr = io.StringIO()
            try:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    guard_module.guarded_inspect(
                        root.resolve(), integration_manifest,
                        (integration_symbol,), compiler, compiler_id,
                        reporter_factory=factory)
                verdict = (None, None)
            except Exception as error:
                verdict = (type(error), str(error))
            finally:
                guard_module.inspect_probe = original_inspect_probe
                guard_module.IncludeSnapshot.validate = original_validate
            return (verdict, stdout.getvalue(), stderr.getvalue(), tuple(trace),
                    tuple(validation_trace))
        heartbeat_reports = []
        heartbeat_instances = []
        class BarrierReporter(guard_module.HeartbeatReporter):
            def __init__(self):
                self.progress = threading.Event()
                self.wait_calls = 0
                self.published = []
                super().__init__(10, heartbeat_reports.append,
                                 waiter=self.scripted_wait)
            def scripted_wait(self, _interval):
                if self.wait_calls == 0:
                    self.wait_calls += 1
                    self.progress.wait()
                    return False
                return True
            def update(self, phase, op, **values):
                super().update(phase, op, **values)
                self.published.append(self.snapshot)
                expansion_index = self.FIELDS["expansion_calls"]
                if self.snapshot[expansion_index] > 0:
                    self.progress.set()
        def heartbeat_factory():
            reporter = BarrierReporter()
            heartbeat_instances.append(reporter)
            return reporter
        accepted_null = integration_run(guard_module.NullReporter)
        accepted_heartbeat = integration_run(heartbeat_factory)
        accepted_failing = integration_run(lambda: FailingDouble())
        assert accepted_null[0] == accepted_heartbeat[0] == accepted_failing[0] == (None, None)
        assert accepted_null[1] == accepted_heartbeat[1] == accepted_failing[1]
        assert accepted_null[3] == accepted_heartbeat[3] == accepted_failing[3]
        assert accepted_null[4] == accepted_heartbeat[4] == accepted_failing[4]
        assert len(accepted_null[4]) == 4
        assert heartbeat_reports
        accepted_reporter = heartbeat_instances[0]
        emitted_snapshot = heartbeat_reports[0][:-2]
        assert emitted_snapshot in accepted_reporter.published
        assert emitted_snapshot[0] > 0
        assert emitted_snapshot[
            accepted_reporter.FIELDS["expansion_calls"]] > 0
        final_counters = accepted_null[4][-1][1]
        assert accepted_reporter.snapshot[
            accepted_reporter.FIELDS["resolutions"]] == final_counters[0]
        assert accepted_reporter.snapshot[
            accepted_reporter.FIELDS["candidate_checks"]] == final_counters[16]
        assert accepted_reporter.snapshot[
            accepted_reporter.FIELDS["tasks"]] == len(accepted_null[3])
        assert accepted_reporter.snapshot[
            accepted_reporter.FIELDS["validations"]] == 2
        forbidden = (str(root), root.name, Path(compiler[0]).name,
                     integration_symbol, "secret")
        assert all(value not in accepted_heartbeat[2] for value in forbidden)
        assert all(value not in repr(heartbeat_reports) for value in forbidden)
        bad = root / "000-bad.c"
        integration_prefix, integration_suffix = integration_symbol.rsplit(
            "_", 1)
        bad.write_text(
            f"{integration_prefix}_ ## {integration_suffix}\n",
            encoding="utf-8")
        def reject_heartbeat_factory():
            reporter = guard_module.HeartbeatReporter(30)
            heartbeat_instances.append(reporter)
            return reporter
        rejected_null = integration_run(guard_module.NullReporter)
        rejected_heartbeat = integration_run(reject_heartbeat_factory)
        rejected_factory = integration_run(
            lambda: (_ for _ in ()).throw(RuntimeError("factory")))
        rejected_failing = integration_run(lambda: FailingDouble())
        assert (rejected_null[0] == rejected_heartbeat[0]
                == rejected_factory[0] == rejected_failing[0])
        assert rejected_null[0][0] is guard_module.BoundaryError
        assert rejected_null[0][1] == rejected_heartbeat[0][1] == rejected_factory[0][1]
        assert (rejected_null[1] == rejected_heartbeat[1]
                == rejected_factory[1] == rejected_failing[1])
        assert (rejected_null[3] == rejected_heartbeat[3]
                == rejected_factory[3] == rejected_failing[3])
        assert (rejected_null[4] == rejected_heartbeat[4]
                == rejected_factory[4] == rejected_failing[4] == ())
        rejected_reporter = heartbeat_instances[1]
        assert rejected_reporter.snapshot[
            rejected_reporter.FIELDS["validations"]] == 0
        assert rejected_reporter.snapshot[1] == "raw"
        bad.unlink()
        for symbol in PROTECTED:
            prefix, suffix = symbol.rsplit("_", 1)
            escaped = symbol.replace("_", "\\x5f", 1)
            manifest = {symbol: {"allowed.c": 1}}
            attacks = (
                f"void bad(void) {{ {symbol}(); }}\n",
                f"void *bad = &{symbol};\n",
                f"void {symbol}(void);\n",
                f"#define BAD {symbol}\n",
                f"{prefix}_\\\n{suffix}();\n",
                f"{prefix}_ ## {suffix}\n",
                f"dlsym(0, \"{symbol}\");\n",
                f"const char *s = \"{escaped}\";\n",
                "#define CAT_I(a, b) a ## b\n"
                "#define CAT(a, b) CAT_I(a, b)\n"
                f"#define P {prefix}\n#define S _{suffix}\n"
                "void bad(void) { CAT(P, S)(); }\n",
                "# define @PREFIX@COMPILER_VERSION @VERSION@\n"
                "#define CAT_I(a, b...) a ## b\n"
                "#define CAT(a, b...) CAT_I(a, b)\n"
                f"#define P {prefix}\n#define S _{suffix}\n"
                "void bad(void) { CAT(P, S)(); }\n",
            )
            allowed.write_text(f"void {symbol}(void) {{}}\n",
                               encoding="utf-8")
            invoke(guard, root, symbol, manifest, compiler_id, compiler, True)
            for attack in attacks:
                bad = root / "bad.c"
                bad.write_text(attack, encoding="utf-8")
                invoke(guard, root, symbol, manifest, compiler_id, compiler,
                       False)
                bad.unlink()
            allowed.write_text(
                f"void {symbol}(void) {{}}\nvoid *p = &{symbol};\n",
                encoding="utf-8")
            invoke(guard, root, symbol, manifest, compiler_id, compiler, False)
            allowed.write_text("void harmless(void) {}\n", encoding="utf-8")
            invoke(guard, root, symbol, manifest, compiler_id, compiler, False)
            committed_like = (root / "tests" / "fixtures" / "CMakeFiles"
                              / "generated_build")
            committed_like.mkdir(parents=True, exist_ok=True)
            allowed.write_text(f"void {symbol}(void) {{}}\n",
                               encoding="utf-8")
            tracked_fixture = committed_like / "tracked.c"
            tracked_fixture.write_text(f"void *p = &{symbol};\n",
                                       encoding="utf-8")
            invoke(guard, root, symbol, manifest, compiler_id, compiler, False)
            tracked_fixture.unlink()
            subproject = root / "subprojects" / "nested"
            subproject.mkdir(parents=True, exist_ok=True)
            nested_ref = subproject / "bad.c"
            nested_ref.write_text(f"void *p = &{symbol};\n", encoding="utf-8")
            invoke(guard, root, symbol, manifest, compiler_id, compiler, False)
            nested_ref.unlink()
            backup_ref = root / "tracked.c~"
            backup_ref.write_text(f"void *p = &{symbol};\n", encoding="utf-8")
            invoke(guard, root, symbol, manifest, compiler_id, compiler, False)
            backup_ref.unlink()
        failing = root / "failing-compiler"
        failing.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
        failing.chmod(0o755)
        allowed.write_text(f"void {PROTECTED[0]}(void) {{}}\n",
                           encoding="utf-8")
        invoke(guard, root, PROTECTED[0],
               {PROTECTED[0]: {"allowed.c": 1}}, "gcc", [str(failing)],
               False)
        clang_cl_sim = root / "clang-cl-sim"
        clang_cl_sim.write_text(
            "#!/bin/sh\n"
            "translated=\n"
            "inputs=\n"
            "for arg in \"$@\"; do\n"
            "  case \"$arg\" in\n"
            "    /nologo|/EP|/TC|-) ;;\n"
            "    /D*) translated=\"$translated -D${arg#/D}\" ;;\n"
            "    /U*) translated=\"$translated -U${arg#/U}\" ;;\n"
            "    /FI*) translated=\"$translated -include ${arg#/FI}\" ;;\n"
            "    /I*) translated=\"$translated -I${arg#/I}\" ;;\n"
            "    /external:I*) translated=\"$translated -I${arg#/external:I}\" ;;\n"
            "    *.c) inputs=\"$inputs $arg\" ;;\n"
            "    *) exit 8 ;;\n"
            "  esac\n"
            "done\n"
            "if [ -n \"$inputs\" ]; then\n"
            "  for input in $inputs; do\n"
            f"    {shlex.join(compiler)} $translated -E -P -x c \"$input\" || exit $?\n"
            "  done\n"
            "  exit 0\n"
            "fi\n"
            f"exec {shlex.join(compiler)} $translated -E -P -x c -\n",
            encoding="utf-8")
        clang_cl_sim.chmod(0o755)
        symbol = PROTECTED[0]
        prefix, suffix = symbol.rsplit("_", 1)
        allowed.write_text(f"void {symbol}(void) {{}}\n", encoding="utf-8")
        bad = root / "bad.c"
        bad.write_text(
            "# define @PREFIX@COMPILER_VERSION @VERSION@\n"
            "#define CAT_I(a, b...) a ## b\n"
            "#define CAT(a, b...) CAT_I(a, b)\n"
            f"#define P {prefix}\n#define S _{suffix}\n"
            "void bad(void) { CAT(P, S)(); }\n", encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               "clang-cl", [str(clang_cl_sim)], False)

        # A conflicting definition in an unrelated header must not make the
        # definition selected by the translation unit disappear from analysis.
        prefix, suffix = symbol.rsplit("_", 1)
        (root / "a.h").write_text(f"#define P {prefix}\n", encoding="utf-8")
        (root / "b.h").write_text("#define P harmless\n", encoding="utf-8")
        (root / "cat.h").write_text(
            "#define CAT_I(a, b) a ## b\n#define CAT(a, b) CAT_I(a, b)\n",
            encoding="utf-8")
        include_attacks = (
            '#include "a.h"\n#include "cat.h"\nvoid bad(void) { CAT(P, _'
            + suffix + ")(); }\n",
            '#include "b.h"\n#include "a.h"\n#include "cat.h"\n'
            'void bad(void) { CAT(P, _' + suffix + ")(); }\n",
            '#include "a.h"\n#undef P\n#if 1\n#define P ' + prefix
            + '\n#endif\n#include "cat.h"\nvoid bad(void) { CAT(P, _'
            + suffix + ")(); }\n",
        )
        for attack in include_attacks:
            bad.write_text(attack, encoding="utf-8")
            invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
                   compiler_id, compiler, False)
        # The reverse final definition is harmless and must not false-fail.
        bad.write_text(
            '#include "a.h"\n#include "b.h"\n#include "cat.h"\n'
            'void good(void) { CAT(P, _' + suffix + ")(); }\n",
            encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler, True)

        # Tracked angle includes have the same ordered macro semantics.  A
        # generated-like path is found by suffix, while ambiguity fails closed.
        generated = root / "generated" / "include"
        generated.mkdir(parents=True, exist_ok=True)
        generated_a = generated / "angle-a.h"
        generated_cat = generated / "angle-cat.h"
        generated_a.write_text(f"#define ANGLE_P {prefix}\n", encoding="utf-8")
        generated_cat.write_text(
            "#define ANGLE_CAT_I(a, b) a ## b\n"
            "#define ANGLE_CAT(a, b) ANGLE_CAT_I(a, b)\n",
            encoding="utf-8")
        bad.write_text(
            "#include <angle-a.h>\n#include <angle-cat.h>\n"
            "void bad(void) { ANGLE_CAT(ANGLE_P, _" + suffix + ")(); }\n",
            encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler + ["-I", "generated/include"], False)

        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "add", "allowed.c", "bad.c",
                        "cat.h"], check=True)

        # Include roots select the first physical header exactly as the TU's
        # compiler does; identical parents may reach different child content.
        for directory, definition in (("d1", prefix), ("d2", "harmless")):
            include_dir = root / directory
            include_dir.mkdir(exist_ok=True)
            (include_dir / "parent.h").write_text(
                '#include "child.h"\n', encoding="utf-8")
            (include_dir / "child.h").write_text(
                f"#define ORDERED_P {definition}\n", encoding="utf-8")
        bad.write_text(
            "#include <parent.h>\n#include \"cat.h\"\n"
            "void bad(void) { CAT(ORDERED_P, _" + suffix + ")(); }\n",
            encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler + ["-I", "d1", "-I", "d2"], False)
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler + ["-I", "d2", "-I", "d1"], True)

        external = root / "external"
        external.mkdir(exist_ok=True)
        (external / "external.h").write_text(
            f"#define EXTERNAL_P {prefix}\n", encoding="utf-8")
        bad.write_text(
            "#include <external.h>\n#include \"cat.h\"\n"
            "void bad(void) { CAT(EXTERNAL_P, _" + suffix + ")(); }\n",
            encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler + ["-I", "external"], False)
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               "clang-cl", [str(clang_cl_sim), "/Iexternal"], False)

        bad.write_text(
            "#if SELECT_PROTECTED\n#define SELECT_P " + prefix
            + "\n#else\n#define SELECT_P harmless\n#endif\n"
            '#include "cat.h"\nvoid bad(void) { CAT(SELECT_P, _'
            + suffix + ")(); }\n", encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler + ["-DSELECT_PROTECTED=1"], False)
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler + ["-DSELECT_PROTECTED=0"], True)
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               "clang-cl", [str(clang_cl_sim), "/DSELECT_PROTECTED=1"], False)
        response = root / "select.rsp"
        response.write_text("-DSELECT_PROTECTED=1\n", encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler + ["@" + str(response)], False)
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler + ["@" + str(root / "missing.rsp")],
               False)

        outer = root / "configs" / "outer.rsp"
        containing_inner = root / "configs" / "sub" / "inner.rsp"
        command_inner = root / "sub" / "inner.rsp"
        outer.parent.mkdir(exist_ok=True)
        containing_inner.parent.mkdir(exist_ok=True)
        command_inner.parent.mkdir(exist_ok=True)
        outer.write_text("@sub/inner.rsp\n", encoding="utf-8")
        containing_inner.write_text(
            "-DSELECT_PROTECTED=0\n", encoding="utf-8")
        command_inner.write_text(
            "-DSELECT_PROTECTED=1\n", encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler + ["@configs/outer.rsp"], False)
        outer.write_text("@sub/inner.rsp\n", encoding="utf-8")
        containing_inner.write_text(
            "/DSELECT_PROTECTED=0\n", encoding="utf-8")
        command_inner.write_text(
            "/DSELECT_PROTECTED=1\n", encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               "clang-cl", [str(clang_cl_sim), "@configs/outer.rsp"], False)

        forced = external / "forced.h"
        forced.write_text(f"#define FORCED_P {prefix}\n", encoding="utf-8")
        bad.write_text(
            '#include "cat.h"\nvoid bad(void) { CAT(FORCED_P, _'
            + suffix + ")(); }\n", encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id,
               compiler + forced_include_arguments(compiler_id, forced), False)
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               "clang-cl", [str(clang_cl_sim), "/DSELECT_PROTECTED=1",
                            "/FI" + str(forced)], False)

        shadow = external / "shadow.h"
        shadow.write_text(
            "#define WYL_BOUNDARY_LITERAL_0_0\n", encoding="utf-8")
        bad.write_text(
            "#define MULTIPLIED " + symbol + "\n"
            "void a(void) { MULTIPLIED(); }\n"
            "void b(void) { MULTIPLIED(); }\n", encoding="utf-8")
        invoke(guard, root, symbol,
               {symbol: {"allowed.c": 1, "bad.c": 1}}, compiler_id,
               compiler + forced_include_arguments(compiler_id, shadow), False)

        quote_root = root / "quote-root"
        angle_root = root / "angle-root"
        quote_root.mkdir(exist_ok=True)
        angle_root.mkdir(exist_ok=True)
        (quote_root / "ordered.h").write_text(
            f"#define SEARCH_P {prefix}\n", encoding="utf-8")
        (angle_root / "ordered.h").write_text(
            "#define SEARCH_P harmless\n", encoding="utf-8")
        if compiler_id not in {"msvc", "clang-cl"}:
            bad.write_text(
                '#include "ordered.h"\n#include "cat.h"\n'
                "void bad(void) { CAT(SEARCH_P, _" + suffix + ")(); }\n",
                encoding="utf-8")
            invoke(guard, root, symbol, {symbol: {"allowed.c": 1}}, compiler_id,
                   compiler + ["-iquote", "quote-root", "-I", "angle-root"],
                   False)
            bad.write_text(
                '#include <ordered.h>\n#include "cat.h"\n'
                "void good(void) { CAT(SEARCH_P, _" + suffix + ")(); }\n",
                encoding="utf-8")
            invoke(guard, root, symbol, {symbol: {"allowed.c": 1}}, compiler_id,
                   compiler + ["-iquote", "quote-root", "-I", "angle-root"],
                   True)

        # Even an object-only include root is semantically observable through
        # __has_include and must never be pruned from the compiler context.
        object_root = root / "object-only"
        object_root.mkdir(exist_ok=True)
        (object_root / "unit.obj").write_bytes(b"\0object")
        bad.write_text(
            "#if __has_include(<unit.obj>)\n#define OBJECT_P " + prefix
            + "\n#else\n#define OBJECT_P harmless\n#endif\n"
            '#include "cat.h"\nvoid bad(void) { CAT(OBJECT_P, _'
            + suffix + ")(); }\n", encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}}, compiler_id,
               compiler + include_arguments(compiler_id, object_root), False)

        # Windows command strings and response files retain quoted paths,
        # backslashes, /D, /FI, and /I semantics.
        spaced = root / "space dir"
        spaced.mkdir(exist_ok=True)
        spaced_forced = spaced / "forced header.h"
        spaced_forced.write_text(
            f"#define WINDOWS_P {prefix}\n", encoding="utf-8")
        bad.write_text(
            '#include "cat.h"\nvoid bad(void) { CAT(WINDOWS_P, _'
            + suffix + ")(); }\n", encoding="utf-8")
        with tempfile.TemporaryDirectory() as windows_build_directory:
            windows_build = Path(windows_build_directory)
            command = (
                f'"{clang_cl_sim}" /DSELECT_PROTECTED=1 '
                f'/FI"{spaced_forced}" /I"{spaced}" /c "{bad}" '
                '/Fo"obj path\\bad.obj"')
            (windows_build / "compile_commands.json").write_text(
                json.dumps([{"directory": str(root), "command": command,
                             "file": str(bad)}]), encoding="utf-8")
            invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
                   "clang-cl", [str(clang_cl_sim)], False, windows_build)
        windows_response = root / "windows args.rsp"
        windows_response.write_text(
            f'/DSELECT_PROTECTED=1 /FI"{spaced_forced}" '
            f'/I"{spaced}"\n', encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               "clang-cl", [str(clang_cl_sim), "@" + str(windows_response)],
               False)

        # A tracked, uncompiled non-C source remains in the raw manifest scope
        # but cannot affect the configured binary's preprocessor graph.
        uncompiled = root / "uncompiled.cc"
        uncompiled.write_text("#define BENIGN harmless\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "uncompiled.cc"],
                       check=True)
        bad.write_text("void benign(void) {}\n", encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler, True)

        # Authoritative references remain tracked-only, but local include
        # semantics also cover untracked generated headers in source/build.
        bad.write_text(
            '#include "generated.h"\n#include "cat.h"\n'
            "void bad(void) { CAT(P, _" + suffix + ")(); }\n",
            encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "allowed.c", "bad.c",
                        "cat.h"], check=True)
        generated_header = root / "generated.h"
        generated_header.write_text(f"#define P {prefix}\n", encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler, False)
        generated_header.unlink()
        with tempfile.TemporaryDirectory() as build_directory:
            build_root = Path(build_directory)
            (build_root / "generated.h").write_text(
                f"#define P {prefix}\n", encoding="utf-8")
            invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
                   compiler_id, compiler, False, build_root)

        # Compiler-specific include-like directives are not modeled and must
        # fail closed, including after logical line splicing.
        for directive in (
            '#include_next "a.h"\n',
            '#import "a.h"\n',
            '#embed "payload.bin"\n',
            '#include_\\\nnext "a.h"\n',
        ):
            bad.write_text(directive, encoding="utf-8")
            invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
                   compiler_id, compiler, False)

        # The sentinel namespace is reserved even in inactive conditionals;
        # source macros cannot predefine a sentinel away before multiplication.
        for shadow in (
            "#define WYL_BOUNDARY_LITERAL_0_0\n",
            "#if 0\n#define WYL_BOUNDARY_LITERAL_0_0 harmless\n#endif\n",
            "#define SHADOW WYL_BOUNDARY_LITERAL_0_0\n",
        ):
            bad.write_text(shadow, encoding="utf-8")
            invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
                   compiler_id, compiler, False)

        # Each literal gets its own sentinel, so one macro definition may not
        # multiply a protected reference while zero/one active uses are valid.
        bad.write_text(
            "#define MULTIPLY " + symbol + "\n"
            "void a(void) { MULTIPLY(); }\n"
            "void b(void) { MULTIPLY(); }\n", encoding="utf-8")
        invoke(guard, root, symbol,
               {symbol: {"allowed.c": 1, "bad.c": 1}},
               compiler_id, compiler, False)
        bad.write_text(
            "#define ONCE " + symbol + "\nvoid a(void) { ONCE(); }\n",
            encoding="utf-8")
        invoke(guard, root, symbol,
               {symbol: {"allowed.c": 1, "bad.c": 1}},
               compiler_id, compiler, True)
        bad.write_text(
            "#if 0\n#define INACTIVE " + symbol
            + "\nvoid a(void) { INACTIVE(); }\n#endif\n", encoding="utf-8")
        invoke(guard, root, symbol,
               {symbol: {"allowed.c": 1, "bad.c": 1}},
               compiler_id, compiler, True)
        duplicate = root / "vendor" / "angle-a.h"
        duplicate.parent.mkdir(parents=True, exist_ok=True)
        duplicate.write_text("#define ANGLE_P harmless\n", encoding="utf-8")
        bad.write_text(
            "#include <angle-a.h>\n#include <angle-cat.h>\n"
            "void bad(void) { ANGLE_CAT(ANGLE_P, _" + suffix + ")(); }\n",
            encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler, False)
        duplicate.unlink()

        # A literal hidden in an inactive branch cannot cancel a synthesized
        # active token.  Conversely an active literal is masked and harmless.
        bad.write_text(
            "#if 0\nvoid " + symbol + "(void);\n#endif\n"
            '#include "a.h"\n#include "cat.h"\n'
            "void bad(void) { CAT(P, _" + suffix + ")(); }\n",
            encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler, False)
        bad.write_text("void " + symbol + "(void) {}\n", encoding="utf-8")
        invoke(guard, root, symbol,
               {symbol: {"allowed.c": 1, "bad.c": 1}},
               compiler_id, compiler, True)

        # Macro-expanded include operands cannot be resolved soundly by the
        # controlled tracked-file include model and therefore fail closed.
        bad.write_text(
            '#define H "a.h"\n#include H\n#include "cat.h"\n'
            "void bad(void) { CAT(P, _" + suffix + ")(); }\n",
            encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler, False)
        bad.write_text(
            '#define H "a.h"\n#inc\\\nlude H\n#include "cat.h"\n'
            "void bad(void) { CAT(P, _" + suffix + ")(); }\n",
            encoding="utf-8")
        invoke(guard, root, symbol, {symbol: {"allowed.c": 1}},
               compiler_id, compiler, False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
