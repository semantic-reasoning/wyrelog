#!/usr/bin/env python3
"""Exercise the production Wirelog dependency selector in isolated projects."""

from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile


if len(sys.argv) != 3:
    raise SystemExit("usage: test-wirelog-dependency-boundary.py ROOT MESON")

root = Path(sys.argv[1]).resolve()
meson_arg = Path(sys.argv[2])
if not meson_arg.is_absolute():
    raise SystemExit("Meson executable path must be absolute")
meson = str(meson_arg)
if not meson_arg.is_file():
    raise SystemExit(f"Meson executable does not exist: {meson}")

required_api = "wirelog_program_relation_has_input"
selector_call = "subdir('meson/wirelog-dependency')"
root_meson = (root / "meson.build").read_text(encoding="utf-8")
selector_path = root / "meson" / "wirelog-dependency" / "meson.build"


def fail(message):
    raise SystemExit(message)


if root_meson.count(selector_call) != 1:
    fail("root meson.build must delegate Wirelog selection exactly once")

selector_offset = root_meson.index(selector_call)
for required_input in (
    "cc = meson.get_compiler('c')",
    "wirelog_version = '>= 0.54.0'",
    "force_fallback_for = get_option('force_fallback_for')",
    "wrap_mode = get_option('wrap_mode')",
):
    if required_input not in root_meson:
        fail(f"root lost Wirelog selector input: {required_input}")
    if root_meson.index(required_input) > selector_offset:
        fail(f"Wirelog selector runs before required input: {required_input}")

for downstream in (
    "libchronoid_force_fallback =",
    "subdir('wyrelog')",
    "subdir('tests')",
):
    if root_meson.index(downstream) < selector_offset:
        fail(f"Wirelog selector runs after dependency consumer: {downstream}")

for meson_file in root.rglob("meson.build"):
    relative = meson_file.relative_to(root)
    if relative.parts[0] == "subprojects" or meson_file == selector_path:
        continue
    source = meson_file.read_text(encoding="utf-8")
    for competing in ("dependency('wirelog'", "subproject('wirelog'"):
        if competing in source:
            fail(
                f"competing Wirelog selector remains in {relative}: "
                f"{competing}"
            )

selector_source = selector_path.read_text(encoding="utf-8")
if selector_source.count("dependency('wirelog'") != 1:
    fail("production selector must own one system Wirelog discovery")
if selector_source.count("subproject('wirelog'") != 1:
    fail("production selector must own one Wirelog fallback discovery")


def clipped(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    limit = 12000
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[output truncated]..."


def run_command(scenario, argv, *, env=None, timeout=180):
    try:
        return subprocess.run(
            [str(item) for item in argv],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        fail(
            f"{scenario}: command timed out after {timeout}s: {argv!r}\n"
            f"stdout:\n{clipped(error.stdout)}\n"
            f"stderr:\n{clipped(error.stderr)}"
        )


def require_success(scenario, argv, *, env=None, timeout=180):
    result = run_command(scenario, argv, env=env, timeout=timeout)
    if result.returncode != 0:
        fail(
            f"{scenario}: command failed with {result.returncode}: {argv!r}\n"
            f"stdout:\n{clipped(result.stdout)}\n"
            f"stderr:\n{clipped(result.stderr)}"
        )
    return result


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def nested_meson_environment():
    env = os.environ.copy()
    # The boundary driver itself remains under the repository's strict
    # EncodingWarning policy.  Do not impose that policy on an external Meson
    # installation: Meson 1.12 still calls locale.getpreferredencoding() and
    # Python 3.14 warns inside Meson's own code, outside this test's authority.
    env.pop("PYTHONWARNDEFAULTENCODING", None)
    if env.get("PYTHONWARNINGS") == "error::EncodingWarning":
        env.pop("PYTHONWARNINGS")
    return env


def provider_header(kind, provider):
    marker = f"WIRELOG_PROVIDER_{provider.upper()}"
    declaration = ""
    if kind in ("compatible", "missing_symbol"):
        declaration = (
            "bool wirelog_program_relation_has_input(\n"
            "    const wirelog_program_t *program, const char *relation);\n"
        )
    elif kind == "wrong_signature":
        declaration = (
            "int wirelog_program_relation_has_input(\n"
            "    wirelog_program_t *program, char *relation);\n"
        )
    return f"""#pragma once
#include <stdbool.h>
#define {marker} 1
typedef struct wirelog_program wirelog_program_t;
{declaration}"""


def provider_source(kind, provider):
    if kind == "compatible":
        return f"""#include <string.h>
#include <wirelog/wirelog-parser.h>
bool
wirelog_program_relation_has_input(const wirelog_program_t *program,
                                   const char *relation)
{{
  (void) program;
  return relation != 0 && strcmp(relation, "{provider}") == 0;
}}
"""
    if kind == "wrong_signature":
        return """#include <wirelog/wirelog-parser.h>
int
wirelog_program_relation_has_input(wirelog_program_t *program,
                                   char *relation)
{
  (void) program;
  (void) relation;
  return 1;
}
"""
    return "int wirelog_provider_anchor(void) { return 0; }\n"


def install_system_provider(scenario_dir, kind):
    source_dir = scenario_dir / "system-source"
    build_dir = scenario_dir / "system-build"
    prefix = scenario_dir / "system-prefix"
    write(
        source_dir / "meson.build",
        """project('wirelog-system-fixture', 'c',
  version : '0.54.0',
  meson_version : '>= 1.1.0',
  default_options : ['c_std=c17'],
)
wirelog_lib = static_library('wirelog', 'wirelog.c', install : true)
install_headers('wirelog/wirelog-parser.h', subdir : 'wirelog')
pkg = import('pkgconfig')
pkg.generate(wirelog_lib,
  name : 'wirelog',
  filebase : 'wirelog',
  description : 'isolated Wirelog system fixture',
  version : meson.project_version(),
  subdirs : '.',
)
""",
    )
    write(
        source_dir / "wirelog" / "wirelog-parser.h",
        provider_header(kind, "system"),
    )
    write(source_dir / "wirelog.c", provider_source(kind, "system"))
    env = nested_meson_environment()
    require_success(
        f"{scenario_dir.name}: system provider setup",
        [
            meson,
            "setup",
            build_dir,
            source_dir,
            "--prefix",
            prefix,
            "--libdir",
            "lib",
        ],
        env=env,
    )
    require_success(
        f"{scenario_dir.name}: system provider compile",
        [meson, "compile", "-C", build_dir],
        env=env,
    )
    require_success(
        f"{scenario_dir.name}: system provider install",
        [meson, "install", "-C", build_dir],
        env=env,
    )
    pkgconfig_dir = prefix / "lib" / "pkgconfig"
    if not (pkgconfig_dir / "wirelog.pc").is_file():
        fail(f"{scenario_dir.name}: provider did not install wirelog.pc")
    return pkgconfig_dir


def write_fallback(fixture, kind):
    fallback = fixture / "subprojects" / "wirelog"
    write(
        fallback / "meson_options.txt",
        """option('tests', type : 'boolean', value : false)
option('documentation', type : 'boolean', value : false)
""",
    )
    if kind == "forbidden":
        write(
            fallback / "meson.build",
            """project('wirelog', 'c', version : '0.54.99')
error('compatible system selection configured the fallback fixture')
""",
        )
        return
    write(
        fallback / "meson.build",
        """project('wirelog', 'c',
  version : '0.54.99',
  meson_version : '>= 1.1.0',
  default_options : ['c_std=c17'],
)
wirelog_lib = static_library('wirelog', 'wirelog.c')
wirelog_inc = include_directories('.')
wirelog_src_inc = include_directories('wirelog')
""",
    )
    write(
        fallback / "wirelog" / "wirelog-parser.h",
        provider_header(kind, "fallback"),
    )
    write(fallback / "wirelog.c", provider_source(kind, "fallback"))


def consumer_source(expected):
    expected_macro = f"WIRELOG_PROVIDER_{expected.upper()}"
    other = "FALLBACK" if expected == "system" else "SYSTEM"
    return f"""#include <wirelog/wirelog-parser.h>
#if !defined({expected_macro}) || defined(WIRELOG_PROVIDER_{other})
#error selected Wirelog provider does not match the scenario
#endif
int
main(void)
{{
  return wirelog_program_relation_has_input(0, "{expected}") ? 0 : 1;
}}
"""


def selection_environment(pkgconfig_dir):
    env = nested_meson_environment()
    env["PKG_CONFIG_LIBDIR"] = str(pkgconfig_dir)
    env["PKG_CONFIG_PATH"] = ""
    configured_pkgconfig = env.get("PKG_CONFIG")
    if configured_pkgconfig and not Path(configured_pkgconfig).is_absolute():
        resolved_pkgconfig = shutil.which(configured_pkgconfig)
        if resolved_pkgconfig is None:
            fail(f"configured PKG_CONFIG was not found: {configured_pkgconfig}")
        env["PKG_CONFIG"] = resolved_pkgconfig
    return env


def prepare_selection_fixture(scenario_dir, system_kind, fallback_kind,
                              expected):
    pkgconfig_dir = install_system_provider(scenario_dir, system_kind)
    fixture = scenario_dir / "selection-source"
    build = scenario_dir / "selection-build"
    write(
        fixture / "meson.build",
        """project('wirelog-selection-fixture', 'c',
  meson_version : '>= 1.1.0',
  default_options : ['c_std=c17'],
)
cc = meson.get_compiler('c')
wirelog_version = '>= 0.54.0'
force_fallback_for = get_option('force_fallback_for')
wrap_mode = get_option('wrap_mode')
subdir('meson/wirelog-dependency')
consumer = executable('wirelog-consumer', 'consumer.c',
  dependencies : wirelog_dep)
test('wirelog-provider', consumer)
""",
    )
    write(fixture / "consumer.c", consumer_source(expected))
    selector_destination = fixture / "meson" / "wirelog-dependency"
    selector_destination.mkdir(parents=True)
    shutil.copy2(selector_path, selector_destination / "meson.build")
    write_fallback(fixture, fallback_kind)
    native_file = scenario_dir / "no-host-cmake.ini"
    write(
        native_file,
        """[binaries]
cmake = 'wirelog-cmake-must-not-run'
""",
    )
    return fixture, build, native_file, selection_environment(pkgconfig_dir)


SYSTEM_SIGNATURE = (
    "System Wirelog candidate lacks required public API signature "
    f"{required_api} from <wirelog/wirelog-parser.h>."
)
SYSTEM_LINK = (
    "System Wirelog candidate has the required declaration but cannot link "
    f"public API {required_api}."
)
FALLBACK_SIGNATURE = (
    "Pinned Wirelog fallback lacks required public API signature "
    f"{required_api} from <wirelog/wirelog-parser.h>."
)
NOFALLBACK = (
    "--wrap-mode=nofallback refuses the pinned Wirelog fallback required "
    f"to satisfy {required_api}."
)


def require_messages(scenario, output, messages):
    for message in messages:
        if message not in output:
            fail(
                f"{scenario}: missing diagnostic: {message}\n"
                f"{clipped(output)}"
            )


def successful_scenario(base, name, system_kind, fallback_kind, expected,
                        options=(), messages=()):
    scenario_dir = base / name
    fixture, build, native_file, env = prepare_selection_fixture(
        scenario_dir, system_kind, fallback_kind, expected
    )
    setup = require_success(
        f"{name}: selection setup",
        [meson, "setup", build, fixture, "--native-file", native_file,
         *options],
        env=env,
    )
    output = setup.stdout + setup.stderr
    require_messages(name, output, messages)
    require_success(
        f"{name}: selection compile",
        [meson, "compile", "-C", build],
        env=env,
    )
    require_success(
        f"{name}: provider runtime",
        [meson, "test", "-C", build, "--print-errorlogs"],
        env=env,
    )


def setup_failure_scenario(base, name, system_kind, fallback_kind, options,
                           messages, forbidden=()):
    scenario_dir = base / name
    fixture, build, native_file, env = prepare_selection_fixture(
        scenario_dir, system_kind, fallback_kind, "fallback"
    )
    result = run_command(
        f"{name}: expected setup failure",
        [meson, "setup", build, fixture, "--native-file", native_file,
         *options],
        env=env,
    )
    output = result.stdout + result.stderr
    if result.returncode == 0:
        fail(f"{name}: Meson setup unexpectedly succeeded\n{clipped(output)}")
    require_messages(name, output, messages)
    for token in forbidden:
        if token in output:
            fail(f"{name}: unexpected diagnostic token: {token}\n{output}")


def fallback_missing_definition_scenario(base):
    name = "fallback-missing-definition"
    scenario_dir = base / name
    fixture, build, native_file, env = prepare_selection_fixture(
        scenario_dir, "missing", "missing_symbol", "fallback"
    )
    setup = require_success(
        f"{name}: type-only setup",
        [meson, "setup", build, fixture, "--native-file", native_file],
        env=env,
    )
    require_messages(name, setup.stdout + setup.stderr, [SYSTEM_SIGNATURE])
    result = run_command(
        f"{name}: expected consumer link failure",
        [meson, "compile", "-C", build],
        env=env,
    )
    output = result.stdout + result.stderr
    if result.returncode == 0:
        fail(f"{name}: consumer unexpectedly linked\n{clipped(output)}")
    if required_api not in output:
        fail(
            f"{name}: link failure did not name required API\n"
            f"{clipped(output)}"
        )


require_success("Meson executable", [meson, "--version"], timeout=30)

with tempfile.TemporaryDirectory(prefix="wyrelog-wirelog-boundary-") as temp:
    base = Path(temp)
    successful_scenario(
        base, "system-missing-api", "missing", "compatible", "fallback",
        messages=[SYSTEM_SIGNATURE],
    )
    successful_scenario(
        base, "system-wrong-signature", "wrong_signature", "compatible",
        "fallback", messages=[SYSTEM_SIGNATURE],
    )
    successful_scenario(
        base, "system-missing-definition", "missing_symbol", "compatible",
        "fallback", messages=[SYSTEM_LINK],
    )
    successful_scenario(
        base, "compatible-system", "compatible", "forbidden", "system",
    )
    setup_failure_scenario(
        base, "nofallback-signature", "missing", "compatible",
        ["--wrap-mode=nofallback"], [SYSTEM_SIGNATURE, NOFALLBACK],
    )
    setup_failure_scenario(
        base, "nofallback-link", "missing_symbol", "compatible",
        ["--wrap-mode=nofallback"], [SYSTEM_LINK, NOFALLBACK],
    )
    successful_scenario(
        base, "force-fallback-option", "compatible", "compatible", "fallback",
        options=["--force-fallback-for=wirelog"],
    )
    successful_scenario(
        base, "force-fallback-global", "compatible", "compatible", "fallback",
        options=["--wrap-mode=forcefallback"],
    )
    setup_failure_scenario(
        base, "invalid-automatic-fallback", "missing", "wrong_signature", [],
        [FALLBACK_SIGNATURE, "Prior system rejection: " + SYSTEM_SIGNATURE],
    )
    setup_failure_scenario(
        base, "invalid-forced-fallback", "compatible", "wrong_signature",
        ["--force-fallback-for=wirelog"], [FALLBACK_SIGNATURE],
        forbidden=["Prior system rejection:"],
    )
    fallback_missing_definition_scenario(base)

print("Wirelog dependency boundary: OK")
