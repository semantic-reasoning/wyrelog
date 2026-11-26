#!/usr/bin/env python3
"""Exercise the production DuckDB dependency selector in isolated projects.

Each scenario installs a fake DuckDB (a static library, its duckdb.h and a
pkg-config file or a CMake package) into a private prefix, copies the
production selector into a small consumer project next to a fake prebuilt
subproject, and runs meson setup, compile and test.  pkg-config and CMake are
confined to the scenario's own prefix, so a DuckDB installed on the host is
never seen; the "no provider" scenario proves that confinement.
"""

from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile


if len(sys.argv) != 3:
    raise SystemExit("usage: test-duckdb-dependency-boundary.py ROOT MESON")

root = Path(sys.argv[1]).resolve()
meson_arg = Path(sys.argv[2])
if not meson_arg.is_absolute():
    raise SystemExit("Meson executable path must be absolute")
meson = str(meson_arg)
if not meson_arg.is_file():
    raise SystemExit(f"Meson executable does not exist: {meson}")


def fail(message):
    raise SystemExit(message)


selector_call = "subdir('meson/duckdb-dependency')"
selector_path = root / "meson" / "duckdb-dependency" / "meson.build"
root_meson = (root / "meson.build").read_text(encoding="utf-8")

# The selector runs only for the prebuilt provider: the source subproject and
# the secure bridge must never meet an installed DuckDB.
if root_meson.count(selector_call) != 1:
    fail("root meson.build must delegate DuckDB selection exactly once")
selector_offset = root_meson.index(selector_call)
prebuilt_branch = "  if duckdb_source == 'prebuilt'\n"
source_branch = "  else\n    duckdb_provider = 'subproject'\n"
if root_meson.count(prebuilt_branch) != 1 or root_meson.count(source_branch) != 1:
    fail("root lost the prebuilt/subproject DuckDB branches")
if not (root_meson.index(prebuilt_branch) < selector_offset
        < root_meson.index(source_branch)):
    fail("DuckDB selector must run only in the duckdb_source=prebuilt branch")
secure_refusal = "if get_option('duckdb_source') != 'subproject'"
if secure_refusal not in root_meson or \
        root_meson.index(secure_refusal) > selector_offset:
    fail("secure bridge must refuse duckdb_source=prebuilt before selection")
for required_input in (
    "cc = meson.get_compiler('c')",
    "force_fallback_for = get_option('force_fallback_for')",
    "wrap_mode = get_option('wrap_mode')",
    "product_install = get_option('product_install')",
):
    if required_input not in root_meson:
        fail(f"root lost DuckDB selector input: {required_input}")
    if root_meson.index(required_input) > selector_offset:
        fail(f"DuckDB selector runs before required input: {required_input}")

for meson_file in root.rglob("meson.build"):
    relative = meson_file.relative_to(root)
    if relative.parts[0] == "subprojects" or meson_file == selector_path:
        continue
    source = meson_file.read_text(encoding="utf-8")
    for competing in ("dependency('duckdb'", "dependency('DuckDB'",
                      "dependency(duckdb_prebuilt_name",
                      "dependency('duckdb-prebuilt-"):
        if competing in source:
            fail(f"competing DuckDB selector remains in {relative}: {competing}")

selector_source = selector_path.read_text(encoding="utf-8")
for owned, count in (("dependency('duckdb',", 1), ("dependency('DuckDB',", 1),
                     ("dependency(duckdb_prebuilt_name,", 1)):
    if selector_source.count(owned) != count:
        fail(f"production selector must own {count} {owned}")

if shutil.which("cmake") is None:
    fail("cmake is required: the selector's CMake discovery is under test")


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
    # As in test-wirelog-dependency-boundary.py: Meson's own code is outside
    # this repository's EncodingWarning policy.
    env.pop("PYTHONWARNDEFAULTENCODING", None)
    if env.get("PYTHONWARNINGS") == "error::EncodingWarning":
        env.pop("PYTHONWARNINGS")
    for name in ("CPATH", "C_INCLUDE_PATH", "LIBRARY_PATH", "CMAKE_PREFIX_PATH",
                 "PKG_CONFIG_PATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        env.pop(name, None)
    # As in test-wirelog-dependency-boundary.py: the nested Meson runs from
    # another directory, so a relative PKG_CONFIG must be resolved here.
    configured_pkgconfig = env.get("PKG_CONFIG")
    if configured_pkgconfig and not Path(configured_pkgconfig).is_absolute():
        resolved_pkgconfig = shutil.which(configured_pkgconfig)
        if resolved_pkgconfig is None:
            fail(f"configured PKG_CONFIG was not found: {configured_pkgconfig}")
        env["PKG_CONFIG"] = resolved_pkgconfig
    return env


if platform.system() == "Linux":
    PREBUILT = "duckdb-prebuilt-linux"
elif platform.system() == "Darwin":
    PREBUILT = "duckdb-prebuilt-osx"
elif platform.system() == "Windows":
    PREBUILT = "duckdb-prebuilt-windows"
else:
    fail(f"unsupported host for the DuckDB selector: {platform.system()}")


def duckdb_header(marker, series_2_0):
    resource = ("  DUCKDB_ERROR_RESOURCE_IN_USE = 44,\n" if series_2_0 else "")
    return f"""#pragma once
#define {marker} 1
typedef enum duckdb_error_type {{
  DUCKDB_ERROR_INVALID = 0,
{resource}}} duckdb_error_type;
const char *duckdb_library_version(void);
"""


def duckdb_source(library_version):
    if library_version is None:
        return "int duckdb_fixture_anchor(void) { return 0; }\n"
    if library_version == NULL:
        return """#include <duckdb.h>
const char *
duckdb_library_version(void)
{
  return 0;
}
"""
    return f"""#include <duckdb.h>
const char *
duckdb_library_version(void)
{{
  return "{library_version}";
}}
"""


class Provider:
    """A fake installed DuckDB.

    method: 'pkg-config' or 'cmake'.  version: the version its metadata
    reports.  series_2_0: whether duckdb.h carries the 2.0 error code.
    library_version: what duckdb_library_version() returns (None: the
    function is missing; NULL: it returns NULL).
    names_include: whether the CMake package sets DuckDB_INCLUDE_DIRS.
    """

    def __init__(self, method, version, series_2_0=True, library_version=None,
                 cmake_version=None, names_include=True):
        self.names_include = names_include
        self.method = method
        self.version = version
        self.series_2_0 = series_2_0
        self.library_version = ("v" + version if library_version is None
                                else library_version)
        self.cmake_version = version if cmake_version is None else cmake_version


MISSING = "missing"
NULL = "null"


def install_provider(scenario_dir, index, provider):
    name = f"provider-{index}"
    source_dir = scenario_dir / (name + "-source")
    build_dir = scenario_dir / (name + "-build")
    prefix = scenario_dir / (name + "-prefix")
    library_version = (None if provider.library_version == MISSING
                       else provider.library_version)
    pkg = ""
    if provider.method == "pkg-config":
        pkg = f"""pkg = import('pkgconfig')
pkg.generate(duckdb_lib,
  name : 'duckdb',
  filebase : 'duckdb',
  description : 'isolated DuckDB system fixture',
  version : '{provider.version}',
)
"""
    write(source_dir / "meson.build", f"""project('duckdb-system-fixture', 'c',
  meson_version : '>= 1.1.0',
  default_options : ['c_std=c17'],
)
duckdb_lib = static_library('duckdb', 'duckdb.c', install : true)
install_headers('duckdb.h')
{pkg}""")
    write(source_dir / "duckdb.h",
          duckdb_header("DUCKDB_PROVIDER_SYSTEM", provider.series_2_0))
    write(source_dir / "duckdb.c", duckdb_source(library_version))
    env = nested_meson_environment()
    require_success(f"{scenario_dir.name}: {name} setup",
                    [meson, "setup", build_dir, source_dir, "--prefix", prefix,
                     "--libdir", "lib"], env=env)
    require_success(f"{scenario_dir.name}: {name} install",
                    [meson, "install", "-C", build_dir], env=env)
    if provider.method == "pkg-config":
        return prefix / "lib" / "pkgconfig", None
    libraries = sorted(path for path in (prefix / "lib").iterdir()
                       if path.name.startswith(("libduckdb", "duckdb")))
    if len(libraries) != 1:
        fail(f"{scenario_dir.name}: expected one fixture library: {libraries}")
    cmake_dir = prefix / "lib" / "cmake" / "DuckDB"
    include = ('set(DuckDB_INCLUDE_DIRS "${_duckdb_prefix}/include")\n'
               if provider.names_include else "")
    write(cmake_dir / "DuckDBConfig.cmake", f"""get_filename_component(_duckdb_prefix "${{CMAKE_CURRENT_LIST_DIR}}/../../.." ABSOLUTE)
{include}if(NOT TARGET duckdb)
  add_library(duckdb STATIC IMPORTED)
  set_target_properties(duckdb PROPERTIES
    IMPORTED_LOCATION "${{_duckdb_prefix}}/lib/{libraries[0].name}")
endif()
""")
    write(cmake_dir / "DuckDBConfigVersion.cmake", f"""set(PACKAGE_VERSION "{provider.cmake_version}")
set(PACKAGE_VERSION_COMPATIBLE TRUE)
""")
    return None, prefix


def write_fallback(fixture, forbidden):
    fallback = fixture / "subprojects" / PREBUILT
    if forbidden:
        write(fallback / "meson.build", f"""project('{PREBUILT}', 'c', version : '2.0.0')
error('a usable system DuckDB was selected, yet the prebuilt fallback ran')
""")
        return
    write(fallback / "meson.build", f"""project('{PREBUILT}', 'c',
  version : '2.0.0',
  meson_version : '>= 1.1.0',
  default_options : ['c_std=c17'],
)
duckdb_dep = declare_dependency(
  include_directories : include_directories('.'),
  link_with : static_library('duckdb-fallback', 'duckdb.c'),
  version : '2.0.0',
)
""")
    write(fallback / "duckdb.h", duckdb_header("DUCKDB_PROVIDER_FALLBACK", True))
    write(fallback / "duckdb.c", duckdb_source("v2.0.0"))


def consumer_source(expected):
    marker = "SYSTEM" if expected == "system" else "FALLBACK"
    other = "FALLBACK" if expected == "system" else "SYSTEM"
    return f"""#include <duckdb.h>
#if !defined(DUCKDB_PROVIDER_{marker}) || defined(DUCKDB_PROVIDER_{other})
#error selected DuckDB provider does not match the scenario
#endif
int
main(void)
{{
  return duckdb_library_version() == 0;
}}
"""


# CMake would otherwise search /usr and prefixes derived from PATH, where a
# real DuckDB may be installed.  CMAKE_IGNORE_PREFIX_PATH needs CMake 3.23.
CMAKE_ISOLATION = """[cmake]
CMAKE_IGNORE_PREFIX_PATH = '/;/usr;/usr/local;/opt/homebrew;/opt/local'
CMAKE_FIND_USE_CMAKE_SYSTEM_PATH = 'FALSE'
CMAKE_FIND_USE_PACKAGE_REGISTRY = 'FALSE'
CMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY = 'FALSE'
"""


def prepare(base, name, providers, expected, forbidden_fallback, decoy=False):
    scenario_dir = base / name
    pkgconfig_dir = scenario_dir / "empty-pkgconfig"
    pkgconfig_dir.mkdir(parents=True)
    cmake_prefixes = []
    for index, provider in enumerate(providers):
        pc, prefix = install_provider(scenario_dir, index, provider)
        if pc is not None:
            pkgconfig_dir = pc
        if prefix is not None:
            cmake_prefixes.append(prefix)
    fixture = scenario_dir / "selection-source"
    write(fixture / "meson.build", """project('duckdb-selection-fixture', 'c',
  meson_version : '>= 1.1.0',
  default_options : ['c_std=c17'],
)
cc = meson.get_compiler('c')
force_fallback_for = get_option('force_fallback_for')
wrap_mode = get_option('wrap_mode')
product_install = get_option('product_install')
subdir('meson/duckdb-dependency')
message('DUCKDB_PROVIDER=' + duckdb_provider)
consumer = executable('duckdb-consumer', 'consumer.c',
  dependencies : duckdb_dep)
test('duckdb-provider', consumer)
""")
    write(fixture / "meson_options.txt",
          "option('product_install', type : 'boolean', value : false)\n")
    write(fixture / "consumer.c", consumer_source(expected))
    destination = fixture / "meson" / "duckdb-dependency"
    destination.mkdir(parents=True)
    shutil.copy2(selector_path, destination / "meson.build")
    write_fallback(fixture, forbidden_fallback)
    native_file = scenario_dir / "isolation.ini"
    write(native_file, CMAKE_ISOLATION)
    env = nested_meson_environment()
    env["PKG_CONFIG_LIBDIR"] = str(pkgconfig_dir)
    env["PKG_CONFIG_PATH"] = ""
    if decoy:
        # A wrong duckdb.h on the compiler's default search path: only the
        # include directory the CMake package names may be used.
        decoy_dir = scenario_dir / "decoy-include"
        write(decoy_dir / "duckdb.h",
              "#error the default-path duckdb.h was used instead of the "
              "CMake package's\n")
        env["C_INCLUDE_PATH"] = str(decoy_dir)
    options = ["--native-file", native_file]
    if cmake_prefixes:
        options.append("-Dcmake_prefix_path="
                       + ",".join(str(prefix) for prefix in cmake_prefixes))
    return fixture, scenario_dir / "selection-build", options, env


def require_messages(scenario, output, messages):
    for message in messages:
        if message not in output:
            fail(f"{scenario}: missing diagnostic: {message}\n{clipped(output)}")


def selected(base, name, providers, expected, *, options=(), messages=(),
             decoy=False):
    fixture, build, base_options, env = prepare(
        base, name, providers, expected, expected == "system", decoy)
    setup = require_success(f"{name}: selection setup",
                            [meson, "setup", build, fixture, *base_options,
                             *options], env=env)
    output = setup.stdout + setup.stderr
    require_messages(name, output, ["DUCKDB_PROVIDER=" +
                                    ("system" if expected == "system"
                                     else "prebuilt"), *messages])
    executed = f"Executing subproject {PREBUILT}" in output
    if executed != (expected != "system"):
        fail(f"{name}: prebuilt subproject executed={executed}, expected "
             f"provider {expected}\n{clipped(output)}")
    require_success(f"{name}: consumer compile", [meson, "compile", "-C", build],
                    env=env)
    require_success(f"{name}: consumer runtime",
                    [meson, "test", "-C", build, "--print-errorlogs"], env=env)


def refused(base, name, providers, options, messages):
    fixture, build, base_options, env = prepare(
        base, name, providers, "fallback", False)
    result = run_command(f"{name}: expected setup failure",
                         [meson, "setup", build, fixture, *base_options,
                          *options], env=env)
    output = result.stdout + result.stderr
    if result.returncode == 0:
        fail(f"{name}: Meson setup unexpectedly succeeded\n{clipped(output)}")
    require_messages(name, output, messages)


PC = "pkg-config"
CM = "cmake"
NOT_FOUND_PC = "System DuckDB (pkg-config) was not found."
NOT_FOUND_CM = "System DuckDB (cmake) was not found."
SERIES = "is not a DuckDB 2.0.0 or later 2.0.x release."
HEADER = "System DuckDB (pkg-config) header is not a DuckDB 2.0 header."
LINK = "System DuckDB (pkg-config) cannot be linked."
USED_PREBUILT = f"The pinned DuckDB prebuilt ({PREBUILT}) is used."
NOFALLBACK = ("--wrap-mode=nofallback refuses the pinned DuckDB prebuilt "
              "fallback; install DuckDB 2.0.0 or a later 2.0.x release.")

require_success("Meson executable", [meson, "--version"], timeout=30)

with tempfile.TemporaryDirectory(prefix="wyrelog-duckdb-boundary-") as temp:
    base = Path(temp)
    # Positive control for the isolation: with no fixture provider, neither
    # discovery method may find anything, whatever the host has installed.
    selected(base, "no-provider", [], "fallback",
             messages=[NOT_FOUND_PC, NOT_FOUND_CM, USED_PREBUILT])
    selected(base, "pkg-config-2.0.0", [Provider(PC, "2.0.0")], "system",
             messages=["System DuckDB (pkg-config) 2.0.0 is used."])
    selected(base, "pkg-config-2.0.1", [Provider(PC, "2.0.1")], "system",
             messages=["System DuckDB (pkg-config) 2.0.1 is used."])
    selected(base, "cmake-2.0.1", [Provider(CM, "2.0.1")], "system",
             messages=[NOT_FOUND_PC, "System DuckDB (cmake) 2.0.1 is used."],
             decoy=platform.system() != "Windows")
    selected(base, "cmake-no-include", [Provider(CM, "2.0.1",
                                                 names_include=False)],
             "fallback",
             messages=["System DuckDB (cmake) does not name its include "
                       "directory.", USED_PREBUILT])
    # The version probe exits nonzero: reported as a probe that could not
    # run, not as a version mismatch.
    selected(base, "pkg-config-probe-fails",
             [Provider(PC, "2.0.1", library_version=NULL)], "fallback",
             messages=["System DuckDB (pkg-config) library could not be run "
                       "to report its version.", USED_PREBUILT])
    selected(base, "cmake-v-prefixed", [Provider(CM, "2.0.1",
                                                 cmake_version="v2.0.1")],
             "system")
    selected(base, "pkg-config-1.5.6", [Provider(PC, "1.5.6")], "fallback",
             messages=["System DuckDB (pkg-config) 1.5.6 " + SERIES])
    selected(base, "pkg-config-2.1.0", [Provider(PC, "2.1.0")], "fallback",
             messages=["System DuckDB (pkg-config) 2.1.0 " + SERIES])
    selected(base, "pkg-config-dev", [Provider(PC, "2.0.1-dev1")], "fallback",
             messages=["System DuckDB (pkg-config) 2.0.1-dev1 " + SERIES])
    selected(base, "pkg-config-1.x-header",
             [Provider(PC, "2.0.1", series_2_0=False)], "fallback",
             messages=[HEADER])
    selected(base, "pkg-config-library-mismatch",
             [Provider(PC, "2.0.1", library_version="v1.5.6")], "fallback",
             messages=["System DuckDB (pkg-config) library does not report "
                       "v2.0.1."])
    selected(base, "pkg-config-library-patch-mismatch",
             [Provider(PC, "2.0.1", library_version="v2.0.0")], "fallback",
             messages=["System DuckDB (pkg-config) library does not report "
                       "v2.0.1."])
    selected(base, "pkg-config-missing-function",
             [Provider(PC, "2.0.1", library_version=MISSING)], "fallback",
             messages=[LINK])
    selected(base, "stale-pkg-config-then-cmake",
             [Provider(PC, "1.5.6"), Provider(CM, "2.0.1")], "system",
             messages=["System DuckDB (pkg-config) 1.5.6 " + SERIES])
    selected(base, "force-fallback-global", [Provider(PC, "2.0.1")],
             "fallback", options=["--wrap-mode=forcefallback"])
    selected(base, "force-fallback-duckdb", [Provider(PC, "2.0.1")],
             "fallback", options=["--force-fallback-for=duckdb"])
    selected(base, "force-fallback-prebuilt-name", [Provider(PC, "2.0.1")],
             "fallback", options=["--force-fallback-for=" + PREBUILT])
    selected(base, "product-install", [Provider(PC, "2.0.1")], "fallback",
             options=["-Dproduct_install=true"])
    refused(base, "nofallback-no-provider", [], ["--wrap-mode=nofallback"],
            [NOT_FOUND_PC, NOT_FOUND_CM, NOFALLBACK])
    refused(base, "nofallback-1.5.6", [Provider(PC, "1.5.6")],
            ["--wrap-mode=nofallback"],
            ["System DuckDB (pkg-config) 1.5.6 " + SERIES, NOFALLBACK])
    selected(base, "nofallback-system", [Provider(PC, "2.0.1")], "system",
             options=["--wrap-mode=nofallback"])


print("DuckDB dependency boundary: OK")
