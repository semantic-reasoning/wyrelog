#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Negative fixtures for the production daemon WRITE conformance guard."""

import argparse
import importlib.util
import json
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

def synthetic_db(root, real_root, real_build_root, compiler_id, compiler,
                 defines=(), extra=(), real_compiler_id=None):
    build_root = Path(root) / ".guard-build"
    build_root.mkdir(exist_ok=True)
    source = (Path(root) / "wyrelog/daemon/http.c").resolve()
    database = json.loads((Path(real_build_root) / "compile_commands.json").read_text(encoding="utf-8"))
    real_compiler_id = real_compiler_id or compiler_id
    real = next(e for e in database
        if synthetic_db.is_daemon_http_output(e.get("output"), real_compiler_id))
    if real.get("arguments"):
        real_argv = real["arguments"]
    elif compiler_id in ("clang-cl", "msvc"):
        real_argv = synthetic_db.windows_split(real["command"])
    else:
        real_argv = shlex.split(real["command"])
    inherited=[]; i=1
    while i<len(real_argv):
        arg=real_argv[i]
        if arg in ("-I","-D","-isystem","-include","-imacros","-iquote","--sysroot"):
            inherited.extend((arg,real_argv[i+1])); i+=2; continue
        if arg.upper() in ("/I","/D","/FI"):
            inherited.extend((arg,real_argv[i+1])); i+=2; continue
        if arg.startswith(("-I","-D","--sysroot=")): inherited.append(arg)
        elif arg.upper().startswith(("/I","/D","/FI")): inherited.append(arg)
        i+=1
    defines = tuple(defines)
    if compiler_id in ("clang-cl", "msvc"):
        translated=[]; i=0
        while i<len(inherited):
            arg=inherited[i]
            if arg in ("-I","-isystem"):
                translated.append("/I"+inherited[i+1]); i+=2; continue
            if arg=="-D": translated.append("/D"+inherited[i+1]); i+=2; continue
            if arg.startswith("-I"): translated.append("/I"+arg[2:])
            elif arg.startswith("-D"): translated.append("/D"+arg[2:])
            elif arg.upper() in ("/I","/D","/FI"):
                translated.extend((arg,inherited[i+1])); i+=2; continue
            elif arg.upper().startswith(("/I","/D","/FI")): translated.append(arg)
            i+=1
        flags = (translated + ["/I" + str(real_build_root), "/I" + str(real_root),
            "/I" + str(Path(real_root) / "wyrelog")] +
            ["/D" + x for x in defines])
    else:
        flags = (inherited + ["-I" + str(real_build_root), "-I" + str(real_root),
            "-I" + str(Path(real_root) / "wyrelog")] +
            ["-D" + x for x in defines])
    windows = compiler_id in ("clang-cl", "msvc")
    output = ("wyrelog/wyrelogd.exe.p/daemon_http.c.obj" if windows
        else "wyrelog/wyrelogd.p/daemon_http.c.o")
    entry = {"directory": str(real_build_root),
        "arguments": list(compiler) + flags + list(extra) + ["-c", str(source),
            "-o", output],
        "file": str(source), "output": output}
    (build_root / "compile_commands.json").write_text(json.dumps([entry]), encoding="utf-8")
    return build_root

def invoke(guard, root, compiler_id, compiler, defines=(), build_root=None, extra=()):
    if build_root is None:
        build_root = synthetic_db(root, invoke.real_root, invoke.real_build_root,
            compiler_id, compiler, defines, extra, invoke.real_compiler_id)
    return subprocess.run([sys.executable, guard, str(root), "--build-root",
                           str(build_root), "--compiler-id", compiler_id],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True)

def expect_compile_db_rejected(guard, root, compiler_id, compiler, build_root,
                               database, label):
    (Path(build_root) / "compile_commands.json").write_text(
        json.dumps(database), encoding="utf-8")
    if invoke(guard, root, compiler_id, compiler,
              build_root=build_root).returncode == 0:
        raise SystemExit(f"guard accepted invalid compile database: {label}")

def fake_clang_script(compiler, actual_cl):
    common = ("#!/usr/bin/env python3\nimport subprocess, sys\n"
        "required={'/nologo','/E','/TC'}\n"
        "assert required.issubset(sys.argv[1:])\n")
    if actual_cl:
        return common + "MODE='cl'\n" + f"cmd={compiler!r}+sys.argv[1:]\n" + \
            "raise SystemExit(subprocess.run(cmd).returncode)\n"
    return common + "MODE='gnu'\n" + f"cmd={compiler!r}+['-E','-x','c']+" + \
        "['-D'+x[2:] if x.startswith('/D') else '-I'+x[2:] " + \
        "for x in sys.argv[1:] if x.startswith(('/D','/I'))]+" + \
        "[sys.argv[-1]]\nraise SystemExit(subprocess.run(cmd).returncode)\n"

def mutate_function(source, name, old, new):
    start = source.index(name + " (")
    pos = source.index(old, start)
    return source[:pos] + source[pos:].replace(old, new, 1)

def nested_write_scope(source):
    changed = mutate_function(source, "tenant_mutation_handler",
        "g_auto (WylDaemonPolicyWrite) write = { 0 };",
        "{ g_auto (WylDaemonPolicyWrite) write = { 0 };")
    return mutate_function(changed, "tenant_mutation_handler",
        "wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);",
        "wyrelog_error_t rc = wyl_daemon_policy_write_acquire "
        "(ctx, &write); }")

def move_append_acquire_to_forget(source):
    start = source.index("facts_route_handler (")
    first = source.index("g_auto (WylDaemonPolicyWrite) write", start)
    second = source.index("g_auto (WylDaemonPolicyWrite) write", first + 1)
    acquire = source.index("wyl_daemon_policy_write_acquire (ctx, &write);", second)
    acquire_end = acquire + len("wyl_daemon_policy_write_acquire (ctx, &write);")
    chunk = source[second:acquire_end]
    changed = source[:second] + "wyrelog_error_t rc = WYRELOG_E_OK;" + source[acquire_end:]
    insert = changed.index("wyl_fact_store_forget (", start)
    return changed[:insert] + chunk + "\n    " + changed[insert:]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("guard")
    parser.add_argument("root")
    parser.add_argument("--build-root", required=True)
    parser.add_argument("--compiler-id", required=True)
    parser.add_argument("--define", action="append", default=[])
    parser.add_argument("compiler", nargs="+")
    ns = parser.parse_args()
    compiler = ns.compiler[1:] if ns.compiler[:1] == ["--"] else ns.compiler
    guard_spec = importlib.util.spec_from_file_location("authority_guard", ns.guard)
    guard_module = importlib.util.module_from_spec(guard_spec)
    guard_spec.loader.exec_module(guard_module)
    synthetic_db.windows_split = guard_module.split_windows
    synthetic_db.is_daemon_http_output = guard_module.is_daemon_http_output
    invoke.real_root = Path(ns.root).resolve()
    invoke.real_build_root = Path(ns.build_root).resolve()
    invoke.real_compiler_id = ns.compiler_id
    source = (Path(ns.root) / "wyrelog/daemon/http.c").read_text(encoding="utf-8")
    if invoke(ns.guard, ns.root, ns.compiler_id, compiler, ns.define,
              build_root=ns.build_root).returncode:
        raise SystemExit("production fixture rejected")
    with tempfile.TemporaryDirectory(prefix="wyrelog-empty-compile-db-") as empty:
        raw = subprocess.run([sys.executable, ns.guard, ns.root, "--raw-only"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if raw.returncode: raise SystemExit("raw-only no-entry fixture rejected")
        missing = subprocess.run([sys.executable, ns.guard, ns.root,
            "--build-root", empty, "--compiler-id", ns.compiler_id],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if missing.returncode == 0: raise SystemExit("enabled missing-entry fixture accepted")

    fixtures = {
        "legacy-mutex": source + "\npolicy_mutation_lock\n",
        "wrong-lock": source + "\ng_mutex_lock (&other->lock);\n",
        "missing-handler": source.replace("tenant_mutation_handler (", "tenant_mutation_removed (", 1),
        "duplicate-acquire": mutate_function(source, "tenant_mutation_handler",
            "wyl_daemon_policy_write_acquire (ctx, &write);",
            "wyl_daemon_policy_write_acquire (ctx, &write);\n"
            "  wyl_daemon_policy_write_acquire (ctx, &write);"),
        "inactive-acquire": mutate_function(source, "tenant_mutation_handler",
            "wyl_daemon_policy_write_acquire (ctx, &write);",
            "#if 0\n  wyl_daemon_policy_write_acquire (ctx, &write);\n#endif"),
        "mutation-before-acquire": mutate_function(source, "tenant_mutation_handler",
            "wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);",
            "wyrelog_error_t rc = wyl_policy_store_create_tenant "
            "(write.store, tenant, NULL);\n"
            "  rc = wyl_daemon_policy_write_acquire (ctx, &write);"),
        "manual-clear": source.replace(
            "set_tenant_mutation_json (msg, tenant, changed);",
            "wyl_daemon_policy_write_clear (&write);\n"
            "  set_tenant_mutation_json (msg, tenant, changed);", 1),
        "raw-store-getter": source.replace(
            "wyl_policy_store_create_tenant (write.store, tenant, &changed)",
            "wyl_policy_store_create_tenant "
            "(wyl_handle_get_policy_store (ctx->handle), tenant, &changed)", 1),
        "tenant-delete-missing": mutate_function(source,
            "tenant_mutation_handler", "if (g_strcmp0 (action",
            "if (g_strcmp0_disabled (action"),
        "facts-one-branch": mutate_function(source, "facts_route_handler",
            "wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);",
            "wyrelog_error_t rc = WYRELOG_E_OK;"),
        "outside-mutator": source + "\nvoid bad(void){ wyl_perm_grant (NULL, NULL); }\n",
        "shadow-write": mutate_function(source, "tenant_mutation_handler",
            "g_auto (WylDaemonPolicyWrite) write = { 0 };",
            "g_auto (WylDaemonPolicyWrite) write = { 0 };\n"
            "  WylDaemonPolicyWrite write;"),
        "graph-mutation-on-acquire-failure": mutate_function(source,
            "graph_create_handler", "if (rc == WYRELOG_E_OK)",
            "if (rc != WYRELOG_E_OK)"),
        "mutation-after-result": mutate_function(source,
            "graph_create_handler",
            "set_graph_mutation_json (msg, tenant, graph, \"created\", TRUE);",
            "set_graph_mutation_json (msg, tenant, graph, \"created\", TRUE);\n"
            "  (void) wyl_policy_store_create_fact_graph "
            "(write.store, &opts, NULL);"),
        "nested-write-scope": nested_write_scope(source),
        "missing-append": mutate_function(source, "facts_route_handler",
            "wyl_fact_store_append_batch", "wyl_fact_store_append_removed"),
        "missing-retract": mutate_function(source, "facts_route_handler",
            "wyl_fact_store_retract_batch", "wyl_fact_store_retract_removed"),
        "raw-lookup-getter": mutate_function(source,
            "schema_register_handler", "lookup_fact_graph (write.store",
            "lookup_fact_graph (wyl_handle_get_policy_store (ctx->handle)"),
        "raw-load-getter": mutate_function(source, "facts_route_handler",
            "wyl_policy_store_load_fact_relation_schema_columns\n"
            "        (write.store",
            "wyl_policy_store_load_fact_relation_schema_columns\n"
            "        (wyl_handle_get_policy_store (ctx->handle)"),
        "raw-validate-getter": mutate_function(source, "facts_route_handler",
            "wyl_fact_schema_validate_batch (write.store",
            "wyl_fact_schema_validate_batch "
            "(wyl_handle_get_policy_store (ctx->handle)"),
        "empty-success-guard": mutate_function(source,
            "graph_create_handler",
            "if (rc == WYRELOG_E_OK)\n    rc = wyl_policy_store_create_fact_graph",
            "if (rc == WYRELOG_E_OK) {}\n  rc = wyl_policy_store_create_fact_graph"),
        "append-acquire-in-forget-sibling": move_append_acquire_to_forget(source),
        "unconditional-fact-selector": mutate_function(source,
            "facts_route_handler", "if (op == FACT_HTTP_OP_RETRACT)",
            "if (TRUE)"),
        "pre-acquire-raw-store-alias": mutate_function(source,
            "tenant_mutation_handler",
            "g_auto (WylDaemonPolicyWrite) write = { 0 };",
            "wyl_policy_store_t *store = wyl_handle_get_policy_store "
            "(ctx->handle);\n  g_auto (WylDaemonPolicyWrite) write = { 0 };").replace(
            "wyl_policy_store_create_tenant (write.store",
            "wyl_policy_store_create_tenant (store", 1),
        "reverse-ctx-lock": mutate_function(source, "tenant_mutation_handler",
            "g_auto (WylDaemonPolicyWrite) write = { 0 };",
            "g_mutex_lock (&ctx->lock);\n"
            "  g_auto (WylDaemonPolicyWrite) write = { 0 };"),
        "direct-permission-unconditional-selector": mutate_function(source,
            "direct_permission_mutation_handler", "if (grant)", "if (TRUE)"),
        "role-unconditional-selector": mutate_function(source,
            "role_membership_mutation_handler", "if (grant)", "if (TRUE)"),
        "tenant-seal-disabled-selector": mutate_function(source,
            "tenant_mutation_handler",
            "else if (g_strcmp0 (action, \"seal\") == 0)", "else if (FALSE)"),
        "path-dependent-ctx-lock": mutate_function(source,
            "direct_permission_mutation_handler",
            "g_auto (WylDaemonPolicyWrite) write = { 0 };",
            "g_auto (WylDaemonPolicyWrite) write = { 0 };\n"
            "  if (grant) g_mutex_lock (&ctx->lock);\n"
            "  if (!grant) g_mutex_unlock (&ctx->lock);"),
        "trylock-across-write": mutate_function(source,
            "tenant_mutation_handler",
            "g_auto (WylDaemonPolicyWrite) write = { 0 };",
            "g_auto (WylDaemonPolicyWrite) write = { 0 };\n"
            "  (void) g_mutex_trylock (&ctx->lock);"),
        "pre-acquire-supporting-store-alias": mutate_function(source,
            "direct_permission_mutation_handler",
            "g_auto (WylDaemonPolicyWrite) write = { 0 };",
            "wyl_policy_store_t *store = wyl_handle_get_policy_store "
            "(ctx->handle);\n  g_auto (WylDaemonPolicyWrite) write = { 0 };").replace(
            "ensure_policy_permission_exists (msg, write.store, perm)",
            "ensure_policy_permission_exists (msg, store, perm)", 1),
        "string-literal-change": mutate_function(source,
            "graph_create_handler", '"created"', '"created_changed"'),
        "malformed-delimiter": source + "\nvoid malformed( {\n",
        "duplicate-function": source +
            "\nstatic void tenant_mutation_handler(void) { return; }\n",
        "disabled-branch-change": source.replace(
            '"fact_store_disabled"', '"fact_store_disabled_changed"', 1),
        "conditional-directive-change": source.replace(
            "if (!wyl_policy_store_tenant_id_is_valid (tenant) ||\n"
            "#ifdef WYL_HAS_FACT_STORE",
            "if (!wyl_policy_store_tenant_id_is_valid (tenant) ||\n"
            "#if defined(WYL_HAS_FACT_STORE)", 1),
        "storage-class-change": source.replace(
            "static void\ntenant_mutation_handler (",
            "void\ntenant_mutation_handler (", 1),
        "return-type-change": source.replace(
            "static gboolean\nensure_policy_permission_exists (",
            "static int\nensure_policy_permission_exists (", 1),
        "tenant-wrapper-reverse-call": mutate_function(source,
            "tenant_create_handler", '"create"', '"seal"'),
        "permission-wrapper-ctx-lock": mutate_function(source,
            "policy_permission_grant_handler",
            "direct_permission_mutation_handler (",
            "g_mutex_lock (&ctx->lock);\n  direct_permission_mutation_handler ("),
        "role-wrapper-ctx-lock": mutate_function(source,
            "policy_role_revoke_handler",
            "role_membership_mutation_handler (",
            "g_mutex_unlock (&ctx->lock);\n  role_membership_mutation_handler ("),
        "helper-direct-handler-call": source +
            "\nvoid bad_helper(void) { graph_create_handler "
            "(NULL, NULL, NULL, NULL, NULL); }\n",
        "helper-calls-tenant-wrapper": source +
            "\nvoid bad_helper(void) { tenant_create_handler "
            "(NULL, NULL, NULL, NULL, NULL); }\n",
        "helper-calls-permission-wrapper": source +
            "\nvoid bad_helper(void) { policy_permission_grant_handler "
            "(NULL, NULL, NULL, NULL, NULL); }\n",
        "handler-function-pointer-alias": source +
            "\nvoid *handler_alias = graph_create_handler;\n",
        "wrapper-function-pointer-alias": source +
            "\nvoid *wrapper_alias = policy_role_grant_handler;\n",
        "graph-route-deleted": source.replace(
            '  soup_server_add_handler (server, "/graphs/create", '
            'graph_create_handler, ctx,\n      NULL);\n', "", 1),
        "graph-route-duplicated": source.replace(
            '  soup_server_add_handler (server, "/graphs/create", '
            'graph_create_handler, ctx,\n      NULL);',
            '  soup_server_add_handler (server, "/graphs/create", '
            'graph_create_handler, ctx,\n      NULL);\n'
            '  soup_server_add_handler (server, "/graphs/create", '
            'graph_create_handler, ctx,\n      NULL);', 1),
        "tenant-route-path-change": source.replace(
            '"/tenants/create", tenant_create_handler',
            '"/tenants/other", tenant_create_handler', 1),
        "tenant-route-wrapper-swap": source.replace(
            '"/tenants/create", tenant_create_handler',
            '"/tenants/create", tenant_seal_handler', 1),
        "inactive-audit-legacy-mutex": source +
            "\n#ifndef WYL_HAS_AUDIT\npolicy_mutation_lock\n#endif\n",
        "inactive-acquire-alias": source +
            "\n#if 0\nvoid *inactive_alias = "
            "wyl_daemon_policy_write_acquire;\n#endif\n",
        "directive-acquire-alias": source +
            "\n#define INACTIVE_ACQUIRE wyl_daemon_policy_write_acquire\n",
        "cat-locked-wrapper": source +
            "\n#define CAT_INNER(a, b) a ## b\n"
            "#define CAT(a, b) CAT_INNER(a, b)\n"
            "void bad_helper(void) { CAT(tenant_, create_handler) "
            "(NULL, NULL, NULL, NULL, NULL); }\n",
        "wyrelog-ok-redefine": source +
            "\n#undef WYRELOG_E_OK\n#define WYRELOG_E_OK 17\n"
            "int dummy_status = WYRELOG_E_OK;\n",
        "true-redefine": "#define TRUE FALSE\n" + source,
        "acquire-alias": source +
            "\nvoid *acquire_alias = wyl_daemon_policy_write_acquire;\n",
        "mutator-alias": source +
            "\nvoid *mutator_alias = wyl_policy_store_create_tenant;\n",
        "mutex-alias": source + "\nvoid *mutex_alias = g_mutex_lock;\n",
    }
    with tempfile.TemporaryDirectory(prefix="wyrelog-daemon-guard-test-") as tmp:
        fixture_root = Path(tmp)
        target = fixture_root / "wyrelog/daemon/http.c"
        target.parent.mkdir(parents=True)
        manifest = fixture_root / "tools/daemon-policy-write-authority.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text((Path(ns.root) /
            "tools/daemon-policy-write-authority.json").read_text(
            encoding="utf-8"), encoding="utf-8")
        target.write_text(source, encoding="utf-8")
        obj_build = synthetic_db(fixture_root, invoke.real_root,
            invoke.real_build_root, ns.compiler_id, compiler, ns.define)
        obj_db = json.loads((obj_build / "compile_commands.json").read_text(encoding="utf-8"))
        if invoke(ns.guard, fixture_root, ns.compiler_id, compiler, ns.define,
                  build_root=obj_build).returncode:
            raise SystemExit("native compile entry fixture rejected")
        valid_entry = json.loads(json.dumps(obj_db[0]))
        near_misses = {
            "prefixed-target": "/tmp/" + valid_entry["output"],
            "helper-target": valid_entry["output"].replace(
                "wyrelogd.p/", "wyrelogd-helper.p/").replace(
                "wyrelogd.exe.p/", "wyrelogd-helper.exe.p/"),
            "wrong-object": valid_entry["output"] + ".bak",
            "cross-dialect-target": (
                "wyrelog/wyrelogd.p/daemon_http.c.o"
                if ns.compiler_id in ("clang-cl", "msvc")
                else "wyrelog/wyrelogd.exe.p/daemon_http.c.obj"),
        }
        for label, output in near_misses.items():
            entry = json.loads(json.dumps(valid_entry))
            entry["output"] = output
            expect_compile_db_rejected(ns.guard, fixture_root, ns.compiler_id,
                compiler, obj_build, [entry], label)
        expect_compile_db_rejected(ns.guard, fixture_root, ns.compiler_id,
            compiler, obj_build, [valid_entry, json.loads(json.dumps(valid_entry))],
            "duplicate-target")
        (obj_build / "compile_commands.json").write_text(
            json.dumps([valid_entry]), encoding="utf-8")
        for name, text in fixtures.items():
            target.write_text(text, encoding="utf-8")
            if invoke(ns.guard, fixture_root, ns.compiler_id, compiler, ns.define).returncode == 0:
                raise SystemExit(f"guard accepted negative fixture: {name}")
        target.write_text(source + "\nvoid macro_helper(void) { LOCKED "
            "(NULL, NULL, NULL, NULL, NULL); }\n", encoding="utf-8")
        define_flag = "/DLOCKED=tenant_create_handler" if ns.compiler_id in ("clang-cl", "msvc") else "-DLOCKED=tenant_create_handler"
        if invoke(ns.guard, fixture_root, ns.compiler_id, compiler, ns.define,
                  extra=(define_flag,)).returncode == 0:
            raise SystemExit("guard accepted compile-define handler alias")
        forced = fixture_root / "forced-alias.h"
        forced.write_text("#define LOCKED tenant_create_handler\n", encoding="utf-8")
        forced_flags = (("/FI" + str(forced),) if ns.compiler_id in ("clang-cl", "msvc")
            else ("-std=c17", "-pthread", "-I" + str(fixture_root),
                "-include", str(forced)))
        if invoke(ns.guard, fixture_root, ns.compiler_id, compiler, ns.define,
                  extra=forced_flags).returncode == 0:
            raise SystemExit("guard accepted forced-header handler alias")
        response = fixture_root / "alias.rsp"
        response.write_text("-DLOCKED=tenant_create_handler\n", encoding="utf-8")
        if invoke(ns.guard, fixture_root, ns.compiler_id, compiler, ns.define,
                  extra=("@" + str(response),)).returncode == 0:
            raise SystemExit("guard accepted response-file handler alias")
        target.write_text(source, encoding="utf-8")
        actual_cl = ns.compiler_id in ("clang-cl", "msvc")
        harmless = "/DGUARD_SEMANTIC=1" if actual_cl else "-std=c17 -pthread"
        semantic_response = fixture_root / "semantic.rsp"
        semantic_response.write_text(harmless + "\n", encoding="utf-8")
        if invoke(ns.guard, fixture_root, ns.compiler_id, compiler, ns.define,
                  extra=("@" + str(semantic_response),)).returncode:
            raise SystemExit("guard rejected semantic response file")
        crlf_response = fixture_root / "semantic-crlf.rsp"
        crlf_response.write_bytes((("/DGUARD_CRLF=1" if actual_cl
            else "-std=c17\r\n-pthread") + "\r\n").encode())
        if invoke(ns.guard, fixture_root, ns.compiler_id, compiler, ns.define,
                  extra=("@" + str(crlf_response),)).returncode:
            raise SystemExit("guard rejected CRLF semantic response file")
        crlf_alias = fixture_root / "alias-crlf.rsp"
        crlf_alias.write_bytes(b"-DLOCKED=tenant_create_handler\r\n")
        target.write_text(source + "\nvoid macro_helper(void) { LOCKED "
            "(NULL, NULL, NULL, NULL, NULL); }\n", encoding="utf-8")
        if invoke(ns.guard, fixture_root, ns.compiler_id, compiler, ns.define,
                  extra=("@" + str(crlf_alias),)).returncode == 0:
            raise SystemExit("guard accepted CRLF response-file alias")
        nested_dir = fixture_root / "nested"
        nested_dir.mkdir()
        (nested_dir / "guard-inner.rsp").write_text(harmless + "\n", encoding="utf-8")
        outer = nested_dir / "outer.rsp"
        outer.write_text("@guard-inner.rsp\n", encoding="utf-8")
        cwd_inner = invoke.real_build_root / "guard-inner.rsp"
        cwd_inner.write_text(("/D" if actual_cl else "-D") +
            "LOCKED=tenant_create_handler\n", encoding="utf-8")
        try:
            if invoke(ns.guard, fixture_root, ns.compiler_id, compiler, ns.define,
                      extra=("@" + str(outer),)).returncode == 0:
                raise SystemExit("guard resolved nested response relative to parent")
        finally:
            cwd_inner.unlink(missing_ok=True)
        positives = {
            "whitespace-comment": source.replace(
                "g_auto (WylDaemonPolicyWrite) write = { 0 };",
                "g_auto /* freeze-neutral */ ( WylDaemonPolicyWrite )\n"
                "      write = { 0 };", 1),
            "leading-space-directive": source.replace(
                "if (!wyl_policy_store_tenant_id_is_valid (tenant) ||\n"
                "#ifdef WYL_HAS_FACT_STORE",
                "if (!wyl_policy_store_tenant_id_is_valid (tenant) ||\n"
                "   #ifdef WYL_HAS_FACT_STORE", 1),
        }
        for name, text in positives.items():
            target.write_text(text, encoding="utf-8")
            result = invoke(ns.guard, fixture_root, ns.compiler_id, compiler, ns.define)
            if result.returncode:
                raise SystemExit(f"guard rejected neutral fixture: {name}: {result.stderr.strip()}")
        target.write_text(source, encoding="utf-8")
        baseline = json.loads(manifest.read_text(encoding="utf-8"))
        manifest_cases = {}
        extra = dict(baseline); extra["extra"] = True; manifest_cases["extra"] = json.dumps(extra)
        missing = dict(baseline); del missing["aggregate"]; manifest_cases["missing"] = json.dumps(missing)
        changed = dict(baseline); changed["rationale"] = "changed"; manifest_cases["rationale"] = json.dumps(changed)
        bad_type = dict(baseline); bad_type["aggregate"] = 1; manifest_cases["digest-type"] = json.dumps(bad_type)
        directive_tamper = json.loads(json.dumps(baseline))
        directive_tamper["directives"]["sha256"] = "0" * 64
        manifest_cases["directive-hash"] = json.dumps(directive_tamper)
        manifest_cases["duplicate"] = manifest.read_text(encoding="utf-8").replace(
            '"version":1', '"version":1,"version":1', 1)
        original_manifest = manifest.read_text(encoding="utf-8")
        for name, text in manifest_cases.items():
            manifest.write_text(text, encoding="utf-8")
            if invoke(ns.guard, fixture_root, ns.compiler_id, compiler, ns.define).returncode == 0:
                raise SystemExit(f"guard accepted invalid manifest: {name}")
        manifest.write_text(original_manifest, encoding="utf-8")
        if True:
            fake = fixture_root / "clang-cl"
            assert "MODE='cl'" in fake_clang_script(compiler, True)
            assert "MODE='gnu'" in fake_clang_script(compiler, False)
            fake.write_text(fake_clang_script(compiler, actual_cl), encoding="utf-8")
            fake.chmod(0o755)
            target.write_text(source, encoding="utf-8")
            fake_command = [sys.executable, str(fake)]
            if invoke(ns.guard, fixture_root, "clang-cl", fake_command, ns.define).returncode:
                raise SystemExit("clang-cl preprocessing dialect rejected")
            command_build = synthetic_db(fixture_root, invoke.real_root,
                invoke.real_build_root, "clang-cl", fake_command, ns.define,
                real_compiler_id=ns.compiler_id)
            command_db = json.loads((command_build / "compile_commands.json").read_text(encoding="utf-8"))
            entry = command_db[0]
            args = entry.pop("arguments")
            args[-3:] = ["/c", str(target), "/Fo" +
                "wyrelog/wyrelogd.exe.p/daemon_http.c.obj"]
            entry["output"] = "wyrelog/wyrelogd.exe.p/daemon_http.c.obj"
            entry["command"] = " ".join('"'+x.replace('"','\\"')+'"' for x in args)
            (command_build / "compile_commands.json").write_text(
                json.dumps(command_db), encoding="utf-8")
            if invoke(ns.guard, fixture_root, "clang-cl", fake_command, ns.define,
                      build_root=command_build).returncode:
                raise SystemExit("Windows command-only .obj entry rejected")
            entry["output"] = "wyrelog/wyrelogd.p/daemon_http.c.o"
            expect_compile_db_rejected(ns.guard, fixture_root, "clang-cl",
                fake_command, command_build, [entry],
                "Windows cross-dialect target")
    module = guard_module
    if module.lex("1+2 1e+2 0x1p-2") != [
            ("number", "1"), ("punct", "+"), ("number", "2"),
            ("number", "1e+2"), ("number", "0x1p-2")]:
        raise SystemExit("pp-number adjacency lexer vector failed")
    if module.split_windows(r'cc "C:\Program Files\x.c" "a\\\"b"') != [
            "cc", r"C:\Program Files\x.c", 'a\\"b']:
        raise SystemExit("Windows command-line parser vector failed")
    if not module.is_daemon_http_output(
            r"wyrelog\wyrelogd.exe.p\daemon_http.c.obj", "clang-cl"):
        raise SystemExit("normalized Windows daemon target vector failed")
    if module.is_daemon_http_output(
            r"other\wyrelog\wyrelogd.exe.p\daemon_http.c.obj", "clang-cl"):
        raise SystemExit("prefixed Windows daemon target vector accepted")
    if module.is_daemon_http_output(
            "wyrelog/wyrelogd.p/daemon_http.c.o", "clang-cl"):
        raise SystemExit("Windows classifier accepted POSIX target")
    if module.is_daemon_http_output(
            "wyrelog/wyrelogd.exe.p/daemon_http.c.obj", "gcc"):
        raise SystemExit("POSIX classifier accepted Windows target")
    print("OK: daemon WRITE-authority guard rejects negative fixtures")

if __name__ == "__main__":
    main()
