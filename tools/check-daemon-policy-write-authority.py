#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Freeze reviewed active-C token trees for daemon WRITE authority code."""
import argparse, hashlib, json, re, shlex, subprocess, sys
from pathlib import Path

VERSION = 1
PROFILE = "raw-conditional-declarations-v1"
FUNCTIONS = (
    "wyl_daemon_policy_write_detach_message",
    "wyl_daemon_policy_write_clear",
    "wyl_daemon_policy_write_owner_name",
    "wyl_daemon_policy_write_finalize",
    "wyl_daemon_policy_write_record_primary",
    "wyl_daemon_policy_write_observe_cleanup_resource",
    "wyl_daemon_policy_write_finish",
    "wyl_daemon_policy_write_finish_result",
    "wyl_daemon_policy_write_acquire",
    "policy_write_acquire_fault_hit_count",
    "policy_write_record_non_http_finalize_snapshot",
    "policy_write_record_finalize_snapshot",
    "wyl_daemon_http_fail_next_policy_write_finalize_for_test",
    "wyl_daemon_http_fail_next_policy_write_acquire_for_test",
    "wyl_daemon_policy_write_finalize_for_response",
    "wyl_daemon_policy_write_prepare_success_response",
    "set_json_error", "set_json_ok",
    "set_tenant_mutation_json", "set_graph_mutation_json",
    "set_schema_ok_json", "set_fact_op_json",
    "mutate_tenant_lifecycle_publication",
    "tenant_recovery_install", "tenant_recovery_finish_claim",
    "tenant_recovery_repair_with_write",
    "tenant_recovery_attempt_before_authorization",
    "tenant_seal_recovery_retain", "tenant_seal_recovery_discard",
    "wyl_daemon_http_context_rotate_access_token_key",
    "tenant_mutation_handler",
    "graph_create_handler", "graph_seal_handler", "schema_register_handler",
    "facts_route_handler", "direct_permission_mutation_handler",
    "policy_permission_transition_handler", "role_membership_mutation_handler",
    "mfa_enroll_confirm_handler", "wyl_daemon_http_policy_write_for_test",
    "ensure_policy_permission_exists", "ensure_policy_role_exists",
    "mfa_enroll_subject_exists", "lookup_fact_graph",
    "tenant_create_handler", "tenant_seal_handler", "tenant_unseal_handler",
    "tenant_delete_handler",
    "policy_permission_grant_handler", "policy_permission_revoke_handler",
    "policy_role_grant_handler", "policy_role_revoke_handler",
    "service_credential_operation_reconcile_execute",
    "service_credential_operation_recover_execute",
    "service_management_authority_arm_handler",
    "wyl_daemon_http_configure_tenant_for_test",
)
OWNER_INVENTORY = {
    "wyl_daemon_http_context_rotate_access_token_key":
        ("WYL_DAEMON_POLICY_WRITE_OWNER_KEY_ROTATION",),
    "wyl_daemon_http_configure_tenant_for_test":
        ("WYL_DAEMON_POLICY_WRITE_OWNER_TEST_CONFIGURE",),
    "wyl_daemon_http_policy_write_for_test":
        ("WYL_DAEMON_POLICY_WRITE_OWNER_TEST_POLICY_WRITE",),
    "tenant_mutation_handler": ("WYL_DAEMON_POLICY_WRITE_OWNER_TENANT",),
    "tenant_recovery_attempt_before_authorization":
        ("WYL_DAEMON_POLICY_WRITE_OWNER_TENANT",),
    "graph_create_handler": ("WYL_DAEMON_POLICY_WRITE_OWNER_GRAPH_CREATE",),
    "graph_seal_handler": ("WYL_DAEMON_POLICY_WRITE_OWNER_GRAPH_SEAL",),
    "schema_register_handler":
        ("WYL_DAEMON_POLICY_WRITE_OWNER_SCHEMA_REGISTER",),
    "facts_route_handler": (
        "WYL_DAEMON_POLICY_WRITE_OWNER_FACT_FORGET",
        "WYL_DAEMON_POLICY_WRITE_OWNER_FACT_PUBLICATION"),
    "direct_permission_mutation_handler":
        ("WYL_DAEMON_POLICY_WRITE_OWNER_DIRECT_PERMISSION",),
    "policy_permission_transition_handler":
        ("WYL_DAEMON_POLICY_WRITE_OWNER_PERMISSION_TRANSITION",),
    "role_membership_mutation_handler":
        ("WYL_DAEMON_POLICY_WRITE_OWNER_ROLE_MEMBERSHIP",),
    "service_credential_operation_reconcile_execute":
        ("WYL_DAEMON_POLICY_WRITE_OWNER_OPERATION_RECONCILE",),
    "service_credential_operation_recover_execute":
        ("WYL_DAEMON_POLICY_WRITE_OWNER_OPERATION_RECOVER",),
    "mfa_enroll_confirm_handler":
        ("WYL_DAEMON_POLICY_WRITE_OWNER_MFA_CONFIRM",),
    "service_management_authority_arm_handler":
        ("WYL_DAEMON_POLICY_WRITE_OWNER_SELF_ARM",),
}
TEST_ONLY_OWNER_FUNCTIONS = {
    "wyl_daemon_http_configure_tenant_for_test",
    "wyl_daemon_http_policy_write_for_test",
}
FACT_STORE_OWNER_FUNCTIONS = {
    "graph_create_handler", "schema_register_handler", "facts_route_handler",
    "service_credential_operation_reconcile_execute",
    "service_credential_operation_recover_execute",
}
FACT_STORE_DISABLED_STUBS = {
    "graph_create_handler", "schema_register_handler", "facts_route_handler",
}
FACT_STORE_FEATURE_MARKER = """#ifdef WYL_HAS_FACT_STORE
enum
{
  WYL_DAEMON_POLICY_WRITE_ACTIVE_FACT_STORE = 1,
};
#else
enum
{
  WYL_DAEMON_POLICY_WRITE_ACTIVE_FACT_STORE = 0,
};
#endif"""
OWNER_TABLE = (
    ("KEY_ROTATION", "key_rotation"),
    ("TEST_CONFIGURE", "test_configure"),
    ("TEST_POLICY_WRITE", "test_policy_write"),
    ("TENANT", "tenant"),
    ("GRAPH_CREATE", "graph_create"),
    ("GRAPH_SEAL", "graph_seal"),
    ("SCHEMA_REGISTER", "schema_register"),
    ("FACT_FORGET", "fact_forget"),
    ("FACT_PUBLICATION", "fact_publication"),
    ("DIRECT_PERMISSION", "direct_permission"),
    ("PERMISSION_TRANSITION", "permission_transition"),
    ("ROLE_MEMBERSHIP", "role_membership"),
    ("OPERATION_RECONCILE", "operation_reconcile"),
    ("OPERATION_RECOVER", "operation_recover"),
    ("MFA_CONFIRM", "mfa_confirm"),
    ("SELF_ARM", "self_arm"),
)
ALLOW_ACQUIRE = {
    "wyl_daemon_policy_write_acquire",
    "wyl_daemon_http_context_rotate_access_token_key",
    "tenant_mutation_handler", "tenant_recovery_attempt_before_authorization",
    "graph_create_handler", "graph_seal_handler",
    "schema_register_handler", "facts_route_handler",
    "direct_permission_mutation_handler", "policy_permission_transition_handler",
    "role_membership_mutation_handler", "mfa_enroll_confirm_handler",
    "wyl_daemon_http_policy_write_for_test",
    "wyl_daemon_http_configure_tenant_for_test",
    "service_credential_operation_reconcile_execute",
    "service_credential_operation_recover_execute",
    "service_management_authority_arm_handler",
}
ALLOW_MUTATORS = ALLOW_ACQUIRE | {
    "mutate_tenant_lifecycle_publication", "tenant_recovery_repair_with_write",
}
PROTECTED_HANDLERS = {
    "tenant_mutation_handler", "graph_create_handler", "graph_seal_handler",
    "schema_register_handler", "facts_route_handler",
    "direct_permission_mutation_handler", "policy_permission_transition_handler",
    "role_membership_mutation_handler", "mfa_enroll_confirm_handler",
    "service_management_authority_arm_handler",
    "wyl_daemon_http_policy_write_for_test", "tenant_create_handler",
    "tenant_seal_handler", "tenant_unseal_handler", "tenant_delete_handler",
    "policy_permission_grant_handler", "policy_permission_revoke_handler",
    "policy_role_grant_handler", "policy_role_revoke_handler",
    "wyl_daemon_http_configure_tenant_for_test",
}
MUTATORS = {
    "wyl_policy_store_create_tenant", "wyl_policy_store_set_tenant_sealed",
    "wyl_policy_store_create_fact_graph", "wyl_policy_store_seal_fact_graph",
    "wyl_policy_store_register_fact_relation_schema", "wyl_fact_store_forget",
    "wyl_fact_store_append_batch", "wyl_fact_store_retract_batch",
    "wyl_perm_grant", "wyl_perm_revoke", "wyl_role_grant", "wyl_role_revoke",
    "wyl_handle_apply_permission_state_transition", "wyl_mfa_enrollment_commit",
    "wyl_engine_session_run_committed_publication",
    "wyl_engine_session_repair_committed_publication",
}
DAEMON_HTTP_OUTPUT = {
    "posix": "wyrelog/wyrelogd.p/daemon_http.c.o",
    "windows": "wyrelog/wyrelogd.exe.p/daemon_http.c.obj",
}
PUNCT = sorted(("<<=", ">>=", "...", "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "##"), key=len, reverse=True)

class GuardError(Exception): pass

def is_daemon_http_output(output, compiler_id):
    dialect="windows" if compiler_id in ("clang-cl","msvc") else "posix"
    return (isinstance(output,str) and
        output.replace("\\","/")==DAEMON_HTTP_OUTPUT[dialect])

def split_windows(command, whitespace=" \t"):
    args=[]; i=0; n=len(command)
    while True:
        while i<n and command[i] in whitespace: i+=1
        if i>=n: break
        out=[]; quoted=False
        while i<n and (quoted or command[i] not in whitespace):
            if command[i]=="\\":
                start=i
                while i<n and command[i]=="\\": i+=1
                count=i-start
                if i<n and command[i]=='"':
                    out.extend("\\"*(count//2))
                    if count%2: out.append('"'); i+=1
                    else: quoted=not quoted; i+=1
                else: out.extend("\\"*count)
                continue
            if command[i]=='"': quoted=not quoted; i+=1; continue
            out.append(command[i]); i+=1
        if quoted: raise GuardError("unterminated Windows command quote")
        args.append("".join(out))
    return args

def expand_response(argv, directory, windows, stack=(), depth=0):
    if depth>16: raise GuardError("response file nesting too deep")
    result=[]
    for arg in argv:
        if not arg.startswith("@") or arg=="@": result.append(arg); continue
        if windows and depth: raise GuardError("nested Windows response files are unsupported")
        path=Path(arg[1:]); path=path if path.is_absolute() else Path(directory)/path
        path=path.resolve()
        if path in stack: raise GuardError("response file cycle")
        try: text=path.read_text(encoding="utf-8-sig")
        except (OSError,UnicodeError) as e: raise GuardError(f"cannot read response file: {path}: {e}")
        nested=split_windows(text," \t\r\n\v\f") if windows else shlex.split(text,posix=True)
        result.extend(expand_response(nested,directory,windows,stack+(path,),depth+1))
    return result

def compile_entry(root, build_root, compiler_id):
    db=Path(build_root)/"compile_commands.json"
    data=json.loads(db.read_text(encoding="utf-8"))
    source=(Path(root)/"wyrelog/daemon/http.c").resolve()
    matches=[]
    for entry in data:
        directory=Path(entry.get("directory",build_root))
        file=Path(entry.get("file",""))
        resolved=(directory/file).resolve() if not file.is_absolute() else file.resolve()
        if resolved==source and is_daemon_http_output(entry.get("output"),compiler_id):
            matches.append(entry)
    if len(matches)!=1: raise GuardError(f"expected one wyrelogd http.c compile entry, found {len(matches)}")
    entry=matches[0]
    if "arguments" in entry:
        argv=entry["arguments"]
        if not isinstance(argv,list) or not all(isinstance(x,str) for x in argv): raise GuardError("invalid compile arguments")
    elif isinstance(entry.get("command"),str):
        argv=(split_windows(entry["command"]) if compiler_id in ("clang-cl","msvc")
            else shlex.split(entry["command"],posix=True))
    else: raise GuardError("compile entry lacks arguments/command")
    return entry,argv,source

def preprocess(root, build_root, compiler_id):
    entry,argv,source=compile_entry(root,build_root,compiler_id)
    directory=Path(entry.get("directory",build_root))
    cl=compiler_id in ("clang-cl","msvc")
    argv=expand_response(argv,directory,cl)
    kept=[]; i=0; sources=0
    while i<len(argv):
        arg=argv[i]
        resolved=(directory/arg).resolve() if not Path(arg).is_absolute() else Path(arg).resolve()
        if resolved==source:
            sources+=1; i+=1; continue
        low=arg.lower()
        if arg in ("-c","-MD","-MMD","-MP","-MG","-M","-MM") or low in ("/c","/showincludes"):
            i+=1; continue
        operand_flags=("-o","-MF","-MT","-MQ","-MJ")
        cl_operand=("/fo","/sourcedependencies","/scandependencies")
        if arg in operand_flags or low in cl_operand:
            if i+1>=len(argv): raise GuardError(f"compile flag lacks operand: {arg}")
            i+=2; continue
        if any(arg.startswith(x) and arg!=x for x in operand_flags) or any(
                low.startswith(x) and low!=x for x in cl_operand):
            i+=1; continue
        kept.append(arg)
        i+=1
    if sources!=1: raise GuardError(f"compile entry must contain source exactly once, found {sources}")
    if cl: kept += ["/nologo","/E","/TC",str(source)]
    else: kept += ["-E","-x","c",str(source)]
    run=subprocess.run(kept,cwd=entry.get("directory",build_root),text=True,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if run.returncode: raise GuardError("preprocessor failed: "+run.stderr.strip())
    selected=[]; current=None; directory=Path(entry.get("directory",build_root))
    marker=re.compile(r'^\s*#(?:\s*line)?\s+\d+\s+"([^"]+)"')
    saw_source=False
    for line in run.stdout.splitlines(keepends=True):
        match=marker.match(line)
        if match:
            name=match.group(1)
            if name.startswith("<"): current=None
            else:
                marked=Path(name)
                current=(directory/marked).resolve() if not marked.is_absolute() else marked.resolve()
                if current==source: saw_source=True
            continue
        if current==source: selected.append(line)
    if not saw_source: raise GuardError("preprocessor output has no original-source marker")
    return "".join(selected)

def lex(source, preserve_pp=False):
    out=[]; i=0; n=len(source)
    while i<n:
        if preserve_pp and (i==0 or source[i-1]=="\n"):
            mark=i
            while mark<n and source[mark] in " \t\r": mark+=1
            if mark<n and source[mark]=="#":
                end=mark
                while True:
                    nl=source.find("\n",end); nl=n if nl<0 else nl
                    physical=source[end:nl].rstrip("\r")
                    end=nl
                    if not physical.rstrip().endswith("\\") or nl==n: break
                    end=nl+1
                logical=source[mark:end].replace("\\\r\n"," ").replace("\\\n"," ")
                out.append(("directive"," ".join(logical.split())))
                i=end+1 if end<n else end
                continue
        if source[i].isspace(): i+=1; continue
        if source.startswith("//",i):
            j=source.find("\n",i+2); i=n if j<0 else j+1; continue
        if source.startswith("/*",i):
            j=source.find("*/",i+2)
            if j<0: raise GuardError("unterminated comment")
            i=j+2; continue
        start=i
        prefix=""
        for p in ("u8","L","u","U"):
            if source.startswith(p,i) and i+len(p)<n and source[i+len(p)] in "\"'": prefix=p; i+=len(p); break
        if i<n and source[i] in "\"'":
            quote=source[i]; i+=1
            while i<n:
                if source[i]=="\\": i+=2; continue
                if source[i]==quote: i+=1; break
                if source[i]=="\n": raise GuardError("newline in literal")
                i+=1
            else: raise GuardError("unterminated literal")
            out.append(("literal",source[start:i])); continue
        i=start
        if source[i].isalpha() or source[i]=="_":
            i+=1
            while i<n and (source[i].isalnum() or source[i]=="_"): i+=1
            out.append(("identifier",source[start:i])); continue
        if source[i].isdigit() or (source[i]=="." and i+1<n and source[i+1].isdigit()):
            i+=1
            while i<n:
                if source[i].isalnum() or source[i] in "._": i+=1; continue
                if source[i] in "+-" and i>start and source[i-1] in "eEpP": i+=1; continue
                break
            out.append(("number",source[start:i])); continue
        punct=next((p for p in PUNCT if source.startswith(p,i)),None)
        if punct: out.append(("punct",punct)); i+=len(punct); continue
        if source[i] in "()[]{};,:?~!%^&*+-=/<>.|": out.append(("punct",source[i])); i+=1; continue
        if source[i]=="#": raise GuardError("preprocessor residue")
        raise GuardError(f"unrecognized byte at {i}")
    return out

def pairs(tokens):
    stack=[]; mate={}; opens={"(":")","[":"]","{":"}"}; closes=set(opens.values())
    for i,(_,v) in enumerate(tokens):
        if v in opens: stack.append((v,i))
        elif v in closes:
            if not stack or opens[stack[-1][0]]!=v: raise GuardError("malformed delimiter tree")
            _,j=stack.pop(); mate[i]=j; mate[j]=i
    if stack: raise GuardError("unclosed delimiter tree")
    return mate

def definitions(tokens,mate, allow_duplicates=False, full=False):
    result={}; depth=0; i=0; boundary=0
    while i<len(tokens):
        v=tokens[i][1]
        if v=="{": depth+=1
        elif v=="}": depth-=1
        if depth==0 and tokens[i][0]=="identifier" and i+1<len(tokens) and tokens[i+1][1]=="(":
            close=mate[i+1]; brace=close+1
            while brace<len(tokens) and tokens[brace][1] not in ("{",";"): brace+=1
            if brace<len(tokens) and tokens[brace][1]=="{":
                name=v
                begin=boundary if full else i; end=mate[brace]
                item=(begin,end,tokens[begin:end+1])
                if name in result and not allow_duplicates: raise GuardError(f"duplicate function definition: {name}")
                if allow_duplicates: result.setdefault(name,[]).append(item)
                else: result[name]=item
                i=end; boundary=end+1
        if depth==0 and v in (";","}"): boundary=i+1
        i+=1
    return result

def serialize(tokens):
    return b"".join(f"{k}:{len(v.encode())}:".encode()+v.encode()+b"\n" for k,v in tokens)

def owner_table_freeze(source):
    marker="#define WYL_DAEMON_POLICY_WRITE_OWNER_TABLE(X)"
    if source.count(marker) != 1:
        raise GuardError("daemon WRITE owner table declaration mismatch")
    start=source.index(marker)
    end=source.index("\ntypedef enum",start)
    block=source[start:end]
    rows=tuple(re.findall(r"^\s*X\s*\(\s*([A-Z][A-Z0-9_]*)\s*,\s*"
        r"([a-z][a-z0-9_]*)\s*\)\s*\\?\s*$",block,re.MULTILINE))
    if rows != OWNER_TABLE:
        raise GuardError("daemon WRITE owner table order/name mismatch")
    material="".join(symbol+":"+name+"\n" for symbol,name in rows).encode()
    return {"count":len(rows),"sha256":hashlib.sha256(material).hexdigest()}

def validate_feature_marker_source(source):
    if source.count(FACT_STORE_FEATURE_MARKER) != 1:
        raise GuardError("daemon WRITE fact-store feature marker mismatch")

def has_token_sequence(values, expected):
    width=len(expected)
    return any(values[i:i+width]==list(expected)
        for i in range(len(values)-width+1))

def mask_comments_and_literals(source):
    out=list(source)
    i=0
    while i<len(source):
        if source.startswith("//",i):
            start=i
            while True:
                end=source.find("\n",start+2)
                end=len(source) if end<0 else end
                for j in range(start,end): out[j]=" "
                continued=end<len(source) and (source[end-1]=="\\"
                    or (end>=2 and source[end-1]=="\r"
                        and source[end-2]=="\\"))
                if not continued:
                    i=end
                    break
                start=end+1
            continue
        if source.startswith("/*",i):
            end=source.find("*/",i+2)
            if end<0: raise GuardError("unterminated comment")
            for j in range(i,end+2):
                if out[j] not in "\r\n": out[j]=" "
            i=end+2
            continue
        if source[i] in "\"'":
            start=i; quote=source[i]; i+=1
            while i<len(source):
                if source[i]=="\\": i+=2; continue
                if source[i]==quote: i+=1; break
                i+=1
            for j in range(start,i):
                if out[j] not in "\r\n": out[j]=" "
            continue
        i+=1
    return "".join(out)

def validate_owner_fault_matrix(root):
    path=Path(root)/"tests/test-daemon-http-decide.c"
    if not path.is_file():
        raise GuardError(f"missing owner fault matrix: {path}")
    source=path.read_text(encoding="utf-8")
    table_marker=("static const PolicyWriteOwnerFaultCase "
        "policy_write_owner_fault_cases[] = {")
    if source.count(table_marker)!=1:
        raise GuardError("daemon WRITE owner fault table declaration mismatch")
    start=source.index(table_marker)+len(table_marker)
    end=source.index("\n};",start)
    block=source[start:end]
    rows=tuple((int(owner),name) for owner,name in re.findall(
        r"^\s*\{\s*(\d+)\s*,\s*\"([a-z][a-z0-9_]*)\"\s*,",
        block,re.MULTILINE))
    expected=tuple((index,name) for index,(_,name) in enumerate(OWNER_TABLE))
    if rows!=expected:
        raise GuardError("daemon WRITE owner fault table order/name mismatch")

    enum_start=source.index("typedef enum\n{\n  POLICY_WRITE_OWNER_FAULT_FINALIZE")
    enum_end=source.index("} PolicyWriteOwnerFaultMode;",enum_start)
    enum_values=[value for _,value in lex(source[enum_start:enum_end])]
    expected_enum=("typedef","enum","{","POLICY_WRITE_OWNER_FAULT_FINALIZE",
        "=","0",",","POLICY_WRITE_OWNER_FAULT_ACQUIRE_AFTER_STORE",",",
        "POLICY_WRITE_OWNER_FAULT_MODE_COUNT",",")
    if tuple(enum_values)!=expected_enum:
        raise GuardError("daemon WRITE owner fault mode inventory mismatch")

    tokens=lex(source,preserve_pp=True)
    defs=definitions(tokens,pairs(tokens),allow_duplicates=True)
    matrix=defs.get("check_policy_write_all_owner_faults",[])
    invoke=defs.get("policy_write_owner_fault_invoke_http",[])
    if len(matrix)!=1 or len(invoke)!=1:
        raise GuardError("daemon WRITE owner fault matrix function mismatch")
    matrix_values=[value for _,value in matrix[0][2]]
    invoke_values=[value for _,value in invoke[0][2]]
    required_sequences=(
        ("G_STATIC_ASSERT","(","G_N_ELEMENTS","(",
            "policy_write_owner_fault_cases",")","==","16",")",";"),
        ("G_STATIC_ASSERT","(","POLICY_WRITE_OWNER_FAULT_MODE_COUNT","==",
            "2",")",";"),
        ("for","(","guint","mode","=","0",";","mode","<",
            "POLICY_WRITE_OWNER_FAULT_MODE_COUNT",";","mode","++",")","{"),
        ("for","(","gsize","i","=","0",";","i","<",
            "G_N_ELEMENTS","(","policy_write_owner_fault_cases",")",";",
            "i","++",")","{"),
        ("policy_write_owner_fault_invoke_http","(","&","env",",",
            "test_case",",","(","PolicyWriteOwnerFaultMode",")","mode",",",
            "&","before",")",";"),
    )
    if any(not has_token_sequence(matrix_values, sequence)
            for sequence in required_sequences):
        raise GuardError("daemon WRITE owner fault 16x2 traversal mismatch")
    for values,label in ((matrix_values,"matrix"),(invoke_values,"HTTP invoke")):
        for api in ("wyl_daemon_http_fail_next_policy_write_finalize_for_test",
                "wyl_daemon_http_fail_next_policy_write_acquire_for_test"):
            calls=sum(1 for i,value in enumerate(values[:-1])
                if value==api and values[i+1]=="(")
            if calls!=1:
                raise GuardError(f"daemon WRITE owner fault {label} {api}={calls}")
    service_marker="#elif defined(WYL_TEST_VARIANT_SERVICE)\nint\nmain (void)\n{"
    service_end_marker="\n#else /* WYL_TEST_VARIANT_AUDIT */"
    if source.count(service_marker)!=1:
        raise GuardError("daemon WRITE service test main mismatch")
    service_start=source.index(service_marker)+len(service_marker)
    service_end=source.index(service_end_marker,service_start)
    service=source[service_start:service_end]
    masked_service=mask_comments_and_literals(service)
    main_items=defs.get("main",[])
    service_mains=[item for item in main_items
        if "check_service_access_token_state_contract" in
        [value for _,value in item[2]]]
    if len(service_mains)!=1:
        raise GuardError("daemon WRITE service main token tree mismatch")
    service_values=[value for _,value in service_mains[0][2]]
    call_count=sum(1 for i,value in enumerate(service_values[:-1])
        if value=="check_policy_write_all_owner_faults"
        and service_values[i+1]=="(")
    all_main_calls=sum(1 for item in main_items
        for i,(_,value) in enumerate(item[2][:-1])
        if value=="check_policy_write_all_owner_faults"
        and item[2][i+1][1]=="(")
    call_sequence=("gint","all_owner_fault_rc","=",
        "check_policy_write_all_owner_faults","(",")",";")
    if call_count!=1 or all_main_calls!=1 \
            or not has_token_sequence(service_values,call_sequence):
        raise GuardError("daemon WRITE owner fault service invocation mismatch")
    call_line=re.search(r"^[ \t]*gint[ \t]+all_owner_fault_rc[ \t]*=[ \t]*"
        r"check_policy_write_all_owner_faults[ \t]*\([ \t]*\)[ \t]*;[ \t]*$",
        masked_service,re.MULTILINE)
    if call_line is None:
        raise GuardError("daemon WRITE owner fault service call shape mismatch")
    call_pos=call_line.start()
    stack=[]
    for line in masked_service[:call_pos].splitlines():
        directive=re.match(r"\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)",
            line)
        if not directive:
            continue
        kind,value=directive.groups()
        if kind in ("if","ifdef","ifndef"):
            stack.append((kind,value.strip(),"initial"))
        elif kind=="endif":
            if not stack:
                raise GuardError("unbalanced conditional before owner fault matrix")
            stack.pop()
        else:
            if not stack:
                raise GuardError("orphan conditional before owner fault matrix")
            parent_kind,parent_value,_=stack[-1]
            stack[-1]=(parent_kind,parent_value,"alternate")
    expected_stack=[("ifdef","WYL_HAS_FACT_STORE","initial"),
        ("ifndef","G_OS_WIN32","initial")]
    if stack!=expected_stack:
        raise GuardError(
            "owner fault matrix is not live in POSIX fact-enabled service main")

def active_fact_store_enabled(tokens):
    marker="WYL_DAEMON_POLICY_WRITE_ACTIVE_FACT_STORE"
    positions=[i for i,(_,value) in enumerate(tokens) if value==marker]
    if len(positions)!=1:
        raise GuardError("active fact-store feature marker cardinality mismatch")
    i=positions[0]
    values=[value for _,value in tokens]
    if i+3>=len(values) or values[i+1]!="=" or values[i+2] not in ("0","1") \
            or values[i+3]!=",":
        raise GuardError("active fact-store feature marker shape mismatch")
    return values[i+2]=="1"

def candidate(defs, raw_tokens, owner_freeze):
    hashes={name:hashlib.sha256(b"".join(serialize(item[2]) for item in defs[name])).hexdigest() for name in FUNCTIONS}
    directives=[token for token in raw_tokens if token[0]=="directive"]
    directive_freeze={"count":len(directives),
        "sha256":hashlib.sha256(serialize(directives)).hexdigest()}
    material="".join(name+hashes[name] for name in FUNCTIONS)
    material+="directives"+str(directive_freeze["count"])+directive_freeze["sha256"]
    material+="owners"+str(owner_freeze["count"])+owner_freeze["sha256"]
    aggregate=hashlib.sha256(material.encode()).hexdigest()
    return {"version":VERSION,"profile":PROFILE,"rationale":"Reviewed full raw conditional declarations for WRITE intervals and their store-consuming helper closure.","functions":hashes,"directives":directive_freeze,"owners":owner_freeze,"aggregate":aggregate}

def validate_test_only_tenant_seam(source, raw_defs, active_defs=None):
    name="wyl_daemon_http_configure_tenant_for_test"
    marker=source.find(name+" (")
    if marker<0: raise GuardError("missing test-only tenant seam")
    stack=[]
    for line in source[:marker].splitlines():
        directive=re.match(r"\s*#\s*(if|ifdef|ifndef|endif)\b(.*)",line)
        if not directive: continue
        kind,value=directive.groups()
        if kind=="endif":
            if not stack: raise GuardError("unbalanced conditional before tenant seam")
            stack.pop()
        else: stack.append((kind,value.strip()))
    if ("ifdef","WYL_TEST_DAEMON_HTTP") not in stack:
        raise GuardError("tenant seam is not structurally WYL_TEST-only")
    items=raw_defs.get(name,[])
    if len(items)!=1: raise GuardError("tenant seam definition cardinality mismatch")
    values=[value for _,value in items[0][2]]
    required=("wyl_daemon_policy_write_acquire",
        "wyl_policy_store_create_tenant","wyl_policy_store_set_tenant_sealed")
    for symbol in required:
        if values.count(symbol)!=1: raise GuardError(f"tenant seam {symbol} cardinality mismatch")
    forbidden=("wyl_handle_get_policy_store","g_mutex_lock","g_mutex_unlock")
    if any(symbol in values for symbol in forbidden):
        raise GuardError("tenant seam bypasses WRITE-owned store authority")
    if active_defs is not None and name in active_defs:
        raise GuardError("test-only tenant seam leaked into production preprocessing")

def global_invariants(tokens,defs):
    values=[v for _,v in tokens]
    if "policy_mutation_lock" in values: raise GuardError("legacy mutex present")
    owner={}
    for name,(lo,hi,_) in defs.items():
        for i in range(lo,hi+1): owner[i]=name
    for i,v in enumerate(values[:-1]):
        if owner.get(i) is not None and v in MUTATORS|{"wyl_daemon_policy_write_acquire","g_mutex_lock","g_mutex_unlock","g_mutex_trylock","g_mutex_lock_full"} and values[i+1] != "(":
            raise GuardError(f"authority symbol alias/reference is forbidden: {v}")
        if v=="wyl_daemon_policy_write_acquire" and values[i+1]=="(":
            if owner.get(i) is not None and owner.get(i) not in ALLOW_ACQUIRE: raise GuardError(f"acquire outside allowlist: {owner.get(i)}")
        if v in MUTATORS and values[i+1]=="(" and owner.get(i) is not None and owner.get(i) not in ALLOW_MUTATORS:
            raise GuardError(f"authority mutator outside allowlist: {v}")
        if v in ("wyl_daemon_policy_write_clear","wyl_service_auth_write_lease_release","wyl_service_auth_write_lease_free") and owner.get(i) in ALLOW_ACQUIRE-set(("wyl_daemon_policy_write_acquire",)):
            raise GuardError(f"manual WRITE cleanup in {owner.get(i)}")
        if owner.get(i) is not None and v in ("g_mutex_lock","g_mutex_unlock","g_mutex_trylock","g_mutex_lock_full") and values[i+1]=="(":
            if v not in ("g_mutex_lock","g_mutex_unlock") or values[i+2:i+6] != ["&","ctx","->","lock"]:
                raise GuardError(f"non-canonical mutex call: {v}")
    for name in ("ensure_policy_permission_exists","ensure_policy_role_exists","mfa_enroll_subject_exists","lookup_fact_graph"):
        if name not in defs: continue
        vals=[v for _,v in defs[name][2]]
        if "wyl_handle_get_policy_store" in vals or any(v.startswith("g_mutex_") for v in vals):
            raise GuardError(f"hidden store/lock acquisition in {name}")

def raw_global_invariants(tokens, defs, check_directives=True):
    values=[v for _,v in tokens]
    mate=pairs(tokens)
    if "policy_mutation_lock" in values: raise GuardError("legacy mutex present in raw source")
    owner={}
    starts=set()
    for name,items in defs.items():
        for lo,hi,_ in items:
            starts.add(next(i for i in range(lo,hi+1)
                if tokens[i][0]=="identifier" and values[i]==name and
                i+1<=hi and values[i+1]=="("))
            for i in range(lo,hi+1): owner[i]=name
    authority=MUTATORS|{"wyl_daemon_policy_write_acquire","g_mutex_lock",
        "g_mutex_unlock","g_mutex_trylock","g_mutex_lock_full"}
    protected=PROTECTED_HANDLERS
    forbidden_directive=authority|protected|{"policy_mutation_lock"}
    for kind,value in tokens:
        if check_directives and kind=="directive" and any(re.search(r"\b"+re.escape(name)+r"\b",value)
                for name in forbidden_directive):
            raise GuardError("authority symbol in preprocessor directive is forbidden")
    for i,v in enumerate(values):
        if not check_directives and owner.get(i) is None: continue
        if v in authority and (i+1>=len(values) or values[i+1]!="("):
            raise GuardError(f"raw authority symbol alias/reference is forbidden: {v}")
        if v=="wyl_daemon_policy_write_acquire" and i+1<len(values) and values[i+1]=="(" and owner.get(i) not in ALLOW_ACQUIRE:
            raise GuardError(f"raw acquire outside allowlist: {owner.get(i)}")
        if v in MUTATORS and i+1<len(values) and values[i+1]=="(" and owner.get(i) not in ALLOW_MUTATORS:
            raise GuardError(f"raw authority mutator outside allowlist: {v}")
        if v in ("g_mutex_lock","g_mutex_unlock","g_mutex_trylock","g_mutex_lock_full") and i+1<len(values) and values[i+1]=="(":
            if v not in ("g_mutex_lock","g_mutex_unlock") or values[i+2:i+6] != ["&","ctx","->","lock"]:
                raise GuardError(f"raw non-canonical mutex call: {v}")
    if not any(v in protected for v in values): return
    wrapper_calls={
        "tenant_mutation_handler": {
            "tenant_create_handler": 'server msg path query user_data "create"',
            "tenant_seal_handler": 'server msg path query user_data "seal"',
            "tenant_unseal_handler": 'server msg path query user_data "unseal"',
            "tenant_delete_handler": 'server msg path query user_data "delete"'},
        "direct_permission_mutation_handler": {
            "policy_permission_grant_handler": "server msg path query user_data TRUE",
            "policy_permission_revoke_handler": "server msg path query user_data FALSE"},
        "role_membership_mutation_handler": {
            "policy_role_grant_handler": "server msg path query user_data TRUE",
            "policy_role_revoke_handler": "server msg path query user_data FALSE"},
    }
    exact="wyl_daemon_http_add_exact_handler"
    prefix="wyl_daemon_http_add_prefix_handler"
    route_registrations={
        "tenant_create_handler": (exact,'"/tenants/create"'),
        "tenant_seal_handler": (exact,'"/tenants/seal"'),
        "tenant_unseal_handler": (exact,'"/tenants/unseal"'),
        "tenant_delete_handler": (exact,'"/tenants/delete"'),
        "graph_create_handler": (exact,'"/graphs/create"'),
        "graph_seal_handler": (exact,'"/graphs/seal"'),
        "schema_register_handler": (exact,'"/facts/schema/register"'),
        "facts_route_handler": (prefix,'"/facts"'),
        "policy_permission_grant_handler": (exact,'"/policy/permissions/grant"'),
        "policy_permission_revoke_handler": (exact,'"/policy/permissions/revoke"'),
        "policy_permission_transition_handler": (exact,'"/policy/permissions/transition"'),
        "policy_role_grant_handler": (exact,'"/policy/roles/grant"'),
        "policy_role_revoke_handler": (exact,'"/policy/roles/revoke"'),
        "mfa_enroll_confirm_handler": (exact,'"/auth/mfa/enroll/confirm"'),
        "service_management_authority_arm_handler":
            (exact,'"/service-management-authority/arm"'),
    }
    edge_counts={(inner,outer):0 for inner,outers in wrapper_calls.items()
        for outer in outers}
    route_counts={name:0 for name in route_registrations}
    for i,v in enumerate(values):
        if v not in protected or i in starts: continue
        own=owner.get(i)
        allowed=wrapper_calls.get(v,{}).get(own)
        if allowed is not None:
            close=pairs(tokens)[i+1]
            args=" ".join(x for x in values[i+2:close] if x!=",")
            if not check_directives:
                if allowed.endswith(" TRUE"): allowed=allowed[:-5]+" ( ! ( 0 ) )"
                elif allowed.endswith(" FALSE"): allowed=allowed[:-6]+" ( 0 )"
            if args==allowed:
                edge_counts[(v,own)]+=1
                continue
        route=route_registrations.get(v)
        if route and own=="wyl_daemon_start_http_server_with_runtime":
            api,path=route
            call=next((j for j in range(i-1,max(-1,i-12),-1)
                if values[j]==api and
                j+1<len(values) and values[j+1]=="("),None)
            if call is not None:
                close=mate[call+1]
                args=[x for x in values[call+2:close] if x!=","]
                expected=["server",path,v,"ctx","NULL"] if check_directives else [
                    "server",path,v,"ctx","(","(","void","*",")","0",")"]
                if args==expected:
                    route_counts[v]+=1
                    continue
        raise GuardError(f"protected handler reference has forbidden owner/shape: {v} in {own}")
    bad_edges=[f"{outer}->{inner}={count}" for (inner,outer),count in edge_counts.items()
        if count!=1]
    if bad_edges: raise GuardError("wrapper edge cardinality mismatch: "+", ".join(bad_edges))
    bad_routes=[f"{name}={count}" for name,count in route_counts.items() if count!=1]
    if bad_routes: raise GuardError("route cardinality mismatch: "+", ".join(bad_routes))

def validate_recover_write_boundary(defs):
    name="service_credential_operation_recover_execute"
    items=defs.get(name,[])
    # The raw source contract above requires this owner.  Active preprocessed
    # source legitimately omits it when fact-store support is disabled.
    if not items: return
    if len(items)!=1: raise GuardError("recover WRITE owner cardinality mismatch")
    values=[value for _,value in items[0][2]]
    calls=(
        "wyl_daemon_policy_write_acquire",
        "management_reauthorize_inside_write",
        "wyl_service_credential_operation_coordinator_lock_acquire",
        "wyl_service_credential_operation_coordinator_recover",
    )
    positions={symbol:[i for i,value in enumerate(values)
        if value==symbol and i+1<len(values) and values[i+1]=="("]
        for symbol in calls}
    bad=[f"{symbol}={len(found)}" for symbol,found in positions.items()
        if len(found)!=1]
    if bad: raise GuardError("recover WRITE call cardinality mismatch: "+", ".join(bad))
    write_store=[i for i in range(len(values)-2)
        if values[i:i+3]==["write",".","store"]]
    if len(write_store)!=2:
        raise GuardError(f"recover pinned WRITE store cardinality mismatch: {len(write_store)}")
    ordered=[positions[calls[0]][0],positions[calls[1]][0],write_store[0],
        positions[calls[2]][0],positions[calls[3]][0],write_store[1]]
    if ordered!=sorted(ordered):
        raise GuardError("recover WRITE acquire/reauthorize/store/lock/recover ordering mismatch")
    forbidden=("wyl_handle_get_policy_store","wyl_daemon_policy_write_clear",
        "wyl_service_auth_write_lease_release","wyl_service_auth_write_lease_free")
    if any(symbol in values for symbol in forbidden):
        raise GuardError("recover WRITE owner bypasses automatic pinned authority")

def validate_owner_inventory(defs):
    if sum(len(owners) for owners in OWNER_INVENTORY.values()) != 17:
        raise GuardError("daemon WRITE owner inventory must contain 17 owners")
    all_owner_tokens={owner for owners in OWNER_INVENTORY.values()
        for owner in owners}
    for name,expected in OWNER_INVENTORY.items():
        items=defs.get(name,[])
        values=[value for _,_,tokens in items for _,value in tokens]
        acquires=sum(1 for i,value in enumerate(values[:-1])
            if value=="wyl_daemon_policy_write_acquire" and values[i+1]=="(")
        if acquires != len(expected):
            raise GuardError(f"daemon WRITE owner acquire mismatch: {name}={acquires}")
        found={owner for owner in all_owner_tokens if owner in values}
        if found != set(expected):
            raise GuardError(f"daemon WRITE owner placement mismatch: {name}")
        for owner in expected:
            if values.count(owner) != 1:
                raise GuardError(f"daemon WRITE owner id mismatch: {name}:{owner}")

def validate_active_owner_inventory(defs, fact_store_enabled):
    expected=set(OWNER_INVENTORY)-TEST_ONLY_OWNER_FUNCTIONS
    if not fact_store_enabled:
        expected-=FACT_STORE_OWNER_FUNCTIONS
    all_owner_tokens={owner for owners in OWNER_INVENTORY.values()
        for owner in owners}
    for name in sorted(expected):
        if name not in defs:
            raise GuardError(f"missing active daemon WRITE owner: {name}")
        values=[value for _,value in defs[name][2]]
        owners=OWNER_INVENTORY[name]
        acquires=sum(1 for i,value in enumerate(values[:-1])
            if value=="wyl_daemon_policy_write_acquire" and values[i+1]=="(")
        if acquires != len(owners):
            raise GuardError(f"active daemon WRITE owner acquire mismatch: {name}={acquires}")
        found={owner for owner in all_owner_tokens if owner in values}
        if found != set(owners):
            raise GuardError(f"active daemon WRITE owner placement mismatch: {name}")
        for owner in owners:
            if values.count(owner)!=1:
                raise GuardError(f"active daemon WRITE owner id mismatch: {name}:{owner}")

    for name in sorted(TEST_ONLY_OWNER_FUNCTIONS):
        if name in defs:
            raise GuardError(f"test-only daemon WRITE owner is active: {name}")

    if fact_store_enabled:
        return
    for name in sorted(FACT_STORE_DISABLED_STUBS):
        if name not in defs:
            raise GuardError(f"missing fact-disabled WRITE owner stub: {name}")
        values=[value for _,value in defs[name][2]]
        if "\"fact_store_disabled\"" not in values:
            raise GuardError(f"fact-disabled WRITE owner stub mismatch: {name}")
        if "wyl_daemon_policy_write_acquire" in values \
                or any(owner in values for owner in all_owner_tokens) \
                or any(mutator in values for mutator in MUTATORS):
            raise GuardError(f"fact-disabled WRITE owner stub retained authority: {name}")
    absent=FACT_STORE_OWNER_FUNCTIONS-FACT_STORE_DISABLED_STUBS
    leaked=sorted(name for name in absent if name in defs)
    if leaked:
        raise GuardError("fact-disabled WRITE owners remain active: "+", ".join(leaked))

def validate_terminal_write_contract(defs):
    required_helpers=(
        "wyl_daemon_policy_write_detach_message",
        "wyl_daemon_policy_write_clear",
        "wyl_daemon_policy_write_finalize",
        "wyl_daemon_policy_write_record_primary",
        "wyl_daemon_policy_write_finish",
        "wyl_daemon_policy_write_finish_result",
        "wyl_daemon_policy_write_finalize_for_response",
        "wyl_daemon_policy_write_prepare_success_response",
        "set_json_error", "set_json_ok",
    )
    for name in required_helpers:
        items=defs.get(name,[])
        if len(items)!=1:
            raise GuardError(f"terminal WRITE helper cardinality mismatch: {name}")
    helper_values={name:[v for _,v in defs[name][0][2]]
        for name in required_helpers}
    if helper_values["wyl_daemon_policy_write_clear"].count(
            "wyl_service_auth_write_lease_release_terminal")!=2:
        raise GuardError("emergency WRITE cleanup terminal-entry mismatch")
    if helper_values["wyl_daemon_policy_write_finalize"].count(
            "wyl_service_auth_write_lease_release_terminal")!=1:
        raise GuardError("checked WRITE finalize terminal-entry mismatch")
    if "g_assert" in helper_values["wyl_daemon_policy_write_clear"]:
        raise GuardError("emergency WRITE cleanup must not assert")
    if helper_values["wyl_daemon_policy_write_finish"].count(
            "wyl_daemon_policy_write_finalize")!=1:
        raise GuardError("WRITE finish must delegate exactly once")
    if helper_values["wyl_daemon_policy_write_finish"].count(
            "wyl_daemon_policy_write_record_primary")!=1:
        raise GuardError("WRITE finish must preserve primary exactly once")
    if helper_values["wyl_daemon_policy_write_finish_result"].count(
            "wyl_daemon_policy_write_finalize")!=1:
        raise GuardError("non-HTTP WRITE result must finalize exactly once")
    if helper_values["wyl_daemon_policy_write_finish_result"].count(
            "wyl_daemon_policy_write_record_primary")!=1:
        raise GuardError("non-HTTP WRITE result must preserve primary exactly once")
    finish_values=helper_values["wyl_daemon_policy_write_finish"]
    returns=[finish_values[i+1] for i,value in enumerate(finish_values[:-1])
        if value=="return"]
    if returns != ["primary_rc"]:
        raise GuardError("HTTP WRITE finish must preserve the primary result")
    if helper_values["wyl_daemon_policy_write_finalize_for_response"].count(
            "wyl_daemon_policy_write_finalize")!=1:
        raise GuardError("response finalizer must delegate exactly once")
    if helper_values["wyl_daemon_policy_write_prepare_success_response"].count(
            "wyl_daemon_policy_write_finalize_for_response")!=1:
        raise GuardError("success response must finalize exactly once")
    if helper_values["set_json_error"].count(
            "wyl_daemon_policy_write_finalize_for_response")!=1:
        raise GuardError("error response must finalize exactly once")
    if helper_values["set_json_ok"].count(
            "wyl_daemon_policy_write_finalize_for_response")!=1:
        raise GuardError("OK response must finalize exactly once")

    raw_release_owners={
        "service_auth_invalidation_execute_locked",
        "service_auth_retire_exact", "service_auth_retire_due",
        "wyl_daemon_http_latch_service_unavailable_for_test",
    }
    for name,items in defs.items():
        for _,_,tokens in items:
            values=[v for _,v in tokens]
            if "wyl_service_auth_write_lease_release" in values or \
                    "wyl_service_auth_write_lease_free" in values:
                raise GuardError(f"ordinary WRITE release remains in {name}")
            if "wyl_service_auth_write_lease_release_terminal" in values \
                    and name not in raw_release_owners | {
                        "wyl_daemon_policy_write_clear",
                        "wyl_daemon_policy_write_finalize"}:
                raise GuardError(f"unreviewed raw terminal WRITE owner: {name}")

def strict_json(path):
    def pairs_hook(items):
        obj={}
        for key,value in items:
            if key in obj: raise GuardError(f"duplicate manifest key: {key}")
            obj[key]=value
        return obj
    return json.loads(path.read_text(encoding="utf-8"),object_pairs_hook=pairs_hook)

def validate_manifest(value):
    if not isinstance(value, dict): raise GuardError("manifest must be an object")
    if set(value)!={"version","profile","rationale","functions","directives","owners","aggregate"}: raise GuardError("manifest keys mismatch")
    if not isinstance(value["functions"], dict): raise GuardError("manifest functions must be an object")
    if set(value["functions"])!=set(FUNCTIONS): raise GuardError("manifest function set mismatch")
    if not isinstance(value["directives"],dict) or set(value["directives"])!={"count","sha256"}: raise GuardError("manifest directive freeze mismatch")
    if not isinstance(value["directives"]["count"],int) or value["directives"]["count"]<0: raise GuardError("invalid directive count")
    if not isinstance(value["directives"]["sha256"],str) or not re.fullmatch(r"[0-9a-f]{64}",value["directives"]["sha256"]): raise GuardError("invalid directive digest")
    if not isinstance(value["owners"],dict) or set(value["owners"])!={"count","sha256"}: raise GuardError("manifest owner freeze mismatch")
    if value["owners"].get("count")!=len(OWNER_TABLE): raise GuardError("invalid owner count")
    if not isinstance(value["owners"].get("sha256"),str) or not re.fullmatch(r"[0-9a-f]{64}",value["owners"]["sha256"]): raise GuardError("invalid owner digest")
    if value["version"]!=VERSION or value["profile"]!=PROFILE or value["rationale"]!="Reviewed full raw conditional declarations for WRITE intervals and their store-consuming helper closure.": raise GuardError("manifest metadata mismatch")
    if not isinstance(value["aggregate"], str) or not re.fullmatch(r"[0-9a-f]{64}",value["aggregate"]): raise GuardError("invalid aggregate digest")
    if any(not isinstance(x, str) or not re.fullmatch(r"[0-9a-f]{64}",x) for x in value["functions"].values()): raise GuardError("invalid function digest")

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("root"); p.add_argument("--build-root"); p.add_argument("--compiler-id"); p.add_argument("--raw-only",action="store_true"); p.add_argument("--manifest"); p.add_argument("--print-candidate",action="store_true"); ns=p.parse_args(argv)
    path=Path(ns.root)/"wyrelog/daemon/http.c"; manifest=Path(ns.manifest) if ns.manifest else Path(ns.root)/"tools/daemon-policy-write-authority.json"
    if not path.is_file(): raise GuardError(f"missing source: {path}")
    source=path.read_text(encoding="utf-8")
    validate_owner_fault_matrix(ns.root)
    validate_feature_marker_source(source)
    owner_freeze=owner_table_freeze(source)
    raw_tokens=lex(source,preserve_pp=True); raw_mate=pairs(raw_tokens); raw_defs=definitions(raw_tokens,raw_mate,allow_duplicates=True,full=True)
    missing=[x for x in FUNCTIONS if x not in raw_defs]
    if missing: raise GuardError("missing function definitions: "+", ".join(missing))
    if not ALLOW_ACQUIRE.issubset(FUNCTIONS):
        raise GuardError("acquire allowlist must be contained by the frozen function set")
    validate_test_only_tenant_seam(source,raw_defs)
    validate_recover_write_boundary(raw_defs)
    validate_owner_inventory(raw_defs)
    validate_terminal_write_contract(raw_defs)
    raw_global_invariants(raw_tokens,raw_defs)
    if not ns.raw_only:
        if not ns.build_root or not ns.compiler_id: raise GuardError("active check requires build-root and compiler-id")
        tokens=lex(preprocess(ns.root,ns.build_root,ns.compiler_id),preserve_pp=True); mate=pairs(tokens)
        grouped=definitions(tokens,mate,allow_duplicates=True)
        required_active=set(FUNCTIONS)|{"wyl_daemon_start_http_server_with_runtime"}
        ambiguous=[name for name in required_active if name in grouped and len(grouped[name])!=1]
        if ambiguous: raise GuardError("ambiguous active function definitions: "+", ".join(sorted(ambiguous)))
        defs={name:items[0] for name,items in grouped.items()
            if name in raw_defs and len(items)==1}
        fact_store_enabled=active_fact_store_enabled(tokens)
        validate_test_only_tenant_seam(source,raw_defs,defs)
        validate_recover_write_boundary({name:[item] for name,item in defs.items()})
        validate_active_owner_inventory(defs,fact_store_enabled)
        global_invariants(tokens,defs)
        raw_global_invariants(tokens,{name:[item] for name,item in defs.items()},False)
    actual=candidate(raw_defs,raw_tokens,owner_freeze)
    if ns.print_candidate: print(json.dumps(actual,indent=2,sort_keys=True)); return
    expected=strict_json(manifest); validate_manifest(expected)
    for name in FUNCTIONS:
        if expected.get("functions",{}).get(name)!=actual["functions"][name]:
            raise GuardError(f"token freeze mismatch {name}: {expected.get('functions',{}).get(name)} -> {actual['functions'][name]}")
    if expected.get("aggregate")!=actual["aggregate"] or expected.get("version")!=VERSION or expected.get("profile")!=PROFILE: raise GuardError("aggregate/profile freeze mismatch")
    if expected != actual: raise GuardError("manifest does not exactly match generated candidate")
    print("OK: daemon WRITE authority token freeze matches")

if __name__=="__main__":
    try: main()
    except (GuardError,OSError,ValueError,json.JSONDecodeError) as e: print(f"error: {e}",file=sys.stderr); sys.exit(1)
