# SPDX-License-Identifier: GPL-3.0-or-later
"""Native security/console setup for disposable executable acceptance tests."""
import atexit
import csv
import ctypes
from ctypes import wintypes
from contextlib import contextmanager
from functools import lru_cache
import subprocess

kernel = ctypes.WinDLL('kernel32', use_last_error=True)
security = ctypes.WinDLL('advapi32', use_last_error=True)
pointer = ctypes.c_void_p


def signature(name, arguments, result=wintypes.BOOL):
    function = getattr(security, name)
    function.argtypes = arguments
    function.restype = result
    return function


signature('ConvertStringSecurityDescriptorToSecurityDescriptorW',
    [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(pointer), pointer])
signature('SetNamedSecurityInfoW', [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
    pointer, pointer, pointer, pointer], wintypes.DWORD)
signature('GetNamedSecurityInfoW', [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
    ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.POINTER(pointer),
    ctypes.POINTER(pointer), ctypes.POINTER(pointer)], wintypes.DWORD)
signature('GetSecurityDescriptorOwner',
    [pointer, ctypes.POINTER(pointer), ctypes.POINTER(wintypes.BOOL)])
signature('GetSecurityDescriptorControl',
    [pointer, ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(wintypes.DWORD)])
signature('GetSecurityDescriptorDacl', [pointer, ctypes.POINTER(wintypes.BOOL),
    ctypes.POINTER(pointer), ctypes.POINTER(wintypes.BOOL)])
signature('GetAclInformation', [pointer, pointer, wintypes.DWORD, ctypes.c_int])
signature('GetAce', [pointer, wintypes.DWORD, ctypes.POINTER(pointer)])
signature('ConvertStringSidToSidW', [wintypes.LPCWSTR, ctypes.POINTER(pointer)])
signature('EqualSid', [pointer, pointer])
signature('IsValidSid', [pointer])
kernel.LocalFree.argtypes = [pointer]
kernel.LocalFree.restype = pointer
kernel.GetConsoleCP.restype = wintypes.UINT
kernel.AllocConsole.restype = wintypes.BOOL
kernel.FreeConsole.restype = wintypes.BOOL


class AclSize(ctypes.Structure):
    _fields_ = [('count', ctypes.c_uint32), ('used', ctypes.c_uint32),
                ('free', ctypes.c_uint32)]


class AllowedAce(ctypes.Structure):
    _fields_ = [('kind', ctypes.c_ubyte), ('flags', ctypes.c_ubyte),
                ('size', ctypes.c_uint16), ('mask', ctypes.c_uint32),
                ('sid_start', ctypes.c_uint32)]


@lru_cache(maxsize=1)
def user_sid():
    # SID is ASCII even when the account name/code page is localized.
    output = subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh'], timeout=10)
    sid = next(csv.reader(output.decode('utf-8', errors='replace').splitlines()))[-1]
    assert sid.startswith('S-1-'), 'whoami did not return a SID'
    return sid


@contextmanager
def sid_pointer(text):
    result = pointer()
    if not security.ConvertStringSidToSidW(text, ctypes.byref(result)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield result
    finally:
        kernel.LocalFree(result)


def checked(result):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())


def verify(descriptor, *, directory, token):
    # Match graph-windows-security-private.c and wyctl-token-file.c.
    # Control bits such as AUTO_INHERITED do not change these requirements.
    owner = pointer()
    defaulted = wintypes.BOOL()
    checked(security.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner),
        ctypes.byref(defaulted)))
    control = ctypes.c_uint16()
    revision = wintypes.DWORD()
    checked(security.GetSecurityDescriptorControl(descriptor, ctypes.byref(control),
        ctypes.byref(revision)))
    assert control.value & 0x1000, 'fixture DACL is not protected'
    present = wintypes.BOOL()
    dacl = pointer()
    checked(security.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present),
        ctypes.byref(dacl), ctypes.byref(defaulted)))
    assert present.value and dacl.value and not defaulted.value, 'invalid fixture DACL'
    size = AclSize()
    checked(security.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), 2))
    assert size.count == 1, 'fixture DACL has additional or missing ACEs'
    raw = pointer()
    checked(security.GetAce(dacl, 0, ctypes.byref(raw)))
    ace = ctypes.cast(raw, ctypes.POINTER(AllowedAce)).contents
    assert ace.kind == 0 and ace.flags == (3 if directory else 0), 'invalid fixture ACE'
    assert ace.mask == 0x001F01FF and ace.size >= 20, 'invalid fixture access mask/size'
    # The variable SID begins at the DWORD following the mask.
    trustee = pointer(raw.value + AllowedAce.sid_start.offset)
    assert owner.value and trustee.value, 'missing fixture SID'
    assert security.IsValidSid(owner) and security.IsValidSid(trustee), 'invalid fixture SID'
    with sid_pointer(user_sid()) as expected_owner, \
            sid_pointer('S-1-3-4' if token else user_sid()) as expected_trustee:
        assert security.EqualSid(owner, expected_owner), 'fixture owner is not the token user'
        assert security.EqualSid(trustee, expected_trustee), 'unexpected fixture trustee'


def protect(path, *, token=False):
    """Apply and read back protected owner/ACE fields required by production."""
    sid = user_sid()
    directory = path.is_dir()
    flags = 'OICI' if directory else ''
    ace_sid = 'OW' if token else sid
    descriptor = pointer()
    checked(security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f'O:{sid}D:P(A;{flags};FA;;;{ace_sid})', 1, ctypes.byref(descriptor), None))
    try:
        # OWNER | DACL | PROTECTED_DACL. No inherited or additional ACEs.
        owner = pointer()
        dacl = pointer()
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        checked(security.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner),
            ctypes.byref(defaulted)))
        checked(security.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present),
            ctypes.byref(dacl), ctypes.byref(defaulted)))
        error = security.SetNamedSecurityInfoW(str(path), 1, 0x80000005,
            owner, None, dacl, None)
        if error:
            raise ctypes.WinError(error)
    finally:
        kernel.LocalFree(descriptor)
    actual = pointer()
    error = security.GetNamedSecurityInfoW(str(path), 1, 5,
        None, None, None, None, ctypes.byref(actual))
    if error:
        raise ctypes.WinError(error)
    try:
        verify(actual, directory=directory, token=token)
    finally:
        kernel.LocalFree(actual)


def ensure_console():
    """Give the parent and its dedicated child group an actual console."""
    if not kernel.GetConsoleCP():
        checked(kernel.AllocConsole())
        atexit.register(kernel.FreeConsole)
