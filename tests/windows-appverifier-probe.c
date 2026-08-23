/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <windows.h>
#include <wchar.h>

typedef DWORD (WINAPI *WylAppVerifierHandleProbe) (DWORD mode);

int
wmain (int argc, wchar_t **argv)
{
  HMODULE module;
  WylAppVerifierHandleProbe probe;
  DWORD mode;
  DWORD error;

  if (argc != 3
      || (wcscmp (argv[1], L"clean") != 0
      && wcscmp (argv[1], L"leak") != 0
      && wcscmp (argv[1], L"invalid") != 0))
    return 2;
  mode = wcscmp (argv[1], L"leak") == 0 ? 0
      : (wcscmp (argv[1], L"clean") == 0 ? 1 : 2);
  module = LoadLibraryW (argv[2]);
  if (module == NULL)
    return 3;
  probe = (WylAppVerifierHandleProbe) GetProcAddress (module,
          "wyl_appverifier_handle_probe");
  if (probe == NULL) {
    FreeLibrary (module);
    return 4;
  }
  error = probe (mode);
  if (error != ERROR_SUCCESS) {
    FreeLibrary (module);
    return 5;
  }
  if (!FreeLibrary (module))
    return 6;
  return 0;
}
