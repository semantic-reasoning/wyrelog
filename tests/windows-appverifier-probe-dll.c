/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <windows.h>

__declspec(dllexport) DWORD WINAPI
wyl_appverifier_handle_probe (DWORD mode)
{
  HANDLE event = CreateEventW (NULL, FALSE, FALSE,
          L"Local\\WyrelogAppVerifierHandleProbe");
  DWORD error;

  if (event == NULL)
    return GetLastError ();
  if (mode == 0)
    return ERROR_SUCCESS;
  if (!CloseHandle (event)) {
    error = GetLastError ();
    return error == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : error;
  }
  if (mode == 1)
    return ERROR_SUCCESS;
  if (CloseHandle (event))
    return ERROR_INVALID_HANDLE;
  error = GetLastError ();
  return error == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : error;
}
