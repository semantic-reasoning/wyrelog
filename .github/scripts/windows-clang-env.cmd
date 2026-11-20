@echo off
rem The hosted VS2026 image also carries VC14.44, compatible with Clang 20.
rem Discover the instance rather than inheriting a different MSVC/STL pair.
set "WYRELOG_VS_ROOT="
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.14.44.17.14.x86.x64 -property installationPath`) do set "WYRELOG_VS_ROOT=%%i"
if not defined WYRELOG_VS_ROOT (
  echo Missing Visual Studio with the VC14.44 x64 toolset.
  exit /b 1
)
if not exist "%WYRELOG_VS_ROOT%\VC\Auxiliary\Build\vcvars64.bat" (
  echo Missing vcvars64.bat in the discovered Visual Studio instance.
  exit /b 1
)
call "%WYRELOG_VS_ROOT%\VC\Auxiliary\Build\vcvars64.bat" -vcvars_ver=14.44
if errorlevel 1 exit /b 1
if not "%VCToolsVersion:~0,5%"=="14.44" (
  echo Expected VC14.44, received %VCToolsVersion%.
  exit /b 1
)
exit /b 0
