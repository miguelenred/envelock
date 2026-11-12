@echo off
rem Run the encoder with a separately supplied portable Python in prebuilt\python.
rem Usage: envelock ^<command^> [options]      e.g.  envelock new-project
rem -E -s: ignore PYTHON* variables and the user's site-packages, so only the bundled libraries run.
setlocal
rem The launcher's own folder, read inside a called label: at the top level %~dp0 expands to the
rem CURRENT folder when the launcher is found through PATH under a quoted name (call "envelock"),
rem which would run a prebuilt\python\windows-x64\python.exe planted there.
call :root
if not exist "%ROOT%prebuilt\python\windows-x64\python.exe" (
  echo No portable Python at prebuilt\python\windows-x64. Use Python 3.10+ with the>&2
  echo encoder's requirements instead: see docs\MANUAL.md, section 4.>&2
  exit /b 2
)
"%ROOT%prebuilt\python\windows-x64\python.exe" -E -s "%ROOT%encoder\envelock.py" %*
exit /b %ERRORLEVEL%

:root
set "ROOT=%~dp0"
exit /b 0
