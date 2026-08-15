@echo off
setlocal EnableExtensions

set "ROOT=%~dp0"
set "APP=%ROOT%maya_lens_server.py"
set "SRC=%ROOT%src"

if not exist "%APP%" (
  echo MAYA Sentinel launcher error:
  echo Expected server entry was not found:
  echo   %APP%
  exit /b 2
)

set "PYTHONPATH=%SRC%;%ROOT%;%PYTHONPATH%"
set "PY_CMD="

call :try_python "py -3.13"
if defined PY_CMD goto :run
call :try_python "py -3.12"
if defined PY_CMD goto :run
call :try_python "py -3.11"
if defined PY_CMD goto :run
call :try_python "python"
if defined PY_CMD goto :run

echo MAYA Sentinel launcher error:
echo No supported Python runtime was found.
echo Install Python 3.11, 3.12, or 3.13, then run this launcher again.
exit /b 2

:run
echo Starting MAYA Sentinel with %PY_CMD%
%PY_CMD% "%APP%"
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
  echo.
  echo MAYA Sentinel stopped with exit code %EXIT_CODE%.
)
exit /b %EXIT_CODE%

:try_python
set "CANDIDATE=%~1"
%CANDIDATE% -c "import importlib, sys; sys.exit(0 if (3, 11) <= sys.version_info[:2] <= (3, 13) and all(importlib.import_module(name) for name in ('maya_lens.scanner','maya_lens.report','maya_lens.public_safety','maya_lens.retention','maya_lens_server')) else 1)" >nul 2>nul
if "%ERRORLEVEL%"=="0" set "PY_CMD=%CANDIDATE%"
exit /b 0
