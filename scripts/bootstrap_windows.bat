@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_first_run.ps1" %*
exit /b %ERRORLEVEL%
