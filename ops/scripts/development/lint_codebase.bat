@echo off
REM REVENG Code Quality Check - Windows Wrapper
REM ===========================================

echo.
echo REVENG Enterprise Code Quality Verification
echo ============================================
echo.

python scripts\lint_codebase.py %*

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Code quality checks passed!
    exit /b 0
) else (
    echo.
    echo [FAILURE] Code quality issues found.
    echo Run with --fix to auto-fix some issues.
    exit /b 1
)
