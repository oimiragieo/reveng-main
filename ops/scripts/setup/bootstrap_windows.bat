@echo off
REM REVENG Windows Bootstrap Script
REM ================================
REM
REM Automatically installs required toolchain components on Windows
REM
REM Requirements:
REM   - Python 3.8+ already installed
REM   - Chocolatey (will prompt to install if missing)
REM
REM Usage:
REM   scripts\bootstrap_windows.bat
REM   scripts\bootstrap_windows.bat --no-compiler   (skip compiler install)

echo.
echo ========================================
echo REVENG Windows Bootstrap
echo ========================================
echo.
echo This script will install:
echo   - Python packages
echo   - Compilers (optional)
echo   - Ollama AI (optional)
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found!
    echo Please install Python 3.8+ from https://python.org
    exit /b 1
)

echo [OK] Python found
python --version
echo.

REM Check for Chocolatey
where choco >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Chocolatey not found
    echo.
    echo Chocolatey is recommended for installing compilers on Windows.
    echo.
    choice /M "Install Chocolatey now?"
    if errorlevel 2 (
        echo Skipping Chocolatey install...
    ) else (
        echo Installing Chocolatey...
        powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"

        REM Refresh environment
        refreshenv
    )
)

REM Install Python packages
echo.
echo ========================================
echo Installing Python Packages
echo ========================================
echo.

python -m pip install --upgrade pip

echo Installing LIEF...
pip install lief

echo Installing Keystone...
pip install keystone-engine

echo Installing Capstone...
pip install capstone

echo.
echo [OK] Python packages installed
echo.

REM Install compiler (unless --no-compiler flag)
if "%1"=="--no-compiler" (
    echo Skipping compiler installation
    goto :skip_compiler
)

where choco >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Cannot install compiler without Chocolatey
    echo.
    echo Manual installation options:
    echo   1. Visual Studio Build Tools: https://visualstudio.microsoft.com/downloads/
    echo   2. MinGW-w64: https://www.mingw-w64.org/
    echo   3. LLVM/Clang: https://releases.llvm.org/
    echo.
    goto :skip_compiler
)

echo.
echo ========================================
echo Installing C Compiler
echo ========================================
echo.
echo Which compiler would you like to install?
echo   1. MinGW (GCC for Windows) - Recommended
echo   2. LLVM/Clang
echo   3. Skip (already installed)
echo.
choice /C 123 /M "Select option"

if errorlevel 3 goto :skip_compiler
if errorlevel 2 (
    echo Installing LLVM/Clang...
    choco install llvm -y
    goto :compiler_done
)
if errorlevel 1 (
    echo Installing MinGW...
    choco install mingw -y
    goto :compiler_done
)

:compiler_done
echo.
echo [OK] Compiler installed
refreshenv

:skip_compiler

REM Offer to install Ollama
echo.
echo ========================================
echo AI Support (Optional)
echo ========================================
echo.
echo Ollama provides local AI analysis with open-source models.
echo Visit: https://ollama.ai
echo.
choice /M "Install Ollama AI support?"

if not errorlevel 2 (
    echo.
    echo Downloading Ollama installer...
    echo Please visit https://ollama.ai and download the Windows installer
    echo.
    echo After installing Ollama:
    echo   1. Open a new terminal
    echo   2. Run: ollama pull phi
    echo   3. Run: ollama pull codellama
    echo   4. Start analysis: python reveng_analyzer.py binary.exe
    echo.
    pause
)

REM Run toolchain check
echo.
echo ========================================
echo Verifying Installation
echo ========================================
echo.

python tools\check_toolchain.py

if errorlevel 1 (
    echo.
    echo [WARNING] Some components are still missing
    echo Run: python tools\check_toolchain.py --fix
    echo.
) else (
    echo.
    echo ========================================
    echo [SUCCESS] Bootstrap Complete!
    echo ========================================
    echo.
    echo You can now run:
    echo   python reveng_analyzer.py binary.exe
    echo.
)

pause
