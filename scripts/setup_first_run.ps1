[CmdletBinding()]
param(
    [switch]$VerifyOnly,
    [switch]$SkipPythonInstall,
    [switch]$SkipGhidraServer,
    [switch]$SkipSmokeTest,
    [switch]$SkipOllamaStartup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$GhidraServerUrl = "http://127.0.0.1:13370"
$OllamaUrl = "http://127.0.0.1:11434/api/tags"
$SetupLogDir = Join-Path $env:TEMP "reveng-first-run"
$GhidraServerLog = Join-Path $SetupLogDir "ghidra-server.log"
$GhidraServerErrorLog = Join-Path $SetupLogDir "ghidra-server.err.log"
$OllamaLog = Join-Path $SetupLogDir "ollama-serve.log"
$OllamaErrorLog = Join-Path $SetupLogDir "ollama-serve.err.log"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-WarnLine {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Find-Python {
    $candidates = @(
        @{ Command = "py"; Arguments = @("-3") },
        @{ Command = "python"; Arguments = @() }
    )

    foreach ($candidate in $candidates) {
        $commandInfo = Get-Command $candidate.Command -ErrorAction SilentlyContinue
        if ($null -eq $commandInfo) {
            continue
        }

        try {
            & $candidate.Command @($candidate.Arguments + @("--version")) *> $null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        } catch {
        }
    }

    throw "Python 3 was not found in PATH. Install Python 3.9+ and retry."
}

function Invoke-Python {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Python,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $Python.Command @($Python.Arguments + $Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed: $($Python.Command) $($Arguments -join ' ')"
    }
}

function Test-HttpJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [int]$TimeoutSeconds = 5
    )

    try {
        return Invoke-RestMethod -Uri $Url -TimeoutSec $TimeoutSeconds
    } catch {
        return $null
    }
}

function Wait-ForEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [int]$Attempts = 20,
        [int]$DelaySeconds = 2
    )

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $response = Test-HttpJson -Url $Url
        if ($null -ne $response) {
            return $response
        }
        Start-Sleep -Seconds $DelaySeconds
    }

    return $null
}

if (-not (Test-Path (Join-Path $RepoRoot "pyproject.toml"))) {
    throw "Run this script from the repository checkout. Expected pyproject.toml under $RepoRoot."
}

New-Item -ItemType Directory -Path $SetupLogDir -Force | Out-Null
$Python = Find-Python
$BundledGhidra = Join-Path $RepoRoot "external\ghidra-dist\ghidra_12.0.4_PUBLIC"
$BundledHeadless = Join-Path $BundledGhidra "support\analyzeHeadless.bat"

Write-Host "REVENG first-run setup" -ForegroundColor Green
Write-Host "Repository: $RepoRoot"

Write-Step "Checking core prerequisites"
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    throw "Java 21+ is required for the bundled Ghidra distribution."
}
$javaVersionLine = cmd /c "java -version 2>&1" | Select-Object -First 1
Write-Ok ($javaVersionLine.ToString())

if (-not (Test-Path $BundledHeadless)) {
    throw "Bundled Ghidra distribution is missing: $BundledHeadless"
}
Write-Ok "Bundled Ghidra detected at $BundledGhidra"

Write-Step "Checking Python environment"
Write-Ok ("Using Python via '{0}'" -f $Python.Command)

if (-not $VerifyOnly -and -not $SkipPythonInstall) {
    Write-Step "Installing Python dependencies"
    Push-Location $RepoRoot
    try {
        Invoke-Python -Python $Python -Arguments @("-m", "pip", "install", "-r", "requirements.txt")
        Invoke-Python -Python $Python -Arguments @("-m", "pip", "install", "-e", ".")
    } finally {
        Pop-Location
    }
    Write-Ok "Python dependencies installed"
} else {
    Write-WarnLine "Skipping Python dependency installation"
}

Write-Step "Validating REVENG package imports"
Push-Location $RepoRoot
try {
    $importCheck = "import sys; from pathlib import Path; sys.path.insert(0, str(Path(r'$RepoRoot\src'))); from reveng.analysis.analyzer import REVENGAnalyzer; from reveng.integrations.ghidra.ghidra_engine import GhidraEngine; print('reveng-imports-ok')"
    Invoke-Python -Python $Python -Arguments @("-c", $importCheck)
} finally {
    Pop-Location
}
Write-Ok "REVENG imports are available"

if (-not $SkipOllamaStartup) {
    Write-Step "Checking Ollama"
    $ollamaCommand = Get-Command ollama -ErrorAction SilentlyContinue
    if ($null -eq $ollamaCommand) {
        Write-WarnLine "Ollama executable not found. Local LLM features will remain optional."
    } else {
        $ollamaStatus = Test-HttpJson -Url $OllamaUrl
        if ($null -eq $ollamaStatus) {
            Start-Process -FilePath $ollamaCommand.Source -ArgumentList "serve" -RedirectStandardOutput $OllamaLog -RedirectStandardError $OllamaErrorLog -WindowStyle Hidden | Out-Null
            $ollamaStatus = Wait-ForEndpoint -Url $OllamaUrl -Attempts 15 -DelaySeconds 2
        }

        if ($null -ne $ollamaStatus) {
            Write-Ok "Ollama service is reachable"
        } else {
            Write-WarnLine "Ollama did not respond. AI-assisted prompts may be unavailable until 'ollama serve' is running."
        }
    }
}

if (-not $SkipGhidraServer) {
    Write-Step "Checking bundled Ghidra server"
    $ghidraHealth = Test-HttpJson -Url "$GhidraServerUrl/health"
    if ($null -eq $ghidraHealth -or $ghidraHealth.status -ne "healthy") {
        Push-Location $RepoRoot
        try {
            Start-Process -FilePath $Python.Command `
                -ArgumentList @($Python.Arguments + @("external\ghidra-server\ghidra_http_server.py")) `
                -WorkingDirectory $RepoRoot `
                -RedirectStandardOutput $GhidraServerLog `
                -RedirectStandardError $GhidraServerErrorLog `
                -WindowStyle Hidden | Out-Null
        } finally {
            Pop-Location
        }
        $ghidraHealth = Wait-ForEndpoint -Url "$GhidraServerUrl/health" -Attempts 20 -DelaySeconds 2
    }

    if ($null -eq $ghidraHealth -or $ghidraHealth.status -ne "healthy") {
        throw "Bundled Ghidra server failed to start. See $GhidraServerLog"
    }
    Write-Ok "Bundled Ghidra server is healthy"
} else {
    Write-WarnLine "Skipping bundled Ghidra server startup"
}

Write-Step "Checking compiler toolchain"
$compilerCommand = Get-Command gcc -ErrorAction SilentlyContinue
if ($null -eq $compilerCommand) {
    $compilerCommand = Get-Command clang -ErrorAction SilentlyContinue
}
if ($null -eq $compilerCommand) {
    $compilerCommand = Get-Command cl -ErrorAction SilentlyContinue
}
if ($null -eq $compilerCommand) {
    Write-WarnLine "No compiler toolchain found. Recompilation will not work until gcc, clang, or MSVC is installed."
} else {
    Write-Ok ("Compiler detected: {0}" -f $compilerCommand.Name)
}

if (-not $SkipSmokeTest) {
    Write-Step "Running first-run smoke test"
    $sampleBinary = Get-ChildItem -Path (Join-Path $RepoRoot "test_samples") -Filter *.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $sampleBinary) {
        Write-WarnLine "No sample .exe found under test_samples; skipping smoke test."
    } else {
        $smokeOutput = Join-Path $SetupLogDir "sample_decompiled.c"
        Push-Location $RepoRoot
        try {
            & $Python.Command @($Python.Arguments + @("reveng.py", "decompile", $sampleBinary.FullName, "--timeout", "120", "--output", $smokeOutput))
            if ($LASTEXITCODE -ne 0) {
                throw "REVENG decompile smoke test failed for $($sampleBinary.FullName)"
            }
        } finally {
            Pop-Location
        }

        if (-not (Test-Path $smokeOutput)) {
            throw "REVENG smoke test did not produce $smokeOutput"
        }
        Write-Ok "Smoke test passed: $smokeOutput"
    }
} else {
    Write-WarnLine "Skipping smoke test"
}

Write-Step "Setup summary"
Write-Ok "REVENG first-run setup completed"
Write-Host "Next commands:"
Write-Host "  python reveng.py --no-ollama-check analyze <binary>"
Write-Host "  python reveng.py decompile <binary>"
Write-Host "  python reveng.py recompile <binary> --no-gemini"
