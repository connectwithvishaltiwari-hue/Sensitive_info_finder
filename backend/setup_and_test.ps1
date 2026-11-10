$ErrorActionPreference = "Stop"

# Run this script from any directory; it always targets this project's backend.
$Backend = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Backend

Write-Host "Project backend: $Backend" -ForegroundColor Cyan

# Prevent imports from older project copies (for example v3.1) or Anaconda paths.
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue

# Create this checkout's own virtual environment if it does not exist.
if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "Creating backend virtual environment..." -ForegroundColor Yellow
    py -3 -m venv .venv
}

$Python = Join-Path $Backend ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "Could not find the virtual environment Python at $Python. Install Python 3 and run this script again."
}

Write-Host "Installing backend dependencies..." -ForegroundColor Yellow
& $Python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }
& $Python -m pip install -r (Join-Path $Backend "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }

Write-Host "Verifying required packages and app import..." -ForegroundColor Yellow
& $Python -c "import multipart, docx; import app; print('python-multipart:', multipart.__file__); print('python-docx:', docx.__file__); print('app:', app.__file__)"
if ($LASTEXITCODE -ne 0) { throw "Dependency or application import check failed." }

Write-Host "Running backend tests..." -ForegroundColor Yellow
& $Python -m pytest -v
if ($LASTEXITCODE -ne 0) { throw "Tests failed. Review the traceback above." }

Write-Host "All backend tests passed." -ForegroundColor Green
