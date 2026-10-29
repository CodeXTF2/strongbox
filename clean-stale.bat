@echo off
rem Remove build artifacts older than N days (default 7) without a full rebuild.
rem Needs: cargo install cargo-sweep
where cargo-sweep >nul 2>nul || (echo cargo-sweep not found. Install it with: cargo install cargo-sweep & exit /b 1)
set DAYS=%1
if "%DAYS%"=="" set DAYS=7
cd /d "%~dp0"
cargo sweep --time %DAYS%
