@echo off
rem Strongbox desktop client quick start.
rem
rem   start-client.bat          desktop app with your security key (Windows 11 22H2 or later)
rem   start-client.bat --soft   desktop app with the INSECURE software key, for trying the UI
rem                             without a security key (development only)
rem
rem Start the server first (start-server.bat), then use http://127.0.0.1:8080 as the server
rem address in the app. For the command-line client instead, see README.md (sbox).

setlocal
cd /d "%~dp0"

where cargo >nul 2>nul
if errorlevel 1 (
    echo Rust is not installed. Get it from https://rustup.rs and run this again.
    exit /b 1
)

echo The first run compiles the app, which takes a few minutes.
echo.

if /i "%~1"=="--soft" (
    echo WARNING: software security key. Its secrets sit in a plain file; do not store real data.
    if not defined STRONGBOX_SOFT_AUTHENTICATOR set "STRONGBOX_SOFT_AUTHENTICATOR=%~dp0softkey-dev.json"
    cargo run -p strongbox-desktop --features dev-soft-authenticator
) else (
    cargo run -p strongbox-desktop
)
set "code=%errorlevel%"
if not "%code%"=="0" pause
exit /b %code%
