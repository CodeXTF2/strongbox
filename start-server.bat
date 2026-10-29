@echo off
rem Strongbox server quick start (local testing).
rem
rem   start-server.bat                 open registration on http://127.0.0.1:8080
rem   start-server.bat --debug         same, with debug logging (request paths, raw errors)
rem
rem Any extra arguments are passed to strongbox-server (see: start-server.bat --help).
rem Settings below are only defaults: set the environment variable first to override.
rem For a real deployment use deploy\ (TLS proxy, invite-only registration) instead.

setlocal
cd /d "%~dp0"

where cargo >nul 2>nul
if errorlevel 1 (
    echo Rust is not installed. Get it from https://rustup.rs and run this again.
    exit /b 1
)

if not defined STRONGBOX_LISTEN       set "STRONGBOX_LISTEN=127.0.0.1:8080"
if not defined STRONGBOX_DATA_DIR     set "STRONGBOX_DATA_DIR=%~dp0strongbox-data"
rem Anyone who can reach the server may create accounts. Fine on 127.0.0.1 only.
if not defined STRONGBOX_REGISTRATION set "STRONGBOX_REGISTRATION=open"
rem Deniable vault layout: drives per account and size per drive. Fixed for a data directory
rem on its first start (the server remembers it), so it is only asked for once. Every account's
rem vault is allocated in full when created: drives x size of disk.
set "layout=remembered from the first start"
if exist "%STRONGBOX_DATA_DIR%\strongbox.sqlite3" goto layout_done
if not defined STRONGBOX_DRIVES_PER_VAULT (
    echo First start: choose the deniable vault layout ^(it cannot be changed later^).
    set "STRONGBOX_DRIVES_PER_VAULT=100"
    set /p "STRONGBOX_DRIVES_PER_VAULT=  Drives per account [100]: "
)
if not defined STRONGBOX_DRIVE_SIZE (
    set "STRONGBOX_DRIVE_SIZE=16MiB"
    set /p "STRONGBOX_DRIVE_SIZE=  Size per drive, e.g. 16MiB or 1GiB [16MiB]: "
)
set "layout=%STRONGBOX_DRIVES_PER_VAULT% drives x %STRONGBOX_DRIVE_SIZE% (allocated per account)"
:layout_done

echo Strongbox server
echo   address:      http://%STRONGBOX_LISTEN%
echo   data:         %STRONGBOX_DATA_DIR%
echo   registration: %STRONGBOX_REGISTRATION%
echo   vault layout: %layout%
echo The first run compiles the server, which takes a few minutes. Ctrl+C stops it.
echo.

cargo run -p strongbox-server -- %*
set "code=%errorlevel%"
if not "%code%"=="0" pause
exit /b %code%
