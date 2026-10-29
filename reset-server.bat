@echo off
setlocal
cd /d "%~dp0"

if not defined STRONGBOX_DATA_DIR set "STRONGBOX_DATA_DIR=%~dp0strongbox-data"

for %%I in ("%STRONGBOX_DATA_DIR%") do set "RESET_TARGET=%%~fI"
for %%I in ("%~dp0.") do set "SCRIPT_DIR=%%~fI"

echo.
echo ================================================================
echo WARNING: THIS PERMANENTLY DELETES THE STRONGBOX SERVER DATA
echo ================================================================
echo.
echo This removes every account and vault, all files, the database,
echo vault files, and the remembered vault layout in this data directory:
echo.
echo   "%RESET_TARGET%"
echo.
echo Stop the server before continuing. This cannot be undone.
echo.

if /i "%RESET_TARGET%"=="%RESET_TARGET:~0,3%" (
    echo ERROR: Refusing to reset a drive root.
    exit /b 1
)
if /i "%RESET_TARGET%"=="%SCRIPT_DIR%" (
    echo ERROR: Refusing to reset the application folder.
    exit /b 1
)
if not exist "%RESET_TARGET%\strongbox.sqlite3" (
    echo No Strongbox database was found in that directory; nothing was deleted.
    exit /b 1
)

set "CONFIRM="
set /p "CONFIRM=Type DELETE to permanently reset this server: "
if /i not "%CONFIRM%"=="DELETE" (
    echo Reset cancelled. No data was deleted.
    exit /b 1
)

rmdir /s /q "%RESET_TARGET%"
if exist "%RESET_TARGET%\" (
    echo ERROR: The data directory could not be removed completely.
    exit /b 1
)

echo.
echo Server data deleted. Run start-server.bat to create a fresh server.
exit /b 0
