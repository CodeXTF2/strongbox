@echo off
rem Strongbox server quick start (local testing).
rem
rem   start-server.bat                 open registration on http://127.0.0.1:8080 (ports asked on first start)
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

if not defined STRONGBOX_DATA_DIR     set "STRONGBOX_DATA_DIR=%~dp0strongbox-data"
rem Anyone who can reach the server may create accounts. Fine on 127.0.0.1 only.
if not defined STRONGBOX_REGISTRATION set "STRONGBOX_REGISTRATION=open"
rem Network interface and ports are asked once, on the first start, then remembered in the
rem data directory:
rem   interface        which address the server listens on, picked from a list (default: this
rem                    machine only). The admin page always stays on this machine.
rem   server port      what clients connect to (default 8080)
rem   admin page port  the invite code / stats page, opened in a browser on this machine only
rem                    (default 4444)
rem Invite codes only matter with STRONGBOX_REGISTRATION=invite.
if defined STRONGBOX_LISTEN goto listen_done
call :ask_host svc_host
call :ask_port svc_port 8080 server-port.txt "First start: port for the server (clients connect here)"
set "STRONGBOX_LISTEN=%svc_host%:%svc_port%"
:listen_done
if defined STRONGBOX_ADMIN_LISTEN goto admin_done
call :ask_port adm_port 4444 admin-port.txt "First start: port for the admin page (this machine only)"
set "STRONGBOX_ADMIN_LISTEN=127.0.0.1:%adm_port%"
:admin_done
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
if "%svc_host%"=="" goto host_note_done
if "%svc_host%"=="127.0.0.1" goto host_note_done
echo                 reachable from the network over plain HTTP: put a TLS proxy in front ^(deploy\^)
:host_note_done
echo   admin page:   http://%STRONGBOX_ADMIN_LISTEN%/  ^(this machine only^)
echo   data:         %STRONGBOX_DATA_DIR%
echo   registration: %STRONGBOX_REGISTRATION%
echo   vault layout: %layout%
echo The first run compiles the server, which takes a few minutes. Ctrl+C stops it.
echo.

cargo run -p strongbox-server -- %*
set "code=%errorlevel%"
if not "%code%"=="0" pause
exit /b %code%

rem ask_port <variable> <default> <file in the data directory> <prompt>
rem Reads the saved port, or asks for it (Enter keeps the default) and saves the answer.
:ask_port
set "%~1=%~2"
if exist "%STRONGBOX_DATA_DIR%\%~3" goto ask_port_saved
set /p "%~1=%~4 [%~2]: "
call :port_ok %~1 %~2
if not exist "%STRONGBOX_DATA_DIR%" mkdir "%STRONGBOX_DATA_DIR%"
call set "ap_val=%%%~1%%"
>"%STRONGBOX_DATA_DIR%\%~3" echo %ap_val%
exit /b 0
:ask_port_saved
set /p "%~1="<"%STRONGBOX_DATA_DIR%\%~3"
call :port_ok %~1 %~2
exit /b 0

rem port_ok <variable> <default>: fall back to the default unless the value is all digits.
:port_ok
call set "ap_val=%%%~1%%"
echo %ap_val%| findstr /r "^[0-9][0-9]*$" >nul
if errorlevel 1 echo   Not a port number; using %~2.
if errorlevel 1 set "%~1=%~2"
exit /b 0

rem ask_host <variable>: pick the interface to listen on from a list, or read the saved choice.
:ask_host
if exist "%STRONGBOX_DATA_DIR%\listen-host.txt" goto ask_host_saved
set "ifn=2"
set "iface_1=127.0.0.1"
set "iface_2=0.0.0.0"
set "iname_1=This machine only"
set "iname_2=All interfaces"
rem Adapter name and IPv4 address of every interface (PowerShell), falling back to ipconfig.
for /f "usebackq tokens=1,2 delims=|" %%a in (`powershell -NoProfile -Command "Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { $_.InterfaceAlias + '|' + $_.IPAddress }" 2^>nul`) do call :add_iface %%b "%%a"
if %ifn% gtr 2 goto ask_host_show
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do call :add_iface %%a "Interface"
:ask_host_show
echo First start: choose the network interface the server listens on ^(1 is recommended: use it
echo with a local TLS proxy^).
set "ifi=1"
:ask_host_list
if %ifi% gtr %ifn% goto ask_host_pick
call set "ifa=%%iface_%ifi%%%"
call set "ifm=%%iname_%ifi%%%"
echo   %ifi%^) %ifm%: %ifa%
set /a ifi+=1
goto ask_host_list
:ask_host_pick
set "ifc=1"
set /p "ifc=  Interface [1]: "
echo %ifc%| findstr /r "^[0-9][0-9]*$" >nul
if errorlevel 1 set "ifc=1"
if %ifc% lss 1 set "ifc=1"
if %ifc% gtr %ifn% set "ifc=1"
call set "%~1=%%iface_%ifc%%%"
if not exist "%STRONGBOX_DATA_DIR%" mkdir "%STRONGBOX_DATA_DIR%"
call set "ifa=%%%~1%%"
>"%STRONGBOX_DATA_DIR%\listen-host.txt" echo %ifa%
exit /b 0
:ask_host_saved
set /p "%~1="<"%STRONGBOX_DATA_DIR%\listen-host.txt"
exit /b 0

rem add_iface <address> <adapter name>: append a detected interface to the list.
:add_iface
set /a ifn+=1
set "iface_%ifn%=%~1"
set "iname_%ifn%=%~2"
exit /b 0
