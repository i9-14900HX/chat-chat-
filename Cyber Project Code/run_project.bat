@echo off
setlocal enabledelayedexpansion

:: --- מספר לקוחות
set /p NUM_CLIENTS=How many clients would you like to run?

:: --- Start server and save PID
start "" cmd /k python "C:\Users\bugon\Documents\code\python\Cyber Project\28122025server.py"
for /f "tokens=2" %%a in ('tasklist /FI "IMAGENAME eq cmd.exe" /FO LIST ^| find "PID:"') do set SERVER_PID=%%a

:: --- Start clients and save PIDs
set i=1
:client_loop
if %i% leq %NUM_CLIENTS% (
    start "" cmd /k python "C:\Users\bugon\Documents\code\python\Cyber Project\28122025client.py"
    for /f "tokens=2" %%a in ('tasklist /FI "IMAGENAME eq cmd.exe" /FO LIST ^| find "PID:"') do (
        set CLIENT_PID_!i!=%%a
    )
    set /a i+=1
    goto client_loop
)

echo All processes started.
pause

:: --- Kill server
taskkill /F /PID %SERVER_PID%

:: --- Kill clients
set i=1
:kill_loop
if %i% leq %NUM_CLIENTS% (
    taskkill /F /PID !CLIENT_PID_%i%! 
    set /a i+=1
    goto kill_loop
)

echo All processes killed.
pause