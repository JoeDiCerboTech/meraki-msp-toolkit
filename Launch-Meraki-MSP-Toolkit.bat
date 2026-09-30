@echo off
setlocal
cd /d "%~dp0"

if not exist "%~dp0Meraki-MSP-Toolkit.py" (
    echo.
    echo ERROR: Meraki-MSP-Toolkit.py was not found next to this launcher.
    echo Extract the entire ZIP before running the toolkit.
    echo.
    pause
    exit /b 1
)

REM Prefer the windowless launcher for normal use, but fall back to a
REM console Python process on failure so startup errors remain visible.
where pyw.exe >nul 2>&1
if %errorlevel%==0 (
    pyw.exe -3 "%~dp0Meraki-MSP-Toolkit.py"
    if %errorlevel%==0 exit /b 0
    echo.
    echo The windowless Python launch failed. Retrying with a console...
    echo.
    py.exe -3 "%~dp0Meraki-MSP-Toolkit.py"
    if %errorlevel%==0 exit /b 0
    echo.
    echo Meraki MSP Toolkit failed to start.
    pause
    exit /b %errorlevel%
)

where pythonw.exe >nul 2>&1
if %errorlevel%==0 (
    pythonw.exe "%~dp0Meraki-MSP-Toolkit.py"
    if %errorlevel%==0 exit /b 0
    echo.
    echo The windowless Python launch failed. Retrying with a console...
    echo.
    where python.exe >nul 2>&1
    if %errorlevel%==0 (
        python.exe "%~dp0Meraki-MSP-Toolkit.py"
        if %errorlevel%==0 exit /b 0
    )
    echo.
    echo Meraki MSP Toolkit failed to start.
    pause
    exit /b 1
)

where py.exe >nul 2>&1
if %errorlevel%==0 (
    py.exe -3 "%~dp0Meraki-MSP-Toolkit.py"
    if %errorlevel%==0 exit /b 0
    echo.
    echo Meraki MSP Toolkit failed to start.
    pause
    exit /b %errorlevel%
)

where python.exe >nul 2>&1
if %errorlevel%==0 (
    python.exe "%~dp0Meraki-MSP-Toolkit.py"
    if %errorlevel%==0 exit /b 0
    echo.
    echo Meraki MSP Toolkit failed to start.
    pause
    exit /b %errorlevel%
)

echo.
echo Python 3 was not found.
echo Install Python 3 and make py.exe or python.exe available in PATH.
echo.
pause
exit /b 1
