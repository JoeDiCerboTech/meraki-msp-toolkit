@echo off
setlocal
cd /d "%~dp0"

REM Transparent launcher: start the Python GUI directly.
where pyw.exe >nul 2>&1
if %errorlevel%==0 (
    pyw.exe -3 "%~dp0Meraki-MSP-Toolkit.py"
    exit /b %errorlevel%
)

where pythonw.exe >nul 2>&1
if %errorlevel%==0 (
    pythonw.exe "%~dp0Meraki-MSP-Toolkit.py"
    exit /b %errorlevel%
)

where py.exe >nul 2>&1
if %errorlevel%==0 (
    py.exe -3 "%~dp0Meraki-MSP-Toolkit.py"
    exit /b %errorlevel%
)

where python.exe >nul 2>&1
if %errorlevel%==0 (
    python.exe "%~dp0Meraki-MSP-Toolkit.py"
    exit /b %errorlevel%
)

echo.
echo Python 3 was not found.
echo Install Python 3 and make py.exe or python.exe available in PATH.
echo.
pause
exit /b 1
