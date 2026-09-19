@echo off
setlocal
cd /d "%~dp0"

REM Quiet launcher: hand off to WScript and immediately close this CMD window.
start "" "%SystemRoot%\System32\wscript.exe" "%~dp0Launch-Meraki-MSP-Toolkit.vbs"
exit /b 0
