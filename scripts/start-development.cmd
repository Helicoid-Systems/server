@echo off
setlocal
rem Run the reviewed loopback fixture; keep errors visible after it stops.
rem Preserve the configured PowerShell policy. No elevation or bypass.
powershell.exe -NoLogo -NoProfile -File "%~dp0start-development.ps1"
set "helicoid_fixture_exit=%ERRORLEVEL%"
echo.
echo Helicoid development server stopped (exit %helicoid_fixture_exit%).
echo If PowerShell refused the script, the error is shown above.
echo No service was installed. Press any key to close this window.
pause >nul
exit /b %helicoid_fixture_exit%
