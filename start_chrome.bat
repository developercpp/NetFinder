@echo off
echo Starting Chrome with remote debugging on port 9222...
echo.
echo NOTE: Close ALL Chrome windows first for this to work.
echo.


if exist "C:\Program Files\Google\Chrome\Application\chrome.exe" (
    start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir="%TEMP%\chrome-debug"
    goto :done
)

if exist "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" (
    start "" "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir="%TEMP%\chrome-debug"
    goto :done
)


if exist "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" (
    echo Chrome not found, using Microsoft Edge instead...
    start "" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --remote-debugging-port=9222 --user-data-dir="%TEMP%\edge-debug"
    goto :done
)

echo Could not find Chrome or Edge. Please install Chrome or edit this script.
pause
exit /b 1

:done
echo.
echo Browser started! Now run: python finder.py
echo.
pause

