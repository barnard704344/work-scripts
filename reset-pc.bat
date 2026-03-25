@echo off
:: Suspend BitLocker and factory reset Windows
:: Run as Administrator (self-elevates)

:: Check for admin rights, self-elevate if needed
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ============================================
echo   Suspend BitLocker ^& Reset PC
echo ============================================
echo.

:: Suspend BitLocker
echo Suspending BitLocker on C: ...
manage-bde -protectors -disable C:
if %errorlevel% neq 0 (
    echo WARNING: Could not suspend BitLocker. It may not be enabled.
    echo Continuing with reset anyway...
)
echo.

:: Confirm before reset
echo This will FACTORY RESET this PC and remove all data.
echo.
set /p confirm=Are you sure? (Y/N): 
if /i not "%confirm%"=="Y" (
    echo Cancelled.
    pause
    exit /b
)

echo.
echo Starting factory reset...
systemreset --factoryreset

pause
