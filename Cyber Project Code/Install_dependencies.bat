@echo off
:: Change code page to UTF-8 for better encoding support
chcp 65001 >nul

echo ===================================================
echo   Installing External Libraries for Chat ^& Audio
echo ===================================================
echo.

:: Check if Python and pip are installed in the system
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found on this system. 
    echo Please install Python 3 and make sure to check "Add Python to PATH".
    pause
    exit /b
)

echo [+] Upgrading pip to the latest version...
python -m pip install --upgrade pip
echo.

echo [+] Starting installation of external public packages...
echo ---------------------------------------------------

:: Installing PyQt6 for the Graphical User Interface (GUI)
echo [+] Installing PyQt6...
pip install PyQt6

:: Installing audio processing and file management libraries
echo [+] Installing numpy...
pip install numpy

echo [+] Installing soundfile...
pip install soundfile

echo [+] Installing sounddevice (for recording ^& playback)...
pip install sounddevice

:: Installing encryption and security libraries
echo [+] Installing pycryptodome (for AES cryptography)...
pip install pycryptodome

echo [+] Installing py-diffie-hellman (for DH key exchange)...
pip install py-diffie-hellman

echo ---------------------------------------------------
echo [V] All public libraries have been installed successfully!
echo.
pause