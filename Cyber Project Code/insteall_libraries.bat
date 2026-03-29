@echo off
echo Installing required Python packages...
python -m pip install --upgrade pip
python -m pip install numpy pathlib pycryptodome py-diffie-hellman soundfile sounddevice keyboard
echo Done!
pause