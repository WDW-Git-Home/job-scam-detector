@echo off
echo ========================================
echo Building Job Scam Detector .exe
echo ========================================

:: Install dependencies if needed
pip install customtkinter pyinstaller pillow

:: Clean previous builds
if exist "dist" rmdir /s /q dist
if exist "build" rmdir /s /q build

:: Build single executable
pyinstaller --onefile --windowed --icon=assets\logo.ico ^
  --name "scam-detector" ^
  --add-data "assets;assets" ^
  scam-detector-gui.py

echo.
echo ========================================
echo Build complete! Executable located at:
echo dist\scam-detector.exe
echo ========================================

pause
