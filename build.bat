@echo off
setlocal

echo.
echo ========================================
echo   x64dbg MCP Build Helper
echo ========================================
echo.

set "CMAKE_BIN=cmake"
where %CMAKE_BIN% >nul 2>nul
if errorlevel 1 (
    if exist "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" (
        set "CMAKE_BIN=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    ) else (
        echo [ERROR] CMake not found in PATH and no Visual Studio CMake was detected.
        exit /b 1
    )
)

echo [*] Using CMake: %CMAKE_BIN%
echo.

if not exist "build" (
    echo [*] Configuring build directory...
    "%CMAKE_BIN%" -S . -B build
    if errorlevel 1 exit /b 1
)

echo [*] Building both plugin architectures...
"%CMAKE_BIN%" --build build --target all_plugins --config Release
if errorlevel 1 exit /b 1

echo.
echo [OK] Build finished.
echo dp32/dp64 outputs are available under the generated build folders.
echo.
