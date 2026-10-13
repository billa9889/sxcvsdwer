@echo off
setlocal
cd /d "%~dp0"

set "INCLUDE="
set "LIB="
set "LIBPATH="
set "VCINSTALLDIR="
set "VSINSTALLDIR="
set "WindowsSdkDir="
set "WindowsSDKVersion="
set "UCRTVersion="
set "VCToolsInstallDir="
set "VCToolsVersion="
set "VisualStudioVersion="
set "VSAPPIDDIR="
set "VSAPPIDNAME="
set "FrameworkDir="
set "FrameworkVersion="

set "VSCMD_VER="
set "VSCMD_ARG_TGT_ARCH="
set "VSCMD_ARG_HOST_ARCH="
set "VSCMD_ARG_VCVARS_VER="
set "VSCMD_ARG_APP_PLAT="
set "VSCMD_START_DIR="
set "VSCMD_SKIP_SENDTELEMETRY="

taskkill /f /im FileHider.exe >nul 2>&1

del /f /q FileHider.obj >nul 2>&1
del /f /q FileHider.bin >nul 2>&1
del /f /q FileHider.exe >nul 2>&1

if not exist "RTCore64.bin" (
    if exist "RTCore64.sys.bak" (
        move /y "RTCore64.sys.bak" "RTCore64.bin" >nul 2>&1
    )
)

set "VCVARS="
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

if not defined VCVARS goto :no_vcvars
echo [*] vcvars: %VCVARS%
call "%VCVARS%" >nul 2>&1

set "WDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "WDK_VER="
if not defined WDK_VER if exist "%WDK_ROOT%\Include\10.0.26100.0\km\ntifs.h" set "WDK_VER=10.0.26100.0"
if not defined WDK_VER if exist "%WDK_ROOT%\Include\10.0.22621.0\km\ntifs.h" set "WDK_VER=10.0.22621.0"
if not defined WDK_VER if exist "%WDK_ROOT%\Include\10.0.22000.0\km\ntifs.h" set "WDK_VER=10.0.22000.0"
if not defined WDK_VER if exist "%WDK_ROOT%\Include\10.0.20348.0\km\ntifs.h" set "WDK_VER=10.0.20348.0"
if not defined WDK_VER if exist "%WDK_ROOT%\Include\10.0.19041.0\km\ntifs.h" set "WDK_VER=10.0.19041.0"
if not defined WDK_VER goto :no_wdk
echo [*] WDK: %WDK_VER%

set "INCLUDE=%WDK_ROOT%\Include\%WDK_VER%\km;%WDK_ROOT%\Include\%WDK_VER%\km\crt;%WDK_ROOT%\Include\%WDK_VER%\shared;%WDK_ROOT%\Include\%WDK_VER%\km\filter;%INCLUDE%"
set "LIB=%WDK_ROOT%\Lib\%WDK_VER%\km\x64;%WDK_ROOT%\Lib\%WDK_VER%\km\x64\filter;%LIB%"

echo.
echo [1/2] FileHider.bin
if not exist "FileHider.c" goto :no_src

cl /nologo /c /GS- /kernel /Zl /W3 /O2 /D_AMD64_ /DAMD64 FileHider.c
if errorlevel 1 goto :cl_failed

link /nologo /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE /MACHINE:X64 /NODEFAULTLIB /OUT:FileHider.bin FileHider.obj ntoskrnl.lib hal.lib fltmgr.lib
if errorlevel 1 goto :link_failed
echo     driver OK

del /f /q FileHider.obj >nul 2>&1

echo.
echo [2/2] FileHider.exe
if not exist "Program.cs"      goto :no_client
if not exist "KernelLoader.cs" goto :no_client

set "CSC="
if not defined CSC if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\Roslyn\csc.exe" set "CSC=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\Roslyn\csc.exe"
if not defined CSC if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\Roslyn\csc.exe" set "CSC=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\Roslyn\csc.exe"
if not defined CSC if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\Roslyn\csc.exe" set "CSC=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\Roslyn\csc.exe"
if not defined CSC if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe" set "CSC=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe"
if not defined CSC if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe" set "CSC=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe"

if not defined CSC set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" goto :no_csc

echo [*] csc: %CSC%
echo.

set "RES="
if exist "FileHider.bin" set "RES=%RES% /resource:FileHider.bin,FileHider"
if exist "RTCore64.bin"  set "RES=%RES% /resource:RTCore64.bin,RTCore64"

echo [*] resources: %RES%
echo.

"%CSC%" /nologo /target:winexe /platform:x64 /optimize+ /main:FileHider.Program /win32manifest:app.manifest /out:FileHider.exe %RES% /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.ServiceProcess.dll /reference:System.Xml.dll Program.cs KernelLoader.cs
if errorlevel 1 goto :csc_failed

echo     client OK
echo.
echo BUILD COMPLETE
endlocal
exit /b 0

:no_vcvars
echo [!] vcvars64.bat not found.
exit /b 2
:no_wdk
echo [!] WDK km headers not found under "%WDK_ROOT%\Include"
exit /b 3
:no_src
echo [!] FileHider.c missing
exit /b 4
:cl_failed
echo [!] cl failed
exit /b 5
:link_failed
echo [!] link failed
exit /b 6
:no_client
echo [!] Program.cs or KernelLoader.cs missing
exit /b 7
:no_csc
echo [!] csc.exe missing
exit /b 9
:csc_failed
echo [!] csc failed
exit /b 10