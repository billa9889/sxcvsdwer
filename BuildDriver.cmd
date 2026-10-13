@echo off
setlocal
cd /d "%~dp0"

set "CONFIG=%~1"
if "%CONFIG%"=="" set "CONFIG=Release"

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

:: --- Kill VS Developer Command Prompt markers so vcvars64 re-initializes ---
set "VSCMD_VER="
set "VSCMD_ARG_TGT_ARCH="
set "VSCMD_ARG_HOST_ARCH="
set "VSCMD_ARG_VCVARS_VER="
set "VSCMD_ARG_APP_PLAT="
set "VSCMD_START_DIR="
set "VSCMD_SKIP_SENDTELEMETRY="

del /f /q "Native\FileHider.obj" >nul 2>&1
del /f /q "Native\FileHider.sys" >nul 2>&1

:: ...rest of the file unchanged...