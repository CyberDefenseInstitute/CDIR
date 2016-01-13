@echo off

rem CDIR v0.2.2

ver | findstr "5." > nul 2>&1
if %ERRORLEVEL% EQU 0 goto XP

rem 管理者権限で実行されているか確認


for /f "tokens=1 delims=," %%i in ('whoami /groups /FO CSV /NH') do (
	if "%%~i"=="BUILTIN\Administrators" set ADMIN=yes
	if "%%~i"=="Mandatory Label\High Mandatory Level" set ELEVATED=yes
)

if "%ADMIN%" neq "yes" (
    echo Administratorsグループではないユーザーです．
    PAUSE
    exit
)
if "%ELEVATED%" neq "yes" (
    echo プロセスが昇格されていません．
    PAUSE
    exit
)

:XP

pushd %~dp0

rem check cdir.exe, cscript.exe
if EXIST tools\cdir.exe (
    SET CDIR_CMDEXE="tools\cdir.exe"
) else (
    echo cdir.exe が見つかりませんでした．
    PAUSE
    exit
)

if EXIST tools\cscript.exe (
    SET CDIR_CSCRIPT="tools\cscript.exe"
) else (
    SET CDIR_CSCRIPT="%SYSTEMROOT%\System32\cscript.exe"
)

%CDIR_CMDEXE% /C tools\proc.bat
