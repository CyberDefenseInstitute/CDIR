@echo off

rem CDIR v0.2.2

rem if内のERRORLEVELを常時反映させるためにENABLEDELAYEDEXPANSIONをセット
setlocal ENABLEDELAYEDEXPANSION


echo ライブデータ収集ツール実行開始


FOR /F "usebackq" %%i IN (`%CDIR_CSCRIPT% tools\preproc.vbs`) DO SET foldername=%%i

if %ERRORLEVEL% NEQ 0 (
    echo VBScriptの実行に失敗しました．
    PAUSE
    exit
)


FOR /F "usebackq" %%i IN (`type %foldername%\info\computername`) DO SET computername=%%i
FOR /F "usebackq" %%i IN (`type %foldername%\info\osvolume`) DO SET osvolume=%%i
FOR /F "usebackq" %%i IN (`type %foldername%\info\pagefilepath`) DO SET pagefilepath=%%i
FOR /F "usebackq" %%i IN (`type %foldername%\info\osarchitecture`) DO SET osarchitecture=%%i
FOR /F "usebackq" %%i IN (`type %foldername%\info\version`) DO SET version=%%i


echo "メモリダンプを取得:1 メモリダンプを取得しない:2 終了:0"
set /p input=">"

if %input%==1 goto memdump
if %input%==2 goto forecopy

goto SKIP


:memdump

echo メモリダンプ取得開始
rem Windows XP/2003用
if %version% lss 6 (
    if %osarchitecture% equ 64 (
        tools\RamCapture64.exe %foldername%\RAM_%COMPUTERNAME%.raw
    ) else (
        tools\RamCapture.exe %foldername%\RAM_%COMPUTERNAME%.raw
    )
) else (
    if %osarchitecture% equ 64 (
        tools\RamCapture64.exe %foldername%\RAM_%COMPUTERNAME%.raw
    ) else (
        tools\RamCapture.exe %foldername%\RAM_%COMPUTERNAME%.raw
    )

    rem winpmemが失敗したときはRamCaptureで取得する
    if "!ERRORLEVEL!" NEQ "0" (
        rem pagefile.sysがOSのボリューム配下にあれば一緒に取得する
        tools\winpmem.exe -p %pagefilepath% -o %foldername%\RAM_%COMPUTERNAME%.aff4
    )
)
echo メモリダンプ取得終了
echo.

:forecopy

echo 解析用データ取得開始

rem $MFT, プリフェッチ、イベントログ、レジストリを取得
tools\forecopy.exe -mpeg %foldername%\
move forecopy_handy.log %foldername%\forecopy.log
echo 解析用データ取得終了
echo.
echo データ取得が完了しました。
echo.


:SKIP


PAUSE
exit
