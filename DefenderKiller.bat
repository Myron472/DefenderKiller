:Start
@echo off

Rem Enable Delayed Expansion
setlocal EnableDelayedExpansion

color 0f
Title DefenderKiller

rem ��६����
set "sFreeSize="
set "sFreeSizePseudoMb1="
set "Freed="
set "ch=cecho.exe"

rem UAC
reg query "HKU\S-1-5-19\Environment" >nul 2>&1 & cls
if "%Errorlevel%" NEQ "0" (
PowerShell -WindowStyle Hidden -NoProfile "Start-Process '%~dpnx0' -WindowStyle Normal -Verb RunAs" && exit
)

rem �᫨ ���⭨� ������� - ��। ����᪮� �஢��塞, �⮡� ���� � ॠ�쭮� �६��� �뫠 �⪫�祭� - ��� �⮣� �� ᪠砥��� FuckDefender
if exist "%SystemDrive%\Program Files\Windows Defender" (
reg query "HKLM\Software\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" >nul 2>&1 || call :CheckOff
)

rem Check Ethernet, DownLoad Files, Check Update
if not exist %SystemDrive%\DefenderKiller call :DownLoadFile 

rem ����� .bat �� ����� TI
if /i not "%USERNAME%"=="SYSTEM" "%SystemDrive%\DefenderKiller\TI.exe" "%~f0" %* & exit

rem ���室�� � ࠡ�稩 ��⠫��
cd /d "%SystemDrive%\DefenderKiller"

ConX.exe show

rem �஢��塞 ����������
call :CheckUpdate

rem 740
@cmdow @ /SIZ 1000 715

rem ���� ���᮫� � �
reg query "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" >nul 2>&1 || call :ModifedCMD

qprocess "Win 10 Tweaker.exe">nul 2>&1 || nircmd.exe win center alltop


cls

%ch% {0f}DefenderKiller �����: {0b}8.3{#}
if "%Version%" EQU "!latestVersion!" (
%ch% {0a} [�� �ᯮ���� ���㠫��� �����]{\n #}
) else (
%ch% {0c} [����� ���� ���ॢ襩]{\n #}
)
%ch% {0f}����饭� � �ࠢ���: {0e}%username%{\n #}
echo.
%ch% {03}����ﭨ� ���⭨�� Windows:{\n #}
if not exist "%ProgramFiles%\Windows Defender" (
%ch% {02}������ �� Windows{08} [����� Windows Defender 㤠����]{\n #}
) else (
%ch% {04}�� 㤠��� �� Windows{\n #}
)

rem Win 8.1
VER | FINDSTR /IL "6.3." > NUL
IF %ERRORLEVEL% EQU 0 (goto Proc)

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" >nul 2>&1
if "%ERRORLEVEL%"=="0" (%ch% {0a}���⭨� �⪫�祭 {08}[���� ॥��� DisableAntiSpyware]{\n #})
if "%ERRORLEVEL%"=="1" (%ch% {04}���⭨� ����祭{\n #})

:Proc
echo.

%ch% {03}����ﭨ� ����ᮢ ���⭨��:{\n #}

%ch% {0f}MsMpEng      {#}
qprocess "MsMpEng.exe">nul 2>&1 && %ch% {04}����� ����饭{#}|| %ch% {0a}����� �� ����饭{#}
%ch% {08} (Antimalware Service Executable){\n #}

%ch% {0f}SmartScreen  {#}
qprocess "smartscreen.exe">nul 2>&1 && %ch% {04}����� ����饭{#}|| %ch% {0a}����� �� ����饭{#}
%ch% {08} (SmartScreen ���⭨�� Windows){\n #}

%ch% {0f}SgrmBroker   {#}
qprocess "SgrmBroker.exe">nul 2>&1 && %ch% {04}����� ����饭{#}|| %ch% {0a}����� �� ����饭{#}
%ch% {08} (��㦡� �ப�� �����ਭ�� �।� �믮������ System Guard){\n #}

%ch% {0f}Uhssvc Upd.  {#}
qprocess "uhssvc.exe">nul 2>&1 && %ch% {04}����� ����饭{#}|| %ch% {0a}����� �� ����饭{#}
%ch% {08} (Uhssvc.exe Microsoft Update Health Service){\n #}

%ch% {0f}SecHealthUI  {#}
qprocess "SecHealthUI.exe">nul 2>&1 && %ch% {04}����� ����饭{#}|| %ch% {0a}����� �� ����饭{#}
%ch% {08} (������᭮��� Windows){\n #}

%ch% {0f}NisSrv       {#}
qprocess "NisSrv.exe">nul 2>&1 && %ch% {04}����� ����饭{#}|| %ch% {0a}����� �� ����饭{#}
%ch% {08} (Network Realtime Inspection){\n #}

%ch% {0f}MpCmdRun     {#}
qprocess "MpCmdRun.exe">nul 2>&1 && %ch% {04}����� ����饭{#}|| %ch% {0a}����� �� ����饭{#}
%ch% {08} (Microsoft malware protection){\n #}

%ch% {0f}Heal.Systray {#}
qprocess "SecurityHealthSystray.exe">nul 2>&1 && %ch% {04}����� ����饭{#}|| %ch% {0a}����� �� ����饭{#}
%ch% {08} (SecurityHealthSystray.exe Windows Security notification icon){\n #}

%ch% {0f}Heal.Service {#}
qprocess "SecurityHealthService.exe">nul 2>&1 && %ch% {04}����� ����饭{#}|| %ch% {0a}����� �� ����饭{#}
%ch% {08} (SecurityHealthService.exe){\n #}

%ch% {0f}SHelath Host {#}
qprocess "SecurityHealthHost.exe">nul 2>&1 && %ch% {04}����� ����饭{#}|| %ch% {0a}����� �� ����饭{#}
%ch% {08} (SecurityHealthHost.exe){\n #}

echo.
rem �஢�ઠ �㦡 � �ࠩ��஢
%ch% {03}����ﭨ� �㦡 ���⭨��:{\n #}
%ch% {0f}WinDefend {#} 
sc query WinDefend >nul 2>&1
if ERRORLEVEL 1 (%ch% {0a}�� �������{\n #}) else (
sc query WinDefend | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}�⪫�祭�{\n #}) ELSE (%ch% {04}����饭�{\n #}))

%ch% {0f}WdNisSvc   {#}
sc query WdNisSvc >nul 2>&1
if ERRORLEVEL 1 (%ch% {0a}�� �������{\n #}) else (
sc query WdNisSvc | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}�⪫�祭�{\n #}) ELSE (%ch% {04}����饭�{\n #}))

%ch% {0f}Sense      {#}
sc query Sense >nul 2>&1
if ERRORLEVEL 1 (%ch% {0a}�� �������{\n #}) else (
sc query Sense | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}�⪫�祭�{\n #}) ELSE (%ch% {04}����饭�{\n #}))

%ch% {0f}Sec.Health {#}
sc query SecurityHealthService >nul 2>&1
if ERRORLEVEL 1 (%ch% {0a}�� �������{\n #}) else (
sc query SecurityHealthService | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}�⪫�祭�{\n #}) ELSE (%ch% {04}����饭�{\n #}))

%ch% {0f}wscsvc     {#}
sc query wscsvc >nul 2>&1
if ERRORLEVEL 1 (%ch% {0a}�� �������{\n #}) else (
sc query wscsvc | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}�⪫�祭�{\n #}) ELSE (%ch% {04}����饭�{\n #}))

%ch% {0f}SgrmBroker {#}
sc query SgrmBroker >nul 2>&1
if ERRORLEVEL 1 (%ch% {0a}�� �������{\n #}) else (
sc query SgrmBroker | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}�⪫�祭�{\n #}) ELSE (%ch% {04}����饭�{\n #}))

echo.
%ch% {03}����ﭨ� �ࠩ��஢ ���⭨��:{\n #}

%ch% {0f}WdNisDrv:{#} 
sc query WdNisDrv >nul 2>&1
if ERRORLEVEL 1 (%ch% {08}�� �������{#} ) else (
sc query WdNisDrv | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}�⪫�祭{#} ) ELSE (%ch% {04}����饭{#} ))

%ch% {0f}WdBoot:{#} 
sc query WdBoot >nul 2>&1
if ERRORLEVEL 1 (%ch% {08}�� �������{#} ) else (
sc query WdBoot | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}�⪫�祭{#} ) ELSE (%ch% {04}����饭{#} ))

%ch% {0f}WdFilter:{#} 
sc query WdFilter >nul 2>&1
if ERRORLEVEL 1 (%ch% {08}�� �������{#} ) else (
sc query WdFilter | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}�⪫�祭{#} ) ELSE (%ch% {04}����饭{#} ))

%ch% {0f}MsSecFlt:{#} 
sc query MsSecFlt >nul 2>&1
if ERRORLEVEL 1 (%ch% {08}�� �������{#} ) else (
sc query MsSecFlt | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}�⪫�祭{#} ) ELSE (%ch% {04}����饭{#} ))

%ch% {0f}SgrmAgent:{#} 
sc query SgrmAgent >nul 2>&1
if ERRORLEVEL 1 (%ch% {08}�� �������{\n #}) else (
sc query SgrmAgent | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (%ch% {0a}�⪫�祭{\n #}) ELSE (%ch% {04}����饭{\n #}))

rem �஢�ઠ �����
set "taskpathDef1=Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
set "taskpathDef2=Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
set "taskpathDef3=Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
set "taskpathDef4=Microsoft\Windows\Windows Defender\Windows Defender Verification"
for /f "delims=, tokens=3" %%I in (' 2^>nul SCHTASKS /QUERY /FO CSV /NH /TN "%taskpathDef1%" ') do set "replyTaskDef1=%%~I"
for /f "delims=, tokens=3" %%I in (' 2^>nul SCHTASKS /QUERY /FO CSV /NH /TN "%taskpathDef2%" ') do set "replyTaskDef2=%%~I"
for /f "delims=, tokens=3" %%I in (' 2^>nul SCHTASKS /QUERY /FO CSV /NH /TN "%taskpathDef3%" ') do set "replyTaskDef3=%%~I"
for /f "delims=, tokens=3" %%I in (' 2^>nul SCHTASKS /QUERY /FO CSV /NH /TN "%taskpathDef4%" ') do set "replyTaskDef4=%%~I"
if not "!replyTaskDef1!"=="" (
	if "!replyTaskDef1!"=="�⪫�祭�" ( set "TaskDefResult1={0a}�⪫�祭�{#}" ) else ( set "TaskDefResult1={04}����祭�{#}" )
) else ( set "TaskDefResult1={0a}�� �������{#}" )
if not "!replyTaskDef2!"=="" (
	if "!replyTaskDef2!"=="�⪫�祭�" ( set "TaskDefResult2={0a}�⪫�祭�{#}" ) else ( set "TaskDefResult2={04}����祭�{#}" )
) else ( set "TaskDefResult2={0a}�� �������{#}" )
if not "!replyTaskDef3!"=="" (
	if "!replyTaskDef3!"=="�⪫�祭�" ( set "TaskDefResult3={0a}�⪫�祭�{#}" ) else ( set "TaskDefResult3={04}����祭�{#}" )
) else ( set "TaskDefResult3={0a}�� �������{#}" )
if not "!replyTaskDef4!"=="" (
	if "!replyTaskDef4!"=="�⪫�祭�" ( set "TaskDefResult4={0a}�⪫�祭�{#}" ) else ( set "TaskDefResult4={04}����祭�{#}" )
) else ( set "TaskDefResult4={0a}�� �������{#}" )

echo.
%ch% {03}����ﭨ� ����� � �����஢騪�:{\n #}
%ch% {0f}Windows Defender Cache Maintenance: %TaskDefResult1%{\n #}
%ch% {0f}Windows Defender Cleanup:           %TaskDefResult2%{\n #}
%ch% {0f}Windows Defender Scheduled Scan:    %TaskDefResult3%{\n #}
%ch% {0f}Windows Defender Verification:      %TaskDefResult4%{\n #}

rem ����� ���⭨��
if not exist "%SYSTEMROOT%\System32\Tasks\Microsoft\Windows\Windows Defender" (
set "TasksDefender={0a}����� 㤠����{#}"
) else (
set "TasksDefender={0c}����� �� 㤠����{#}"
)
%ch% {04}^--^>{#}{0f}����� (����� Tasks): %TasksDefender% {\n #}

echo.
%ch% {0f} 1{#} - {0a}�������� ���⭨�� {08}[��������⭮]{\n #}
if exist "%ProgramFiles%\Windows Defender" (
%ch% {0f} 2{#} - {0a}�⪫�祭��/����祭�� {08}[� ����ᨬ��� �� ���ﭨ�. �ॡ���� ��१���㧪�]{\n #}
) else (
%ch% {08} 2{#} - {08}�⪫�祭��/����祭�� ������㯭�, ���⭨� 㤠���{\n #}
)
%ch% {0f} 3{#} - {0b}��������/����⠭������� '������᭮��� Windows'{\n #}
%ch% {0f} 4{#} - {0e}���஡��� ���ﭨ� ��⠫���� ���⭨��{\n #}
%ch% {08} 5{#} - {08}ChangeLog{\n #}
%ch% {08} 6{#} - {08}��ࠢ�� � ࠧࠡ��稪�{\n #}
%ch% {08} 7{#} - {08}��室{\n #}
%ch%                                                                                                       {0b}By Vlado ��� W10T{\n #}

echo.
set "input="
set /p input=*   ��� �롮�: 
if "%input%"=="1"    ( cls && goto DeleteDefender)
if "%input%"=="2"    ( cls && goto OnOffDefender)
if "%input%"=="3"    ( cls && goto SecHealth )
if "%input%"=="4"    ( cls && goto Catalogs)
if "%input%"=="5"    ( cls && goto ChangeLog )
if "%input%"=="6"    ( cls && goto Credits )
if "%input%"=="7"    ( exit )
) else (
	cls & goto Start
)

:DeleteDefender
rem �஢��塞 Unlocker
reg query "HKLM\SOFTWARE\Classes\CLSID\{DDE4BEEB-DDE6-48fd-8EB5-035C09923F83}" >nul 2>&1
if "%errorlevel%"=="0" (
%ch% {0c} � ��� ��⠭����� Unlocker{\n #}
%ch% {0c} �������� ����������, ��᪮��� ��������� ���䫨��, �६���� 㤠��� Unlocker � ������ ������{\n #}
pause>nul && cls && goto Start
)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Unlocker.exe" >nul 2>&1
if "%errorlevel%"=="0" (
%ch% {0c} � ��� ��⠭����� Unlocker{\n #}
%ch% {0c} �������� ����������, ��᪮��� ��������� ���䫨��, �६���� 㤠��� Unlocker � ������ ������{\n #}
pause>nul && cls && goto Start
)


sc query WinDefend >nul 2>&1
if ERRORLEVEL 1 (
%ch% {0c} �������, ���⭨� 㦥 㤠���. �� ��� �� ࠢ�� �஢��� 㤠�����?{\n #}
%ch% {08} 1{#} - {0c}��{\n #}
%ch% {08} 2{#} - {08}�⬥��{\n #}
choice /c 12 /n /m " "
if ERRORLEVEL 2 cls && goto Start
)


rem ��⠥� ���� �� ��᪥ ��। 㤠������
setlocal enableextensions enabledelayedexpansion
for /f "usebackq tokens=2 delims==" %%i in (`wmic.exe LogicalDisk where "Name='c:'" get FreeSpace /value`) do set sFreeSize=%%i
if defined sFreeSize (set sFreeSizePseudoMb=%sFreeSize:~0,-7%)


cls

rem ������ ��� ���� � �⪫�砥� ����
@cmdow @ /TOP
rem @cmdow @ /DIS

rem �����蠥� ������ ���⭨��
%ch%    {0f} �����蠥� ������ ���⭨�� ...{\n #}
powershell -command "Stop-Process -processname MsMpEng, SecurityHealthSystray, SecurityHealthService, SecurityHealthHost, smartscreen, SgrmBroker, SecHealthUI, uhssvc, NisSrv -Force" >nul
taskkill /f /im MpCmdRun.exe >nul 2>&1
taskkill /f /im MsMpEng.exe >nul 2>&1
taskkill /f /im SecurityHealthSystray.exe >nul 2>&1
taskkill /f /im SecurityHealthService.exe >nul 2>&1
taskkill /f /im SecurityHealthHost.exe >nul 2>&1
taskkill /f /im smartscreen.exe >nul 2>&1
taskkill /f /im SgrmBroker.exe >nul 2>&1
taskkill /f /im SecHealthUI.exe >nul 2>&1
taskkill /f /im uhssvc.exe >nul 2>&1
taskkill /f /im NisSrv.exe >nul 2>&1

rem ������塞 ������ � �॥
ConX.exe SysTrayRefresh
echo.


rem �⪫�祭�� ���⭨�� � ��२��������� smartscreen.exe
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t reg_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t reg_DWORD /d 0 /f >nul
ren "%SystemRoot%\System32\smartscreen.exe" "smartscreen_fuck.exe" >nul 2>&1

if not exist "%SystemDrive%\Program Files\Windows Defender" (
%ch%    {0c} �ய����� 㤠����� FuckDefender'�� ? {\n #}
%ch% {0f} 1 - ���{\n #}
%ch% {0f} 2 - ��{\n #}
choice /c 12 /n /m " "
if ERRORLEVEL 2 goto NotFuckWD
)


rem ���� ����᪠ FuckDefender
start FuckDefender.exe
:#
(
for /f %%i in ('"tasklist| findstr /bilc:"FuckDefender.exe""') do (%ch%    {04} ��砫��� 㤠�����.{\n #} && echo. && %ch% {0e}    �믮������ 㤠����� ...{\n #})
)|| goto #

timeout /t 1 /nobreak >nul
echo.
%ch%    {0f} ������� �������� ...{\n #}
timeout /t 1 /nobreak>nul
:reload
tasklist | find "FuckDefender.exe" >nul 2>&1
if ERRORLEVEL 1 goto NoRecord
goto reload
:NoRecord
>nul 2>&1 taskkill /f /im Unlocker.exe
>nul 2>&1 taskkill /f /im FuckDefender.exe
>nul 2>&1 taskkill /f /im wscript.exe


:NotFuckWD
echo.
%ch%    {0e} ����塞 �㦡� Windows Defender ...{\n #}
sc delete SecurityHealthService >nul 2>&1
sc delete Sense >nul 2>&1
sc delete WdNisSvc >nul 2>&1
sc delete WinDefend >nul 2>&1
sc delete wscsvc >nul 2>&1
sc delete SgrmBroker >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService /f >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\Sense /f >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc /f >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\WinDefend /f >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\wscsvc /f >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\SgrmBroker /f >nul 2>&1
echo.

%ch%    {0e} ����塞 ������� �� �����஢騪� ...{\n #}
rd /s /q "%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender" >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Windows Defender" /f >nul 2>&1 
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /f >nul 2>&1
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /f >nul 2>&1
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /f >nul 2>&1
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /f >nul 2>&1
echo.

%ch%    {0e} �⪫�砥� �ࠩ��� Windows Defender ...{\n #}
sc stop WdNisDrv >nul 2>&1
sc stop WdBoot >nul 2>&1
sc stop WdFilter >nul 2>&1
sc stop MsSecFlt >nul 2>&1
sc stop SgrmAgent >nul 2>&1

reg add HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv /v Start /t reg_DWORD /d 4 /f >nul
reg add HKLM\SYSTEM\CurrentControlSet\Services\WdBoot /v Start /t reg_DWORD /d 4 /f >nul
reg add HKLM\SYSTEM\CurrentControlSet\Services\WdFilter /v Start /t reg_DWORD /d 4 /f >nul
reg add HKLM\SYSTEM\CurrentControlSet\Services\MsSecFlt /v Start /t reg_DWORD /d 4 /f >nul
reg add HKLM\SYSTEM\CurrentControlSet\Services\SgrmAgent /v Start /t reg_DWORD /d 4 /f >nul
echo.

%ch%    {0e} ��頥� ���⥪�⭮� ���� �� Windows Defender ...{\n #}
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f >nul 2>&1
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f >nul 2>&1
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f >nul 2>&1
echo.

rem ����塞 �� ����� �१ CMD
%ch%    {0e} ����塞 ����� � 䠩�� Windows Defender ...{\n #}
RD /S /Q "%AllUsersProfile%\Microsoft\Windows Defender" >nul 2>&1
RD /S /Q "%AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection" >nul 2>&1
RD /S /Q "%AllUsersProfile%\Microsoft\Windows Security Health" >nul 2>&1

RD /S /Q "%SystemDrive%\ProgramData\Microsoft\Windows Defender" >nul 2>&1
RD /S /Q "%SystemDrive%\ProgramData\Microsoft\Windows Security Health" >nul 2>&1

RD /S /Q "%SystemDrive%\Program Files\Windows Defender" >nul 2>&1
RD /S /Q "%SystemDrive%\Program Files\Windows Defender Advanced Threat Protection" >nul 2>&1
RD /S /Q "%SystemDrive%\Program Files\Windows Security" >nul 2>&1

RD /S /Q "%SystemDrive%\Program Files\PCHealthCheck" >nul 2>&1
RD /S /Q "%SystemDrive%\Program Files\Microsoft Update Health Tools" >nul 2>&1

RD /S /Q "%SystemDrive%\Program Files (x86)\Windows Defender" >nul 2>&1
RD /S /Q "%SystemDrive%\Program Files (x86)\Windows Defender Advanced Threat Protection" >nul 2>&1

RD /S /Q "%SystemRoot%\WinSxS\amd64_windows-defender-am-sigs_31bf3856ad364e35_10.0.19041.1_none_7275cb8fbafec5e1" >nul 2>&1

del /q /s "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim" >nul 2>&1
del /q /s "%SystemRoot%\WinSxS\WindowsDefenderApplicationGuard.wim" >nul 2>&1
del /q "%SystemRoot%\security\database" >nul 2>&1

rem �������� ��� ����� �� WinSxS
rem For /F "usebackq delims=" %%d In (`2^>nul Dir "C:\Windows\WinSxS\*windows-defender*" /S /B /A:D`) Do Rd "%%d" /s /q


echo.
%ch%    {0a} ��室���� FuckDefender �� ࠧ ...{\n #}
start FuckDefender.exe
:#1
(
for /f %%i in ('"tasklist| findstr /bilc:"FuckDefender.exe""') do (echo>nul)
)|| goto #1
:reload1
tasklist | find "FuckDefender.exe" >nul 2>&1
if ERRORLEVEL 1 goto NoRecord1
goto reload1
:NoRecord1
>nul 2>&1 taskkill /f /im Unlocker.exe
>nul 2>&1 taskkill /f /im FuckDefender.exe
>nul 2>&1 taskkill /f /im wscript.exe

wmic os get caption /Format:List | find /i "11" >nul 2>&1
if "%ERRORLEVEL%"=="0" (
echo.
%ch%    {0b} Delete Windows 11{\n #}
start /wait FuckDefender.exe
>nul 2>&1 taskkill /f /im Unlocker.exe
>nul 2>&1 taskkill /f /im FuckDefender.exe
>nul 2>&1 taskkill /f /im wscript.exe
)


rem Make window not always on top
@cmdow @ /NOT
rem @cmdow @ /ENA

rem ������ ���� �� ��᪥ ��᫥ 㤠�����
for /f "usebackq tokens=2 delims==" %%i in (`wmic.exe LogicalDisk where "Name='c:'" get FreeSpace /value`) do set sFreeSize=%%i
if defined sFreeSize (set sFreeSizePseudoMb1=%sFreeSize:~0,-7%)
set /a Freed=!sFreeSizePseudoMb1! - !sFreeSizePseudoMb!
echo.
%ch%     {2f}!Freed! �������� �᢮�������{\n #}
echo.
rem �஢��塞 㤠��� �� ���⭨�
if not exist "%ProgramFiles%\Windows Defender" (
powershell -command "[Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[Windows.Forms.MessageBox]::show('���⭨� Windows 㤠��� �� ��⥬�. �ॡ���� ��१���㧪� �� .', 'DefenderKiller By Vlado')" >nul
%ch%    {0c} �� ������ ��� ��室�.{\n #}
pause>nul
exit
) else (
%ch%    {0c} ���⭨� �� 㤠��� �� ����. ������ 㤠����� �� ࠧ.{\n #}
pause>nul && cls && goto Start
)


:OnOffDefender
if not exist "%ProgramFiles%\Windows Defender" (cls && goto Start)

sc query SecurityHealthService | find /i "RUNNING" >nul 2>&1
IF ERRORLEVEL 1 (
%ch% {0e} ����砥� ���⭨� ...{\n #}
echo.
timeout /t 1 /nobreak>nul
reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t reg_DWORD /d "0x3" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\Sense" /v "Start" /t reg_DWORD /d "0x3" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t reg_DWORD /d "0x0" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t reg_DWORD /d "0x0" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t reg_DWORD /d "0x3" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t reg_DWORD /d "0x2" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t reg_DWORD /d "0x2" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\wscsvc" /v "Start" /t reg_DWORD /d "0x2" /f >nul

reg delete "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f >nul 2>&1

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /t reg_EXPAND_SZ /d "C:\Windows\system32\SecurityHealthSystray.exe" /f >nul

powershell -command "[Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[Windows.Forms.MessageBox]::show('���⭨� Windows ����祭. �ॡ���� ��१���㧪� �� .', 'DefenderDisabler')" >nul
pause>nul && cls && goto Start
) else (
%ch% {0e} �⪫�砥� ���⭨� ...{\n #}
echo.
timeout /t 1 /nobreak>nul
reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\Sense" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t reg_DWORD /d "0x4" /f >nul
reg add "HKLM\System\CurrentControlSet\Services\wscsvc" /v "Start" /t reg_DWORD /d "0x4" /f >nul


reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t reg_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t reg_DWORD /d 1 /f >nul

reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f >nul 2>&1

powershell -command "[Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');[Windows.Forms.MessageBox]::show('���⭨� Windows �⪫�祭. �ॡ���� ��१���㧪� �� .', 'DefenderDisabler')" >nul
pause>nul && cls && goto Start
)


:Catalogs
%ch% {0e} C:\Program Files:{\n #}
if not exist "%SystemDrive%\Program Files\Windows Defender" (
%ch% {0f}C:\Program Files\Windows Defender {0a}������{\n #}
) else (
%ch% {0f}C:\Program Files\Windows Defender {4f}�� ������{\n #}
)

if not exist "%SystemDrive%\Program Files\Windows Defender Advanced Threat Protection" (
%ch% {0f}C:\Program Files\Windows Defender Advanced Threat Protection {0a}������{\n #}
) else (
%ch% {0f}C:\Program Files\Windows Defender Advanced Threat Protection {04}�� ������{\n #}
)

if not exist "%SystemDrive%\Program Files\Windows Security" (
%ch% {0f}C:\Program Files\Windows Security {0a}������{\n #}
) else (
%ch% {0f}C:\Program Files\Windows Security {04}�� ������{\n #}
)

if not exist "%SystemDrive%\Program Files\PCHealthCheck" (
%ch% {0f}C:\Program Files\PCHealthCheck {0a}������{\n #}
) else (
%ch% {0f}C:\Program Files\PCHealthCheck {04}�� ������{\n #}
)

if not exist "%SystemDrive%\Program Files\Microsoft Update Health Tools" (
%ch% {0f}C:\Program Files\Microsoft Update Health Tools {0a}������{\n #}
) else (
%ch% {0f}C:\Program Files\Microsoft Update Health Tools {04}�� ������{\n #}
)

echo.
%ch% {0e} C:\Program Files (^x86^):{\n #}
if not exist "%ProgramFiles(x86)%\Windows Defender" (
%ch% {0f}C:\Program Files (^x86^)\Windows Defender {0a}������{\n #}
) else (
%ch% {0f}C:\Program Files (^x86^)\Windows Defender {04}�� ������{\n #}
)

if not exist "%ProgramFiles(x86)%\Windows Defender Advanced Threat Protection" (
%ch% {0f}C:\Program Files (^x86^)\Windows Defender Advanced Threat Protection {0a}������{\n #}
) else (
%ch% {0f}C:\Program Files (^x86^)\Windows Defender Advanced Threat Protection {04}�� ������{\n #}
)

echo.
%ch% {0e} C:\ProgramData\Microsoft:{\n #}

if not exist "%AllUsersProfile%\Microsoft\Windows Defender" (
%ch% {0f}C:\ProgramData\Microsoft\Windows Defender {0a}������{\n #}
) else (
%ch% {0f}C:\ProgramData\Microsoft\Windows Defender {04}�� ������{\n #}
)

if not exist "%AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection" (
%ch% {0f}C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection {0a}������{\n #}
) else (
%ch% {0f}C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection {04}�� ������{\n #}
)

if not exist "%AllUsersProfile%\Microsoft\Windows Security Health" (
%ch% {0f}C:\ProgramData\Microsoft\Windows Security Health {0a}������{\n #}
) else (
%ch% {0f}C:\ProgramData\Microsoft\Windows Security Health {04}�� ������{\n #}
)
echo.

%ch% {0e} WindowsDefenderApplicationGuard.wim:{\n #}
if not exist "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim" (
%ch% {0f}C:\Windows\Containers\WindowsDefenderApplicationGuard.wim {0a}������{\n #}
) else (
%ch% {0f}C:\Windows\Containers\WindowsDefenderApplicationGuard.wim {04}�� ������{\n #}
)

if not exist "%SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim" (
%ch% {0f}C:\Windows\Containers\serviced\WindowsDefenderApplicationGuard.wim {0a}������{\n #}
) else (
%ch% {0f}C:\Windows\Containers\serviced\WindowsDefenderApplicationGuard.wim {04}�� ������{\n #}
)

echo.
%ch% {08} �� ������ ��� ������{\n #}
pause>nul && cls && goto Start


:ChangeLog
rem ChangeLog
%ch% {0c} v. 8 - 8.5{\n #}
echo 8.5
echo - ��������� �஢�ઠ ��। ����᪮�, �⮡� "���� � ॠ�쭮� �६���" �뫠 �⪫�祭� - ��� �⮣� �� ᪠砥��� FuckDefender
echo --- ⥯��� �� �ணࠬ�� - ���� ᠬ����⥫��� 䠩� ��� ����ᨬ��⥩ �冷� (����㯭� ⠪�� ��䫠�� �����)
echo --- ��������� ���ᠭ�� � ����ᠬ
echo --- ��������� �஢�ઠ �� ����稥 ���⭨�� ��᫥ 㤠�����
echo --- �ࠢ�� ����䥩�
echo --- ��������� �஢�ઠ �� ����稥 ����������
echo -- ��������� 㤠�����/����⠭������� �ਫ������ '���������� Windows' (��뢠�� ���箪 �� ���� ���)
echo -- ��������� �ࠢ�� � ࠧࠡ��稪�
echo -- ��������� �஢�ઠ �� ����稥 ��⠭��������� Unlocker'a � ��⥬� ��-��������� ���䫨�� 㤠�����
echo - ������� ����, ࠧ���, �஧�筮��� � 梥� ��������� �ணࠬ��
%ch% {0c} v. 7 - 7.2{\n #}
echo - �ࠢ�� �ணࠬ��
%ch% {0c} v. 6 - 6.1{\n #}
echo -- �������� ����� NisSrv - Microsoft Network Realtime Inspection Service
echo - �ࠢ��쭮� 㤠����� WindowsDefenderApplicationGuard.wim
echo - ��������� ����������� 㢨���� ⥪�饥 ���ﭨ� ��⠫���� ���⭨��
echo - ��������� ��⠫��� ��� 㤠����� ��� ��᫥���� ���ᨩ Windows 10 � 11
echo - ��������� ����� ��⥫쭮� 㤠����� ����� �� �����஢騪� � �⪫�祭�� ����ᮢ
echo - �������� �஢�ન �� ����稥 ���⭨��
%ch% {0c} v. 5.2{\n #}
echo - ��������� �⪫�祭��/����祭�� ���⭨�� ��� 㤠�����. �ॡ���� ��१���㧪� ��
%ch% {0c} v. 5.1{\n #}
echo - ����� ���ᨩ �ணࠬ�� �������� � 26 �� "��������" , ��稭�� � 1 ���ᨨ
echo - ��ࠢ��� ��� ����䥩�, ��������騩 ��-�� �����६������ ����᪠ ⢨��� � �ணࠬ��
%ch% {0c} v. 5{\n #}
echo - ������訥 �ࠢ�� ����䥩� � ���⨥ �������� ���� �ਫ������
echo - smartscreen ⥯��� �⪫�砥��� � �१ ॥���
echo - ��⥭� �����, ����� FuckWD ����⥪⨫�� ��⨢���ᠬ� � 㤠����� ����室��� �ந������� ��� ����
%ch% {0c} v. 4{\n #}
echo - ���ࠢ��� changelog
echo - ��������� �஢�ઠ ��। 㤠������ �� ����稥 ���⭨�� � ��⥬� � �뢮� ᮮ⢥�����饣� ᮮ�饭��
echo - ������� ࠧ��� �������� ����, ��᪮��� �� ���� ⥪�� ���頫��
echo - ��������� 㤠����� ����� � ����砬� ���⭨��
echo - �����०�� smartscreen
echo - ��������� �஢�ઠ �� ���ﭨ� ���⭨�� � �⪫�祭�� ���⭨��, �᫨ �� �⪫�祭
%ch% {0c} v. 3{\n #}
echo - �������� ChangeLog
echo - ��������� �஢�ઠ, �᫨ ��⠭������ Windows 11 - ��室�� �������⥫�� ࠧ FuckDefender
echo - ��������� �஢�ઠ �� �ࠢ� TI ��। 㤠������
echo - ������訥 �ࠢ�� ����䥩�, ���� � ���ᠭ�� �㭪権
echo - ������� ᯮᮡ ����祭�� ���ଠ樨 � ����饭��� ������ ���⭨��
echo - 㤠���� ��譨� ��६����
%ch% {0c} v. 2{\n #}
echo - ��������� 梥�
echo - ������� ���室 � ����祭�� ���������⨢��� �ࠢ �� ����᪥, �᫨ ����祭 UAC
%ch% {0c} v. 1{\n #}
echo - ᮧ�����
echo.
%ch% {08} �� ������ ��� ������{\n #}
pause>nul && cls && goto Start


:SecHealth
Set "UAC="
for /f "tokens=3" %%I in (' reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" 2^>nul ') do set /a "UAC=%%I"
if "%UAC%"=="1" (
%ch% {0c} � ��� ����祭 UAC{\n #}
%ch% {0f} ��� �ᯮ�짮����� ������ �㭪樨 �ॡ����, �⮡� UAC �� �몫�祭{\n #} 
pause>nul && cls && goto Start)
ConX hide
NSudoLC.exe -U:C -wait SecHealth.bat
ConX Show
@cmdow @ /ACT
cls && goto Start


:Credits
%ch% {0E}DefenderKiller{\n #}
echo.
%ch% {0A}������ �⨫�� �������� 㤠���� ���⭨� Windows {0c}��������⭮. {08}[�� ����� ������� ��⥬��� �㭪権]{\n #}
echo.
%ch% {0b}��騩 ���:{\n #}
%ch% {0E}����⢥���, ������� � ⮬, �� ��� �������� ��᫥ 㤠����� �⠭�� ������� � �� ������ �� 100 ���஢ ��᫠ ���.{\n #}
%ch% {0E}������, �筮 ����� �⢥ত���, �� �� ��������� �� ��譨� ����ᮢ ���⭨��, ����������� ����ﭭ� ᪠��஢����� � 䮭�.{\n #}
%ch% {0E}�� �������� ������� ᮪���� ���ॡ����� ��� � ᭨���� ����㧪� �� ��, �� ����⨢�� ᪠����� �� ��饬 ���짮����� ��{\n #}
echo.
%ch% {0b}�� 㤠����� � ��� �� ࠡ�⠥�:{\n #}
%ch% {0E}��������� ⮫쪮 ��⠫��� (�����) ���⭨��, �� ���ࠣ���� ������� ��譨� �����. � ⠪��:{\n #}
%ch% {0E}��㦡�, ����� � �����஢騪�, ���⥪�⭮� ���� ���⭨��, �⪫������ �ࠩ���.{\n #}
%ch% {0E}�� ����� �� ���ࠣ����� ��㣨� �㭪権 Windows{\n #}
%ch% {0E}��᫥ 㤠����� ����室��� ��१���㧨�� ��, �⮡� �� ��������� ���㯨�� � ᨫ�{\n #}
echo.
%ch% {0b}Credits:{\n #}
%ch% {0f}���ࠡ��稪 - Vlado{\n #}
%ch% {0f}�ணࠬ�� FuckWindowsDefender - XpucT{\n #}
%ch% {0f}������ � ���஢���� � ���襭�� �ணࠬ�� - Flamer{\n #}
pause>nul && cls && goto Start


:CheckOff
Mode 90,15
Color 0f
echo ��� ⮣�, �⮡� ���⭨� �� 㤠��� ࠡ�稥 䠩�� �ணࠬ��, ����室��� �⪫����
echo.
reg query "HKLM\Software\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" || echo - ����� � ॠ�쭮� �६���
echo - ������� �����
echo - ��⮬������ ��ࠢ�� ��ࠧ殢
echo - ����� �� ��������
start windowsdefender://threat
echo.
echo ��᫥ �⪫�祭�� ������ ���� �������
pause>nul && cls && goto Start


:DownLoadFile
Color 04
ping www.google.nl -n 1 -w 1000 |>nul find /i "TTL=" || echo    ���������� ᪠��� �ॡ㥬� 䠩��, ��� ���୥� ᮥ�������. �ணࠬ�� �� ����� ࠡ���� ��� ���୥�. && pause && exit
md %SystemDrive%\DefenderKiller >nul 2>&1
cd /d "%SystemDrive%\DefenderKiller"
Mode 100,6
Color 0a
echo                                ���୥� ᮥ������� ��⠭������ ...
echo.
echo                     ���稢����� ����室��� 䠩�� � ���� �஢�ઠ ���������� ...

curl -g -k -L -# -o "%tmp%\nircmd.zip" https://www.nirsoft.net/utils/nircmd-x64.zip >nul 2>&1
for /f %%i in ('dir/a-d/b "%tmp%\nircmd.zip"') do (
mshta "javascript:with(new ActiveXObject('Shell.Application')){nameSpace('C:\\DefenderKiller').copyHere(nameSpace('%tmp:\=\\%\\%%i').items(),5652)};close()"
del %tmp%\%%i
)
curl -g -k -L -# -o "%tmp%\nsudo.zip" https://github.com/M2Team/NSudo/releases/download/9.0-Preview1/NSudo_9.0_Preview1_9.0.2676.0.zip >nul 2>&1
for /f %%i in ('dir/a-d/b "%tmp%\nsudo.zip"') do (
mshta "javascript:with(new ActiveXObject('Shell.Application')){nameSpace('C:\\DefenderKiller').copyHere(nameSpace('%tmp:\=\\%\\%%i').items(),5652)};close()"
del %tmp%\%%i
)

curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\cecho.exe" "https://download1349.mediafire.com/1sj94et5bhtg/d6k2wex2qp2jqnp/cecho.exe" >nul 2>&1
curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\SecHealth.bat" "https://download939.mediafire.com/34aryb1osfgg/lpo1b07wn628ck3/SecHealth.bat" >nul 2>&1
curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\TI.exe" "https://download1502.mediafire.com/g9otswtp7oig/njc4jepwlu4i9oo/TI.exe" >nul 2>&1
curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\ConX.exe" "https://download1491.mediafire.com/42q5f5buw1ug/qxlplyx2nguf1p1/ConX.exe" >nul 2>&1
curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\cmdow.exe" "https://raw.githubusercontent.com/ritchielawrence/cmdow/master/bin/Release/cmdow.exe" >nul 2>&1
curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\FuckDefender.exe" "https://i.getspace.eu/cloud/s/N7PPHBiL2A4SDA6/download" >nul 2>&1
curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\TrInstaller.exe" https://github.com/mspaintmsi/superUser/releases/download/v4.0.0.1/superUser64.exe >nul 2>&1

pushd x64
copy NSudoLC.exe %SystemDrive%\DefenderKiller >nul
popd
rd /s /q ARM64 >nul 2>&1
rd /s /q Win32 >nul 2>&1
rd /s /q x64 >nul 2>&1
del /q People.txt >nul 2>&1
del /q nircmdc.exe >nul 2>&1
del /q NirCmd.chm >nul 2>&1
del /q License.txt >nul 2>&1
del /q MoPluginReadme.txt >nul 2>&1
del /q MoPluginReadme.zh-Hans.txt >nul 2>&1
goto:eof

:CheckUpdate
rem Version
set Version=8.3
curl -g -k -L -# -o "%temp%\latestVersion.bat" "https://pastebin.com/raw/dnENFgmC" >nul 2>&1
call "%temp%\latestVersion.bat"
if "%Version%" lss "!latestVersion!" (
@cmdow @ /SIZ 1000 250
cls
echo.
%ch%        {0c}�� �ᯮ���� �����㠫��� ����� DefenderKiller - {0e}!Version!, {0c}������� �ணࠬ�� ��। �ᯮ�짮������{\n #}
%ch%        {0f}��᫥���� ���㠫쭠� ����� - {0a}!latestVersion!{\n #}
%ch%        {0f}�� ��� ᪠��� ��᫥���� ���㠫��� �����?{\n #}
echo.
choice /c:"12" /n /m "[1] ��  [2] ���, ���"
if !errorlevel! equ 1 (
		curl -L -o %0 "https://github.com/VladoGold/DefenderKiller/releases/latest/download/DefenderKiller.bat" >nul 2>&1
		curl -g -k -L -# -o "%SystemDrive%\DefenderKiller\SecHealth.bat" "https://github.com/VladoGold/DefenderKiller/raw/main/SecHealth.bat" >nul 2>&1
		call %0
		exit /b
		)
if !errorlevel! equ 2 ( exit )
)
goto:eof

:ModifedCMD
rem ������ ���᮫� �஧�筮�, �����塞 �� ���� � � (�������� ��� ������ TI, ���⮬�, �����⨢ ॥��� �� ����� ���筮�� ���짮��⥫� �⮩ ��⪨ �� �� ������)
rem 1 �� 㬮�砭��
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0x0" /f >nul
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "InsertMode" /t REG_DWORD /d "0x1" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "QuickEdit" /t REG_DWORD /d "0x1" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "ScreenBufferSize" /t REG_DWORD /d "0x23290078" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "WindowSize" /t REG_DWORD /d "0x1d0078" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "FontSize" /t REG_DWORD /d "0xe0000" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "FontFamily" /t REG_DWORD /d "0x36" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "FontWeight" /t REG_DWORD /d "0x190" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "FaceName" /t REG_SZ /d "Lucida Console" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "HistoryBufferSize" /t REG_DWORD /d "0x32" /f >nul 2>&1
Reg add "HKCU\Console\%%SystemRoot%%_system32_cmd.exe" /v "WindowAlpha" /t REG_DWORD /d "0xed" /f >nul 2>&1
TI.exe "%~f0" %* & exit