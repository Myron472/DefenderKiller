:: DefenderKiller by Vlado - 㤠����� � ����⠭������� Windows Defender [���⭨�� Windows]
:: �� ������, ���� � ������ ��㣮� ᯠᨡ� ����� ���� Eject - https://win10tweaker.ru/forum/profile/eject
:: https://win10tweaker.ru/forum/topic/defenderkiller | https://github.com/oatmealcookiec/DefenderKiller

:: Unlocker by Eject - https://win10tweaker.ru/forum/topic/unlocker
:: Driver by Eject ��� 㤠����� �㦡 � �ࠩ��஢
:: StopDefender - https://github.com/lab52io/StopDefender [Not Updated...]
:: NSudo - https://github.com/M2TeamArchived/NSudo/releases
:: nhmb - https://nhutils.ru/blog/nhmb/
:: Compressed2TXT - https://github.com/AveYo/Compressed2TXT
:: 7Z - https://www.7-zip.org/

:Start
	@echo off
	cls
	Title DK
	Color 0f
	chcp 866 >nul
	if not exist "%~dp0Work" echo �� ������� ࠡ��� ����� Work �冷� � �ணࠬ���, �㤥� �믮���� ��室. && timeout /t 7 /nobreak >nul && exit
	echo "%~dp0" | findstr /r "[()!]" >nul && echo ���� �� .bat ᮤ�ন� �������⨬� ᨬ����, ��ࠢ�� ���� � ������� �ணࠬ�� ����୮. && timeout /t 7 >nul && exit
	SetLocal EnableDelayedExpansion
	cd /d "%~dp0Work"
	reg query "HKU\S-1-5-19" >nul 2>&1 || nircmd elevate "%~f0" && exit

rem ��⠭���� ��६�����
	set "ch=cecho.exe"
	set "ArgNsudo="
	set "MainFolder1="
	set "MainFolder2="
	set "ProcList="
	set "DefenderKey=HKLM\Software\Policies\Microsoft\Windows Defender"

	qprocess WindowsTerminal.exe >nul 2>&1 && (
		%ch% {04} DefenderKiller ����� � ��ନ����{\n #}
		reg add "HKCU\Console\%%%%Startup" /v "DelegationConsole" /t REG_SZ /d "{B23D10C0-E52E-411E-9D5B-C09FDF709C7D}" /f >nul
		reg add "HKCU\Console\%%%%Startup" /v "DelegationTerminal" /t REG_SZ /d "{B23D10C0-E52E-411E-9D5B-C09FDF709C7D}" /f >nul
		%ch% {04} ��१������ �ணࠬ�� ��� ��ࠢ�����{\n #}&& timeout /t 7 /nobreak >nul && exit
	)

rem ��१���� �� TrustedInstaller
	if /i "%USERNAME%" neq "%COMPUTERNAME%$" NSudoLC -U:T -P:E -UseCurrentConsole %0 && exit
	
rem ����� OS
	set "NumberWin="
	for /f "tokens=4 delims=[] " %%v in ('ver') do set "NumberWin=%%v"

rem ����� � ��� �ணࠬ�� / �������. ��ࢮ� �᫮ - �ਭ�, ��஥ - ����
	set Version=14.1
	set DateProgram=30.09.24
	Mode 80,49
	nircmd win center process cmd.exe & nircmd win settext foreground "DK | v. %Version% - %DateProgram% | %NumberWin% | By Vlado"

	if exist "%SystemDrive%\latestVersion.bat" del /q "%SystemDrive%\latestVersion.bat"
	if not exist nhmb.exe %ch% {0c} ��� 䠩�� nhmb.exe � ����� Work.{\n} ��४�砩� ����� ��娢 DefenderKiller.{\n #}&& timeout /t 5 >nul && exit
	if not exist 7z.exe %ch% {0c} ��� 䠩�� 7z.exe � ����� Work. ��४�砩� ����� ��娢 DefenderKiller{\n #}&& timeout /t 7 >nul && exit
	if not exist DKTools.zip %ch% {0c} ��� 䠩�� DKTools.zip � ����� Work. ��४�砩� ����� ��娢 DefenderKiller{\n #}&& timeout /t 7 >nul && exit
	
rem ��㬥�� ��� NSUDO � ����ᨬ��� �� ���ﭨ� UAC [C - �᫨ �⪫��� / E - �᫨ ������]
	reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" | find /i "0x0" >nul 2>&1 && set "ArgNsudo=C" || set "ArgNsudo=E"

rem ������ / �㦡�, �ࠩ���
	for /f "skip=3 tokens=1" %%a in ('tasklist') do set "ProcList=!ProcList! %%a "
	for %%p in (SmartScreen MsMpEng SgrmBroker MsSense uhssvc NisSrv MpCmdRun MPSigStub SecurityHealthSystray SecurityHealthService SecurityHealthHost MpDefenderCoreService) do (
	if "!ProcList!"=="!ProcList:%%p.exe =!" (set "%%~pP=0a") else (set "%%~pP=0c"))

	for %%x in (WinDefend MDCoreSvc WdNisSvc Sense wscsvc SgrmBroker SecurityHealthService webthreatdefsvc webthreatdefusersvc WdNisDrv WdBoot WdFilter SgrmAgent MsSecWfp MsSecFlt MsSecCore) do reg query "HKLM\System\CurrentControlSet\Services\%%~x" >nul 2>&1 && set "%%~x=0c" || set "%%~x=0a"
	
rem 2 ������ �����
	if exist "%AllUsersProfile%\Microsoft\Windows Defender" (set "MainFolder1=04") else (set "MainFolder1=0a")
	if exist "%SystemDrive%\Program Files\Windows Defender" (set "MainFolder2=04") else (set "MainFolder2=0a")

rem ���� � ����� ����� �����஢騪�
	set PathTask=%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender
	if not exist "%PathTask%\Windows Defender Cache Maintenance" (set "Maintenance=0a") else (set "Maintenance=0c")
	if not exist "%PathTask%\Windows Defender Scheduled Scan" (set "Scan=0a") else (set "Scan=0c")
	if not exist "%PathTask%\Windows Defender Verification" (set "Verification=0a") else (set "Verification=0c")
	if not exist "%PathTask%\Windows Defender Cleanup" (set "Cleanup=0a") else (set "Cleanup=0c")

	%ch% {09}������:{\n #}
	%ch% {%MpCmdRunP%} MpCmdRun {%SmartScreenP%}SmartScreen {%SecurityHealthSystrayP%}SecurityHealthSystray {%SecurityHealthHostP%}SecurityHealthHost {%uhssvcP%}uhssvc{\n #}
	
	%ch% {\n}{09}��㦡� � �� ������:{\n #}
	%ch% {%WinDefend%} WinDefend {08} ^> {%MsMpEngP%}MsMpEng.exe{\n #}
	%ch% {%MDCoreSvc%} MDCoreSvc {08} ^> {%MpDefenderCoreServiceP%}MpDefenderCoreService.exe{\n #}
	%ch% {%WdNisSvc%} WdNisSvc {08}  ^>{%NisSrvP%} NisSrv.exe{\n #}
	%ch% {%Sense%} Sense {08}     ^> {%MsSenseP%}MsSense.exe{\n #}
	%ch% {%SgrmBroker%} SgrmBroker {08}^> {%SgrmBrokerP%}SgrmBroker.exe{\n #}
	%ch% {%SecurityHealthService%} SecHealthS {08}^> {%SecurityHealthServiceP%}SecurityHealthService.exe{\n #}
	%ch% {\n}{%webthreatdefsvc%} webthreatdefsvc {%webthreatdefusersvc%}webthreatdefusersvc {%wscsvc%}wscsvc{\n #}
	
	%ch% {\n}{09}�ࠩ���:{\n #}
	%ch% {%WdFilter%} WdFilter {%WdBoot%}WdBoot {%WdNisDrv%}WdNisDrv {%MsSecWfp%}MsSecWfp {%MsSecFlt%}MsSecFlt {%MsSecCore%}MsSecCore {%SgrmAgent%}SgrmAgent{\n #}
	
	%ch% {\n}{09}������ �����:{\n #}
	%ch% {%MainFolder1%} %AllUsersProfile%\Microsoft\Windows Defender{\n #}
	%ch% {%MainFolder2%} %SystemDrive%\Program Files\Windows Defender{\n #}
	
	%ch% {\n}{09}������� � �����஢騪�:{\n #}
	%ch% {%Maintenance%} Cache Maintenance{#}{08} ^| {%Scan%}Scheduled Scan{#} {08}^| {%Verification%}Verification{#} {08}^| {%Cleanup%}Cleanup{\n #}

	%ch% {\n}{0f} 1 - {04}������� ���⭨�{\n #}
	%ch% {0f} 2 - {08}�஢���� ���ﭨ� ����� � 䠩��� ���⭨��{\n #}
	%ch% {0f} 3 - {08}�஢���� ����������{\n #}
	%ch% {0f} 4 - {0e}����⠭�������, {0c}㤠����� ������᭮�� �� ��᪠{\n #}
	%ch% {0f} 5 - {0b}Discord-�ࢥ�{\n #}
	%ch% {\n}

	set "input="
	set /p input=">>>"
	if not defined input  goto Start
	if "%input%"=="1"  cls && goto DeleteDefender
	if "%input%"=="2"  cls && goto Catalogs
	if "%input%"=="3"  cls && goto CheckUpdate
	if "%input%"=="4"  cls && goto ManageDefender
	if "%input%"=="5"  NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c start https://discord.gg/X5VBmJB3aE & goto Start
	cls & %ch%    {0c}����� �㭪樨 �� �������{\n #}
	timeout /t 2 >nul && goto Start

:DeleteDefender
	call :AddExclusion
	7z x -aoa -bso0 -bsp1 "DKTools.zip" -p"DK"
	
rem ��������� ���� vbs
	reg delete "HKLM\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /f >nul 2>&1
	set "sFreeSize=" & set "sFreeSize1=" & set "CountFreeSize="
	echo Set objWMIService = GetObject("winmgmts:\\.\root\cimv2") > DiskSpace.vbs
	echo Set colItems = objWMIService.ExecQuery^ _ >> DiskSpace.vbs
	echo    ("Select FreeSpace from Win32_LogicalDisk Where DeviceID = '%SystemDrive%'") >> DiskSpace.vbs
	echo For Each objItem in colItems >> DiskSpace.vbs
	echo    FreeMegaBytes = CLng(objItem.FreeSpace / 1048576) >> DiskSpace.vbs
	echo Next >> DiskSpace.vbs
	echo WScript.Echo FreeMegaBytes >> DiskSpace.vbs
	for /f %%i in ('cscript //nologo DiskSpace.vbs') do set sFreeSize=%%i

	sc create DKServicesRemover type= kernel binPath= "%~dp0Work\ServiceWDDel.sys" >nul 2>&1

rem �ய�� Unlocker, �᫨ ��� ����� Defender
		if not exist "%AllUsersProfile%\Microsoft\Windows Defender" (
    if not exist "%SystemDrive%\Program Files\Windows Defender" (
        goto SkipUnlocker
		)
	)

rem �ய�᪠�� ᮧ����� �����, �᫨ ��� ��⪨ [�뫮 㤠����� ��� �� ࠧ]
	reg query "HKLM\Software\Microsoft\Windows Advanced Threat Protection" >nul 2>&1 || goto StartUnlockerAndSkipBackup
	
	%ch% {0c} �ᯮ���� �ணࠬ��, �� �ਭ�����, �� 㤠��� ��������� ������᭮��...{\n #}
	%ch% {04} �� �ᯮ���� DK, �᫨ �� �������� ��祬 �� �㦭�^^!{\n #}{\n #}
	
	if not exist "%SystemDrive%\WDefenderBackup" (
			nhmb "������� १�ࢭ�� �����?\n\n����� �ய�����, �᫨ �� �������� Windows � ���⭨� �� �㦥� � ���饬." "Backup" "Warning|YesNo|DefButton1"
			if errorlevel 7 goto StartUnlockerAndSkipBackup
			if errorlevel 6 call :CreateBackupDefender)
			
rem ��᫥ /unlock � ᮧ����� ����� ������ ����� �ਫ������. ���� �㦡� ��ࠢ��� ��.
	net start WinDefend >nul 2>&1
	sc start WinDefend >nul 2>&1

:StartUnlockerAndSkipBackup
	sc query WinDefend >nul 2>&1 && (net start DKServicesRemover || %ch%    {0c} �ࠩ��� �� �����⨫��{\n #}{0c}    �몫��� SecureBoot � BIOS � ������ 㤠�����{\n #}{\n #})
	
	REM NSudoLC -U:P -ShowWindowMode:Hide -Wait UnlockerUnpack.bat
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide -Wait cmd.exe /c taskkill /f /im explorer.exe

	%ch%    {0c} ����塞 Unlocker'�� by Eject{\n #}
	%ch%    {08} �᫨ ����� ���� ����� - ��१������ ��{\n #}{\n #}
	Unlocker /DeleteDefender

rem �஢��塞 ��᫥ 㤠�����, ��⠫��� �� �����. �᫨ ��⠫��� - �믮��塞 ����୮� 㤠����� � ������� Unlocker
	for %%d in ("%AllUsersProfile%\Microsoft\Windows Security Health", "%AllUsersProfile%\Microsoft\Windows Defender", "%AllUsersProfile%\Microsoft\Windows Defender", "%AllUsersProfile%\Microsoft\Windows Defender") do (
		if exist %%d (
			%ch%    {08} ����� %%d �� 㤠������{\n #}
			%ch%    {0c} ����୮� 㤠�����{\n #}{\n #}
			timeout /t 2 /nobreak >nul
			Unlocker /DeleteDefender
		)
	)

	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c start explorer.exe
	
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
:SkipUnlocker
	%ch%    {03} �믮������ 㤠�����{\n #}{\n #}
	sc query DKServicesRemover | find /i "RUNNING" >nul 2>&1 || (sc query WinDefend >nul 2>&1 && (net start DKServicesRemover || %ch%    {0c} �ࠩ��� �� �����⨫��{\n #}{0c}    �몫��� SecureBoot � BIOS � ������ 㤠�����{\n #}{\n #}))

(
rem �������� �����
	for %%d in ("Windows Defender" "Windows Defender Advanced Threat Protection" "Windows Security Health" "Storage Health") do (
		rd /s /q "%AllUsersProfile%\Microsoft\%%~d")

	for %%d in ("Windows Defender" "Windows Defender Sleep" "Windows Defender Advanced Threat Protection" "Windows Security" "PCHealthCheck" "Microsoft Update Health Tools") do (
		rd /s /q "%SystemDrive%\Program Files\%%~d")

	for %%d in ("Windows Defender" "Windows Defender Advanced Threat Protection") do (
		rd /s /q "%SystemDrive%\Program Files (x86)\%%~d")

	for %%d in ("HealthAttestationClient" "SecurityHealth" "WebThreatDefSvc" "Sgrm") do (
		rd /s /q "%SystemRoot%\System32\%%~d")
	
	rd /s /q "%SystemRoot%\security\database"
	rd /s /q "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender"
	rd /s /q "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance"
	rd /s /q "%SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender"
	rd /s /q "%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender"
	rd /s /q "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\Defender"
	rd /s /q "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\DefenderPerformance"
	
rem ��२��������� 䠩���, �� 㤠����� / SmartScreen.exe
	ren "%SystemRoot%\System32\SecurityHealthService.exe" "SecurityHealthService.exe_fuck"
	ren "%SystemRoot%\System32\smartscreenps.dll" smartscreenps.dll_fuck
	ren "%SystemRoot%\System32\wscapi.dll" wscapi.dll_fuck
	ren "%SystemRoot%\System32\smartscreen.exe" "smartscreen.exedel"

	del /f /q "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim"
	del /f /q "%SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim"

	taskkill /f /im smartscreen.exe

	for %%f in (
		"SecurityHealthService.exe" "SecurityHealthService.exe_fuck" "SecurityHealthSystray.exe" "SecurityHealthHost.exe"
		"SecurityHealthAgent.dll" "SecurityHealthSSO.dll" "SecurityHealthProxyStub.dll" "smartscreen.dll" "wscisvif.dll"
		"wscproxystub.dll" "smartscreenps.dll" "smartscreenps.dll_fuck" "wscapi.dll" "wscapi.dll_fuck"
		"windowsdefenderapplicationguardcsp.dll" "wscsvc.dll" "SecurityHealthCore.dll"
		"SecurityHealthSsoUdk.dll" "SecurityHealthUdk.dll" "smartscreen.exe" "smartscreen.exedel"
	) do del /f /q "%SystemRoot%\System32\%%~f"
	
	for %%f in (
		"smartscreen.dll" "wscisvif.dll" "wscproxystub.dll" "smartscreenps.dll" "wscapi.dll"
		"windowsdefenderapplicationguardcsp.dll"
	) do del /f /q "%SystemRoot%\SysWOW64\%%~f"

rem ��㦡� / �ࠩ���
	for %%x in (WinDefend MDCoreSvc WdNisSvc Sense wscsvc SgrmBroker SecurityHealthService webthreatdefsvc webthreatdefusersvc WdNisDrv WdBoot WdFilter SgrmAgent MsSecWfp MsSecFlt MsSecCore) do (
		sc stop "%%~x"
		sc delete "%%~x"
		reg delete "HKLM\System\CurrentControlset\Services\%%~x" /f
	)
	rd /s /q "%SystemRoot%\System32\drivers\wd"
	
rem �����஢騪 / ������
	for %%s in (
	"Windows Defender Cache Maintenance" "Windows Defender Cleanup" "Windows Defender Scheduled Scan" "Windows Defender Verification"
	) do (
		schtasks /Delete /TN "Microsoft\Windows\Windows Defender\%%~s" /f
	)
	schtasks /Delete /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /f

	reg delete "HKLM\Software\Microsoft\Windows Defender" /f
	reg delete "HKLM\Software\Microsoft\Windows Defender Security Center" /f
	reg delete "HKLM\Software\Microsoft\Windows Advanced Threat Protection" /f
	reg delete "HKLM\Software\Microsoft\Windows Security Health" /f

	reg delete "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderApiLogger" /f
	reg delete "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderAuditLogger" /f

rem ���⥪�⭮� ����
	reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
	reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
	reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
	reg delete "HKLM\Software\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f

rem ��⮧����
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" /f
	
rem �������� ������ � ��ࠬ����
	reg delete "HKLM\Software\Microsoft\SystemSettings\SettingId\SystemSettings_WindowsDefender_UseWindowsDefender" /f
	
rem �������� ��ୠ��� ᮡ�⨩
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/WHC" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\NIS-Driver-WFP/Diagnostic" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" /f

rem �������� �� ������ �ࠢ����� ����� Windows Defender [Windows 8.1]
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" /f
	reg delete "HKCR\CLSID\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" /f
	
) >nul 2>&1
	
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

:FinishDelete
rem �᢮����񭭮� ���� �� ��᪥
	for /f %%i in ('cscript //nologo DiskSpace.vbs') do set sFreeSize1=%%i
	set /a CountFreeSize=%sFreeSize1% - %sFreeSize%
	if defined CountFreeSize %ch%    {0e} %CountFreeSize% MB {0f}�᢮������� �� ��᪥ %SystemDrive%\ ��᫥ 㤠�����{\n #}
	
rem ����塞 Unlocker, ��� �ࠩ��� � ��⠫�� 䠩��. �ࠩ��� ����⠭������ ᠬ, �᫨ �ᯮ������ ��⠭����� IObitUnlocker
(
	del /q Unlocker.exe DiskSpace.vbs LGPO.exe UnlockerUnpack.bat ServiceWDDel.sys DelServ.sys
	sc stop DKServicesRemover
	sc delete DKServicesRemover
) >nul 2>&1

	%ch%    {08} �ਥ������� �� ���ﭨ� ����� {0f}- ��� 2 {08}� ������� ����{\n #}
	reg query "HKLM\System\CurrentControlset\Services\WinDefend" >nul 2>&1 && %ch%    {04} ��㦡� WinDefend �� 㤠������{\n #}
	%ch%    {08} ������᭮��� �� ��᪠ ����� 㤠���� � �㭪� 4{\n #}
	%ch%    {08} ������ ���� ������� ��� ������ � ������� ����{\n #}
	pause>nul && goto Start
	
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
:ManageDefender
	cls
	2>nul reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" | find /i "windowsdefender" >nul 2>&1 && set "HideSettigns={0a}����" || set "HideSettigns={0c}�⮡ࠦ�����"

	%ch% {\n}{08} 1 - {0a}����⠭����� ���⭨� �� �����{\n #}
	%ch% {08} 2 - ������� �ਫ������ ������᭮��� � ���⢥ত����� {08}[���箪 � ��᪥]{\n #}
	%ch% {08} 3 - ��࠭�� ������᭮��� � ��ࠬ���� %HideSettigns%{\n #}
	%ch% {08} 4 - ������� ����� ���⭨�� �� �࠭���� WinSxS � ���⢥ত�����{\n #}
	%ch% {\n}{0e} [Enter]{#} - {08}�������� � ������� ����{\n #}
	%ch% {\n}
	set "input="
	set /p input=">>>"
	if not defined input	  goto Start
	if "%input%"=="1"  goto RestoreDefender
	if "%input%"=="2"  goto SecHealthUI
	if "%input%"=="3"  call :HideShowInSettings
	if "%input%"=="4"  goto WinSxSFolders
	goto ManageDefender
	
:WinSxSFolders
	%ch% {\n} �᫨ �� ᮧ�������� १�ࢭ�� �����, 㤠����� ����� �� �࠭���� WinSxS ᫮���� ���������� Windows{\n #}
	%ch% {08} 1.{#} {0c}������� �����{\n #}
	%ch% {08} 2.{#} {08}�⬥��{\n #}
	choice /c 12 /n /m " "
	if errorlevel 2 goto ManageDefender
	
	for %%i in (windows-defender, windows-senseclient-service, windows-dynamic-image) do (
			for /f "usebackq delims=" %%d In (`2^>nul dir "%SystemRoot%\WinSxS\*%%i*" /S /B /A:D`) do rd /s /q "%%d" >nul 2>&1
	)
	goto ManageDefender

:HideShowInSettings
	set "Settings="
	set "NewSettings="
	
	for /f "skip=2 tokens=3" %%i in ('reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility 2^>nul') do set "Settings=%%i"
	if not defined Settings (
		reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /t REG_SZ /d "hide:windowsdefender" /f
		exit /b
	) else (

rem �᫨ ���� ⮫쪮 ���⭨� - 㤠�塞 ��ࠬ���
		if "!Settings!" equ "hide:windowsdefender" (
		reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /f >nul
		exit /b)
	
rem �᫨ ��६����� ᮤ�ন� defender, � 㤠�塞 ������ windowsdefender, ��࠭�� ��⠫�� ��࠭���
		echo !Settings! | find "defender" >nul && (
		set "Settings=!Settings:;windowsdefender=!"
		reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /t REG_SZ /d "!Settings!" /f >nul
		exit /b)

rem ���뢠�� ��࠭��� �� ��ࠬ��஢
		set "NewSettings=!Settings!"
		if "!Settings:~-1!"==";" (set "NewSettings=!Settings!windowsdefender") else (set "NewSettings=!Settings!;windowsdefender")
		reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /t REG_SZ /d "!NewSettings!" /f >nul
	)
	exit /b
	
:SecHealthUI
	set "CurrentBuild="
	for /f "tokens=2*" %%a in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "CurrentBuild" 2^>nul') do set CurrentBuild=%%b
	set /a CurrentBuild=%CurrentBuild%
	if %CurrentBuild% lss 10240 %ch%    {04} �� �ॡ���� �� ������ ���ᨨ Windows{\n #}&& timeout /t 2 /nobreak >nul && goto ManageDefender
	
rem ����砥� SID
	set "SID="
	for /f "tokens=3 delims= " %%a in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoLogonSID" 2^>nul') do set "SID=%%a"
	if not defined SID for /f "tokens=3 delims= " %%a in ('reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v "LastLoggedOnUserSID" 2^>nul') do set "SID=%%a"
	if not defined SID %ch%    {04} SID �� �� ����祭, �⬥�� 㤠����� �ਫ������{\n #}&& timeout /t 2 /nobreak >nul && goto ManageDefender
	
	%ch% {\n} ��᫥ 㤠����� �ਫ������ ���� � ����ன�� ���⭨�� �㤥� {04}����������.{\n #}
	%ch% {08} 1. {0c}������� �ਫ������{\n #}
	%ch% {08} 2. {08}�⬥��{\n #}
	choice /c 12 /n /m " "
	if errorlevel 2 goto ManageDefender
	
rem ����砥� ��� SystemApp ������᭮��� Windows [SecHealthUI] - �᭠�⪠ ��� �ࠢ����� ��⨢���᭮� �ணࠬ��� Windows Defender
	%ch% {\n #}   {03} ����塞 ������᭮��� Windows{\n #}
	set "NameSecHealth="
	for /F "usebackq delims=" %%n In (`2^>nul reg query "HKU\%SID%\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" /f "*SecHealthUI*" /k^|findstr ^H`) do set NameSecHealth=%%~nxn
	if not defined NameSecHealth %ch%    {02} �ਫ������ ������᭮��� Windows 㤠����{\n #}{\n #}&& goto AppRepSys

	%ch% {08} %NameSecHealth%{\n #}{\n #}
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\S-1-5-18\%NameSecHealth%" /f >nul
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\%SID%\%NameSecHealth%" /f >nul
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -AllUsers *SecHealthUI* | Remove-AppxPackage"
	NSudoLC -U:S -P:E -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -All *SecHealthUI* | Remove-AppxPackage -User 'S-1-5-18' -ErrorAction SilentlyContinue"
	for /f "usebackq delims=" %%n In (`2^>nul reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications" /f "*SecHealthUI*" /k^|findstr ^H`) do reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\%%~nxn" /f >nul 2>&1
rem �� ����� ����� 㤠����. ����⠭���������� ᠬ�, �᫨ ����⠭����� �ਫ������ ������᭮���.
	For /F "usebackq delims=" %%d In (`2^>nul Dir "%ProgramData%\Microsoft\Windows\AppRepository\Packages\*SecHealth*" /S /B /A:D`) do rd /s /q "%%d"
	For /F "usebackq delims=" %%d In (`2^>nul Dir "%LocalAppData%\Packages\*SecHealth*" /S /B /A:D`) do rd /s /q "%%d"

:AppRepSys
rem ����砥� ��� SystemApp AppRep [SmartScreen]
	%ch%    {03} ����塞 SmartScreen ���⭨�� Windows{\n #}
	set "NameAppRep="
	for /F "usebackq delims=" %%n In (`2^>nul reg query "HKU\%SID%\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" /f "*Apprep.ChxApp*" /k^|findstr ^H`) do set NameAppRep=%%~nxn
	if not defined NameAppRep %ch%    {02} �ਫ������ SmartScreen ���⭨�� Windows 㤠����{\n #}&& echo. && pause && goto ManageDefender

	%ch% {08} %NameAppRep%{\n #}
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\S-1-5-18\%NameAppRep%" /f >nul
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\%SID%\%NameAppRep%" /f >nul
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -AllUsers *Apprep.ChxApp* | Remove-AppxPackage"
	NSudoLC -U:S -P:E -ShowWindowMode:Hide -Wait PowerShell "Get-AppxPackage -All *Apprep.ChxApp* | Remove-AppxPackage -User 'S-1-5-18' -ErrorAction SilentlyContinue"
	for /f "usebackq delims=" %%n In (`2^>nul reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications" /f "*Apprep.ChxApp*" /k^|findstr ^H`) do reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\%%~nxn" /f >nul 2>&1
rem �� ����� ����� 㤠����, ����⠭���������� ᠬ�, �᫨ ����⠭����� �ਫ������ Apprep.ChxApp
	For /F "usebackq delims=" %%d In (`2^>nul Dir "%ProgramData%\Microsoft\Windows\AppRepository\Packages\*Apprep.ChxApp*" /S /B /A:D`) do rd /s /q "%%d"
	For /F "usebackq delims=" %%d In (`2^>nul Dir "%LocalAppData%\Packages\*Apprep.ChxApp*" /S /B /A:D`) do rd /s /q "%%d"
	
	pause && goto ManageDefender

rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
:AddExclusion
	reg query "HKLM\Software\Microsoft\Windows Advanced Threat Protection" >nul 2>&1 || set "AlreadyInExclusion=Yes" && exit /b
	
	if defined AlreadyInExclusion %ch%    {08} ��� ��������� � �᪫�祭��, �ய��{\n #}{\n #}&& exit /b
	
	%ch%    {03} ������塞 � �᪫�祭��{\n #}{\n #}
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide -Wait PowerShell "Get-PSDrive -PSProvider 'FileSystem' | ForEach-Object { Add-MpPreference -ExclusionPath $_.Root }" >nul 2>&1
	set "AlreadyInExclusion=Yes"
	timeout /t 2 /nobreak >nul
	exit /b

:AddExclusionRestore
	echo Windows Registry Editor Version 5.00 > exclusions.reg
	echo. >> exclusions.reg
	echo [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Exclusions\Paths] >> exclusions.reg

	for %%d in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist %%d:\ (
        echo "%%d:\\"=dword:00000000>> exclusions.reg)
	)
	if exist exclusions.reg reg import exclusions.reg >nul
	del /q exclusions.reg >nul 2>&1
	exit /b
		
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
:CheckUpdate
	cls
rem �஢�ઠ ������ curl � ����� Work ��� � ����� System32 ��� �஢�ન ����������
	if not exist "%SystemRoot%\System32\curl.exe" (
		if not exist "%~dp0Work\curl.exe" (
		%ch% {04} �ணࠬ�� curl �� ������� � ����� Work � � ����� System32.{\n #}
		%ch% {04} ������� �ணࠬ�� � ����� System32 ��� � Work{\n #}
		%ch% {08} ������ ����� ��� - https://curl.se/windows/{\n #}
		pause && goto Start))
	
rem �஢��塞 ����稥 ���୥� � ������塞 �ணࠬ��
	ping pastebin.com -n 1 -w 1000 |>nul find /i "TTL="|| %ch% {04} �訡�� �஢�ન, ��� ���୥�-ᮥ�������.{\n #}&& timeout /t 3 >nul && goto Start
	
	curl -g -k -L -# -o "%SystemDrive%\latestVersion.bat" "https://pastebin.com/raw/dnENFgmC" >nul 2>&1
	call "%SystemDrive%\latestVersion.bat"
	if "%Version%" lss "%latestVersion%" (cls) else (
		%ch% {0a} ���������� �� �������. � ��� ���㠫쭠� ����� {0f}- {0e}%Version%{\n #}{\n #}
		%ch% {08} ��� ������ � ������� ���� ������ ���� �������.{\n #}
		pause >nul
		goto Start
	)
	
	%ch%  {08} ������� {0e}����� �����. {08}������ ���� ������� �⮡� �������� �ணࠬ��.{\n #}
    pause>nul
    curl -g -k -L -# -o "%~dp0DefenderKillerNew.bat" "https://github.com/oatmealcookiec/MyProgramm/releases/latest/download/DefenderKiller.bat" >nul 2>&1
    if not exist "%~dp0DefenderKillerNew.bat" %ch% {\n #} {0c} ����� ����� �� �뫠 ᪠砭�.{\n #}&& pause && goto Start
    start "" NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd /c "timeout /t 2 && del /q "%~f0" && timeout /t 2 && ren "%~dp0DefenderKillerNew.bat" DefenderKiller.bat && start "" "%~dp0DefenderKiller.bat""
    exit
	
rem ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
rem ��� ��� ᮧ����� १�ࢭ�� ����� ���⭨��
rem ������塞 � �᪫�祭�� [� ᠬ�� ��⮤� ���� �஢�ઠ �� ����୮� ����������], �ᯠ���뢠�� Unlocker, ࠧ������㥬 �����, ᮧ��� १�ࢭ�� ����� ����� � 䠩��� ���⭨��.
rem �㭪�� CheckStateBackup �஢���� �������� �� ����� ��� 䠩�� ��᫥ ����஢���� ������� ����� ���⭨��.

:CreateBackupDefender
	if exist "%SystemDrive%\WDefenderBackup" rd /s /q "%SystemDrive%\WDefenderBackup"
	
	set "PathServDrive=%SystemDrive%\WDefenderBackup\ServicesDrivers"
	set "PathRegedit=%SystemDrive%\WDefenderBackup\RegEdit"
	set "PathCLSID=%SystemDrive%\WDefenderBackup\CLSID"

	md "%SystemDrive%\WDefenderBackup\Folder\WinSxS"
	md "%SystemDrive%\WDefenderBackup\Files"
	md "%SystemDrive%\WDefenderBackup\Files\System32"
	md "%SystemDrive%\WDefenderBackup\Files\SysWOW64"
	md "%SystemDrive%\WDefenderBackup\Files\Windows\Containers"
	md "%SystemDrive%\WDefenderBackup\Files\Windows\Containers\serviced"
	md "%PathServDrive%"
	md "%PathRegedit%"
	md "%PathCLSID%"

	%ch%    {09} ������ १�ࢭ�� �����{\n #}
	REM NSudoLC -U:P -ShowWindowMode:Hide -Wait UnlockerUnpack.bat
	Unlocker /unlock "%AllUsersProfile%\Microsoft\Windows Defender" "%SystemDrive%\Program Files\Windows Defender" "%SystemDrive%\Program Files (x86)\Windows Defender"

	for %%d in ("Windows Defender" "Windows Defender Advanced Threat Protection" "Windows Security Health" "Storage Health") do (
		xcopy "%AllUsersProfile%\Microsoft\%%~d" "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\%%~d" /s /e /h /y /i >nul 2>&1
	)
rem �஢�ઠ ��᫥ ᮧ����� �����
	timeout /t 2 /nobreak >nul
	call :CheckStateBackup

rem ProgramFiles / x86
	for %%d in ("Windows Defender" "Windows Defender Sleep" "Windows Defender Advanced Threat Protection" "Windows Security" "PCHealthCheck" "Microsoft Update Health Tools") do xcopy "%SystemDrive%\Program Files\%%~d" "%SystemDrive%\WDefenderBackup\Folder\Program Files\%%~d" /s /e /h /y /i >nul 2>&1
	for %%d in ("Windows Defender" "Windows Defender Advanced Threat Protection") do xcopy "%SystemDrive%\Program Files (x86)\%%~d" "%SystemDrive%\WDefenderBackup\Folder\Program Files (x86)\%%~d" /s /e /h /y /i >nul 2>&1

(
rem Windows - System32
    xcopy /s /e /h /y /i "%SystemRoot%\security\database" "%SystemDrive%\WDefenderBackup\Folder\Windows\security\database"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\HealthAttestationClient" "%SystemDrive%\WDefenderBackup\Folder\System32\HealthAttestationClient"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\SecurityHealth" "%SystemDrive%\WDefenderBackup\Folder\System32\SecurityHealth"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\WebThreatDefSvc" "%SystemDrive%\WDefenderBackup\Folder\System32\WebThreatDefSvc"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\Sgrm" "%SystemDrive%\WDefenderBackup\Folder\System32\Sgrm"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender" "%SystemDrive%\WDefenderBackup\Folder\System32\WindowsPowerShell\v1.0\Modules\Defender"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance" "%SystemDrive%\WDefenderBackup\Folder\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender" "%SystemDrive%\WDefenderBackup\Folder\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender"
    xcopy /s /e /h /y /i "%SystemRoot%\System32\drivers\wd" "%SystemDrive%\WDefenderBackup\Folder\System32\drivers\wd"

rem ����� ���⭨��
	xcopy /s /e /h /y /i "%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender" "%SystemDrive%\WDefenderBackup\Folder\System32\Tasks\Microsoft\Windows\Windows Defender"

rem SysWOW64
    xcopy /s /e /h /y /i "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\Defender" "%SystemDrive%\WDefenderBackup\Folder\SysWOW64\WindowsPowerShell\v1.0\Modules\Defender"
    xcopy /s /e /h /y /i "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\Modules\DefenderPerformance" "%SystemDrive%\WDefenderBackup\Folder\SysWOW64\WindowsPowerShell\v1.0\Modules\DefenderPerformance"
) >nul 2>&1

(
rem ����஢���� 䠩��� �� System32	/ SysWow64
	for %%f in (SecurityHealthService.exe SecurityHealthSystray.exe SecurityHealthHost.exe SecurityHealthAgent.dll SecurityHealthSSO.dll SecurityHealthProxyStub.dll smartscreen.dll wscisvif.dll wscproxystub.dll smartscreenps.dll wscapi.dll windowsdefenderapplicationguardcsp.dll wscsvc.dll SecurityHealthCore.dll SecurityHealthSsoUdk.dll SecurityHealthUdk.dll smartscreen.exe) do (
		copy /y "%SystemRoot%\System32\%%f" "%SystemDrive%\WDefenderBackup\Files\System32\")
		
	for %%f in (smartscreen.dll wscisvif.dll wscproxystub.dll smartscreenps.dll wscapi.dll windowsdefenderapplicationguardcsp.dll) do (
		copy /y "%SystemRoot%\SysWOW64\%%f" "%SystemDrive%\WDefenderBackup\Files\SysWow64\")

	copy /y "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim" "%SystemDrive%\WDefenderBackup\Files\Windows\Containers\"
	copy /y "%SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim" "%SystemDrive%\WDefenderBackup\Files\Windows\Containers\serviced"
) >nul 2>&1

	for /d %%i in ("%SystemRoot%\WinSxS\*windows-defender*") do xcopy "%%i" "%SystemDrive%\WDefenderBackup\Folder\WinSxS\%%~nxi" /I /E /H /Y >nul 2>&1
	for /d %%i in ("%SystemRoot%\WinSxS\*windows-senseclient-service*") do xcopy "%%i" "%SystemDrive%\WDefenderBackup\Folder\WinSxS\%%~nxi" /I /E /H /Y >nul 2>&1
	for /d %%i in ("%SystemRoot%\WinSxS\*windows-dynamic-image*") do xcopy "%%i" "%SystemDrive%\WDefenderBackup\Folder\WinSxS\%%~nxi" /I /E /H /Y >nul 2>&1

rem ��㦡� / �ࠩ���
	for %%x in (SecurityHealthService Sense WdNisSvc WinDefend wscsvc SgrmBroker webthreatdefsvc webthreatdefusersvc WdNisDrv WdBoot WdFilter SgrmAgent MsSecWfp MsSecFlt MsSecCore MDCoreSvc) do reg export "HKLM\System\CurrentControlSet\Services\%%x" "%PathServDrive%\%%x.reg" >nul 2>&1

(
rem ��ᯮ�� ��⮪ ॥���
	reg export "HKCR\*\shellex\ContextMenuHandlers\EPP" "%PathRegedit%\1.reg"
	reg export "HKCR\Directory\shellex\ContextMenuHandlers\EPP" "%PathRegedit%\2.reg"
	reg export "HKCR\Drive\shellex\ContextMenuHandlers\EPP" "%PathRegedit%\3.reg"
	reg export "HKLM\Software\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" "%PathRegedit%\4.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" "%PathRegedit%\5.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "%PathRegedit%\6.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" "%PathRegedit%\7.reg"
	reg export "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderApiLogger" "%PathRegedit%\8.reg"
	reg export "HKLM\System\CurrentControlset\Control\WMI\Autologger\DefenderAuditLogger" "%PathRegedit%\9.reg"
	reg export "HKLM\Software\Microsoft\Windows Defender" "%PathRegedit%\10.reg"
	reg export "HKLM\Software\Microsoft\Windows Defender Security Center" "%PathRegedit%\11.reg"
	reg export "HKLM\Software\Microsoft\Windows Advanced Threat Protection" "%PathRegedit%\12.reg"
	reg export "HKLM\Software\Microsoft\Windows Security Health" "%PathRegedit%\13.reg"
	reg export "HKLM\Software\Microsoft\SystemSettings\SettingId\SystemSettings_WindowsDefender_UseWindowsDefender" "%PathRegedit%\14.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" "%PathRegedit%\15.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/WHC" "%PathRegedit%\16.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\NIS-Driver-WFP/Diagnostic" "%PathRegedit%\17.reg"
	reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" "%PathRegedit%\18.reg"
	reg export "HKCR\CLSID\{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" "%PathRegedit%\19.reg"
) >nul 2>&1

rem ��ᯮ�� CLSID �� ��稭� �� 㤠����� � ���⪥ ॥��� �� �ᯮ�짮����� ⢨��஢ ...
	set "counter=1"
	for %%i in (08728914-3F57-4D52-9E31-49DAECA5A80A 10964DDD-6A53-4C60-917F-7B5723014344 17072F7B-9ABE-4A74-A261-1EB76B55107A 195B4D07-3DE2-4744-BBF2-D90121AE785B 2781761E-28E0-4109-99FE-B9D127C57AFE 2981a36e-f22d-11e5-9ce9-5e5517507c66 2DCD7FDB-8809-48E4-8E4F-3157C57CF987 2EF44DE8-80C9-42D9-8541-F40EF0862FA3 3213CD15-4DF2-415F-83F2-9FC58F3AEB3A 3522D7AF-4617-4237-AAD8-5860231FC9BA 361290c0-cb1b-49ae-9f3e-ba1cbe5dab35 36383E77-35C2-4B45-8277-329E4BEDF47F 3886CA90-AB09-49D1-A047-7A62D096D275 3CD3CA1E-2232-4BBF-A733-18B700409DA0 45F2C32F-ED16-4C94-8493-D72EF93A051B 4DB116D1-9B24-4DFC-946B-BFE03E852002 5ffab5c8-9a36-4b65-9fc6-fb69f451f99c 6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF 6D40A6F9-3D32-4FCB-8A86-BE992E03DC76 7E66DBEF-2474-4E82-919B-9A855F4C2FE8 82345212-6ACA-4B38-8CD7-BF9DE8ED07BD 849F5497-5C61-4023-8E10-A28F1A8C6A70 88866959-07B0-4ED8-8EF5-54BC7443D28C 8a696d12-576b-422e-9712-01b9dd84b446 8C38232E-3A45-4A27-92B0-1A16A975F669 8E67B5C5-BAD3-4263-9F80-F769D50884F7 A2D75874-6750-4931-94C1-C99D3BC9D0C7 a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d A7C452EF-8E9F-42EB-9F2B-245613CA0DC9 C8DFF91D-B243-4797-BAE6-C461B65EDED3 D5F7E36B-5B38-445D-A50F-439B8FCBB87A DACA056E-216A-4FD1-84A6-C306A017ECEC DBF393FC-230C-46CC-8A85-E9C599A81EFB E041C90B-68BA-42C9-991E-477B73A75C90 E476E4C0-409C-43CD-BBC0-5905B4138494 F2102C37-90C3-450C-B3F6-92BE1693BDF2 F80FC80C-6A04-46FB-8555-D769E334E9FC FEEE9C23-C4E2-4A34-8C73-FE8F9786C8B4) do (
		reg export "HKCR\CLSID\{%%i}" "%PathCLSID%\!counter!.reg" >nul 2>&1
		set /a counter+=1
	)

rem ��ᯮ�� CLSID �� WOW6432Node
	for %%i in (17072F7B-9ABE-4A74-A261-1EB76B55107A 2781761E-28E0-4109-99FE-B9D127C57AFE 2981a36e-f22d-11e5-9ce9-5e5517507c66 7E66DBEF-2474-4E82-919B-9A855F4C2FE8 8C38232E-3A45-4A27-92B0-1A16A975F669 D5F7E36B-5B38-445D-A50F-439B8FCBB87A F2102C37-90C3-450C-B3F6-92BE1693BDF2 F80FC80C-6A04-46FB-8555-D769E334E9FC) do (
		reg export "HKCR\WOW6432Node\CLSID\{%%i}" "%PathCLSID%\W64!counter!.reg" >nul 2>&1
		set /a counter+=1
	)

	reg export "HKCR\windowsdefender" "%PathCLSID%\windowsdefender.reg" >nul 2>&1
	reg export "HKCR\WdMam" "%PathCLSID%\WdMam.reg" >nul 2>&1

	%ch%    {08} ����� ᮧ���� � %SystemDrive%\WDefenderBackup{\n #}{\n #}
	exit /b

:RestoreDefender
rem ��� ���४⭮�� �⮡ࠦ���� ����������� ����, �.�. �ணࠬ�� ����饭� �� TI
	if not exist "%SystemRoot%\System32\config\systemprofile\Desktop" md "%SystemRoot%\System32\config\systemprofile\Desktop"
	%ch% {0c} ��������, �� ��࠭��� १. ����� �뫠 ᮧ���� �� �⮩ �� ���ᨨ Windows{\n #}
	
rem �롮� ����� � �஢�ઠ ��࠭��� ����� �� ���४⭮��� १�ࢭ�� �����
	set "BackupFolder="
	for /f %%a in ('powershell -c "(New-Object -COM 'Shell.Application').BrowseForFolder(0, '�롥�� ����� WDefenderBackup � ࠭�� ᮧ������ १�ࢭ�� ������ Windows Defender. ��᫥ �롮� ����� �㤥� ����� ����� � ����⠭������� ���⭨��.', 0, 0).Self.Path"') do set "BackupFolder=%%a"
	echo.
	if not defined BackupFolder goto ManageDefender
	if not exist "%BackupFolder%\Folder" %ch%    {04} ����ୠ� १�ࢭ�� �����. �롥�� �ࠢ����� १�ࢭ�� �����.{\n #}&&timeout /t 3 >nul && goto ManageDefender
	if not exist "%BackupFolder%\ServicesDrivers" %ch%    {04} ����ୠ� १�ࢭ�� �����. �롥�� �ࠢ����� १�ࢭ�� �����.{\n #}&&timeout /t 3 >nul && goto ManageDefender
	
	%ch% {03} ����⠭������� ���⭨��{\n #}{\n #}
	pushd "%BackupFolder%"
(
	copy /y "Files\System32" "%SystemRoot%\System32"
	copy /y "Files\SysWOW64" "%SystemRoot%\SysWOW64"
	copy /y "Files\Windows\Containers\WindowsDefenderApplicationGuard.wim" "%SystemRoot%\Containers\"
	copy /y "Files\Windows\Containers\serviced\WindowsDefenderApplicationGuard.wim" "%SystemRoot%\Containers\serviced"
	
	xcopy "Folder\Program Files\*" "%ProgramFiles%\" /E /H /K /Y
	xcopy "Folder\Program Files (x86)\*" "%ProgramFiles(x86)%\" /E /H /K /Y
	xcopy "Folder\ProgramData\*" "%ProgramData%\" /E /H /K /Y
	xcopy "Folder\System32\*" "%SystemRoot%\System32" /E /H /K /Y
	xcopy "Folder\SysWow64\*" "%SystemRoot%\SysWow64" /E /H /K /Y
	xcopy "Folder\Windows\*" "%SystemRoot%\" /E /H /K /Y
	xcopy "Folder\WinSxS\*" "%SystemRoot%\WinSxS\" /E /H /K /Y

	if exist "%SystemRoot%\System32\smartscreen_disabled.exe" ren "%SystemRoot%\System32\smartscreen_disabled.exe" "smartscreen.exe"

	for %%f in ("RegEdit\*.reg") do reg import "%%f"
	for %%f in ("ServicesDrivers\*.reg") do reg import "%%f"
	for %%f in ("CLSID\*.reg") do reg import "%%f"

	reg delete "HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /f
	reg delete "HKLM\Software\Policies\Microsoft\MRT" /f
rem ����塞 ࠧ��� �� ���஬� �஢������ ᮧ���� �� १�ࢭ�� �����
	reg delete "HKLM\Software\DefenderKiller" /f

) >nul 2>&1

	popd
	
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /f
	NSudoLC -U:%ArgNsudo% -ShowWindowMode:Hide cmd.exe /c reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /f
	
	%ch% {0f} �������� �� ��᪨ � �᪫�祭�� ���⭨��?{\n #}
	%ch% {\n} �ॡ����, �⮡� ��᫥ ����⠭������� ���⭨� �� 㤠��� ��� 䠩��{\n #}
	%ch% {08} 1. {0a}�������� � �᪫�祭��{\n #}
	%ch% {08} 2. �⬥��{\n #}
	choice /c 12 /n /m " "
	if "%errorlevel%"=="1" call :AddExclusionRestore
	if "%errorlevel%"=="2" %ch% {08} �� �ய��⨫� ���������� � �᪫�祭��{\n #}

	nhmb "�ॡ���� ��१���� ��" "DK" "Information|Ok"
	goto Start

:Catalogs
	for /l %%i in (0,1,17) do set "Folder%%i="
	for /l %%i in (1,1,18) do set "File%%i="

rem �����
	if exist "%SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender" (set "Folder0=0c") else (set "Folder0=0a")
	
	if exist "%SystemRoot%\System32\HealthAttestationClient" (set "Folder1=0c") else (set "Folder1=0a")
	if exist "%SystemRoot%\System32\SecurityHealth" (set "Folder2=0c") else (set "Folder2=0a")
	if exist "%SystemRoot%\System32\WebThreatDefSvc" (set "Folder3=0c") else (set "Folder3=0a")
	if exist "%SystemRoot%\System32\Sgrm" (set "Folder4=0c") else (set "Folder4=0a")
	if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender" (set "Folder5=0c") else (set "Folder5=0a")
	if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance" (set "Folder6=0c") else (set "Folder6=0a")
	if exist "%SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender" (set "Folder7=0c") else (set "Folder7=0a")
	if exist "%ProgramFiles%\Windows Defender Sleep" (set "Folder8=0c") else (set "Folder8=0a")
	if exist "%ProgramFiles%\Windows Defender Advanced Threat Protection" (set "Folder9=0c") else (set "Folder9=0a")
	if exist "%ProgramFiles%\Windows Security" (set "Folder10=0c") else (set "Folder10=0a")
	if exist "%ProgramFiles%\PCHealthCheck" (set "Folder11=0c") else (set "Folder11=0a")
	if exist "%ProgramFiles%\Microsoft Update Health Tools" (set "Folder12=0c") else (set "Folder12=0a")
	if exist "%ProgramFiles(x86)%\Windows Defender" (set "Folder13=0c") else (set "Folder13=0a")
	if exist "%ProgramFiles(x86)%\Windows Defender Advanced Threat Protection" (set "Folder14=0c") else (set "Folder14=0a")
	if exist "%AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection" (set "Folder15=0c") else (set "Folder15=0a")
	if exist "%AllUsersProfile%\Microsoft\Windows Security Health" (set "Folder16=0c") else (set "Folder16=0a")
	if exist "%AllUsersProfile%\Microsoft\Storage Health" (set "Folder17=0c") else (set "Folder17=0a")

rem �����
	if exist "%SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim" (set "File1=04") else (set "File1=0a")
	if exist "%SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim" (set "File2=04") else (set "File2=0a")
	if exist "%SystemRoot%\System32\SecurityHealthService.exe" (set "File3=04") else (set "File3=0a")
	if exist "%SystemRoot%\System32\SecurityHealthSystray.exe" (set "File4=04") else (set "File4=0a")
	if exist "%SystemRoot%\System32\SecurityHealthHost.exe" (set "File5=04") else (set "File5=0a")
	if exist "%SystemRoot%\System32\SecurityHealthAgent.dll" (set "File6=04") else (set "File6=0a")
	if exist "%SystemRoot%\System32\SecurityHealthSSO.dll" (set "File7=04") else (set "File7=0a")
	if exist "%SystemRoot%\System32\SecurityHealthProxyStub.dll" (set "File8=04") else (set "File8=0a")
	if exist "%SystemRoot%\System32\smartscreen.dll" (set "File9=04") else (set "File9=0a")
	if exist "%SystemRoot%\System32\wscisvif.dll" (set "File10=04") else (set "File10=0a")
	if exist "%SystemRoot%\System32\wscproxystub.dll" (set "File11=04") else (set "File11=0a")
	if exist "%SystemRoot%\System32\smartscreenps.dll" (set "File12=04") else (set "File12=0a")
	if exist "%SystemRoot%\System32\wscapi.dll" (set "File13=04") else (set "File13=0a")
	if exist "%SystemRoot%\System32\windowsdefenderapplicationguardcsp.dll" (set "File14=04") else (set "File14=0a")
	if exist "%SystemRoot%\System32\wscsvc.dll" (set "File15=04") else (set "File15=0a")
	if exist "%SystemRoot%\System32\SecurityHealthCore.dll" (set "File16=04") else (set "File16=0a")
	if exist "%SystemRoot%\System32\SecurityHealthSsoUdk.dll" (set "File17=04") else (set "File17=0a")
	if exist "%SystemRoot%\System32\SecurityHealthUdk.dll" (set "File18=04") else (set "File18=0a")
	
	%ch% {09}����� � %SystemRoot%\System32{\n #}
	%ch% {%Folder0%} %SystemRoot%\System32\Tasks\Microsoft\Windows\Windows Defender{\n #}

	%ch% {%Folder1%} %SystemRoot%\System32\HealthAttestationClient{\n #}
	%ch% {%Folder2%} %SystemRoot%\System32\SecurityHealth{\n #}
	%ch% {%Folder3%} %SystemRoot%\System32\WebThreatDefSvc{\n #}
	%ch% {%Folder4%} %SystemRoot%\System32\Sgrm{\n #}
	%ch% {%Folder5%} %SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\Defender{\n #}
	%ch% {%Folder6%} %SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\DefenderPerformance{\n #}
	%ch% {%Folder7%} %SystemRoot%\System32\Tasks_Migrated\Microsoft\Windows\Windows Defender{\n #}

	%ch% {\n}{09}����� � %ProgramFiles%{\n #}
	%ch% {%Folder8%} %ProgramFiles%\Windows Defender Sleep{\n #}
	%ch% {%Folder9%} %ProgramFiles%\Windows Defender Advanced Threat Protection{\n #}
	%ch% {%Folder10%} %ProgramFiles%\Windows Security{\n #}
	%ch% {%Folder11%} %ProgramFiles%\PCHealthCheck{\n #}
	%ch% {%Folder12%} %ProgramFiles%\Microsoft Update Health Tools{\n #}

	%ch% {\n}{09}����� � %ProgramFiles(x86)%{\n #}
	%ch% {%Folder13%} %ProgramFiles(x86)%\Windows Defender{\n #}
	%ch% {%Folder14%} %ProgramFiles(x86)%\Windows Defender Advanced Threat Protection{\n #}

	%ch% {\n}{09}����� � %AllUsersProfile%{\n #}
	%ch% {%Folder15%} %AllUsersProfile%\Microsoft\Windows Defender Advanced Threat Protection{\n #}
	%ch% {%Folder16%} %AllUsersProfile%\Microsoft\Windows Security Health{\n #}
	%ch% {%Folder17%} %AllUsersProfile%\Microsoft\Storage Health{\n #}

	%ch% {\n}{09}�����{\n #}
	%ch% {%File1%} %SystemRoot%\Containers\WindowsDefenderApplicationGuard.wim{\n #}
	%ch% {%File2%} %SystemRoot%\Containers\serviced\WindowsDefenderApplicationGuard.wim{\n #}
	%ch% {%File3%} %SystemRoot%\System32\SecurityHealthService.exe{\n #}
	%ch% {%File4%} %SystemRoot%\System32\SecurityHealthSystray.exe{\n #}
	%ch% {%File5%} %SystemRoot%\System32\SecurityHealthHost.exe{\n #}
	%ch% {%File6%} %SystemRoot%\System32\SecurityHealthAgent.dll{\n #}
	%ch% {%File7%} %SystemRoot%\System32\SecurityHealthSSO.dll{\n #}
	%ch% {%File8%} %SystemRoot%\System32\SecurityHealthProxyStub.dll{\n #}
	%ch% {%File9%} %SystemRoot%\System32\smartscreen.dll{\n #}
	%ch% {%File10%} %SystemRoot%\System32\wscisvif.dll{\n #}
	%ch% {%File11%} %SystemRoot%\System32\wscproxystub.dll{\n #}
	%ch% {%File12%} %SystemRoot%\System32\smartscreenps.dll{\n #}
	%ch% {%File13%} %SystemRoot%\System32\wscapi.dll{\n #}
	%ch% {%File14%} %SystemRoot%\System32\windowsdefenderapplicationguardcsp.dll{\n #}
	%ch% {%File15%} %SystemRoot%\System32\wscsvc.dll{\n #}
	%ch% {%File16%} %SystemRoot%\System32\SecurityHealthCore.dll{\n #}
	%ch% {%File17%} %SystemRoot%\System32\SecurityHealthSsoUdk.dll{\n #}
	%ch% {%File18%} %SystemRoot%\System32\SecurityHealthUdk.dll{\n #}

	pause>nul && goto Start

:CheckStateBackup
rem �㭪�� �஢�ન ��᫥ ����஢���� ������� �����, ���� �� � ��� 䠩�� ��� ����� � �뢮� ���ᨨ Windows
		dir /b "%SystemDrive%\WDefenderBackup\Folder\ProgramData\Microsoft\Windows Defender" | findstr /r "^" >nul && (
		exit /b
	) || (
		%ch% {04} ����� "%AllUsersProfile%\Microsoft\Windows Defender" ᪮��஢��� �� 㤠����{\n #}
		%ch% {08} ��� ����� Windows - {03}%NumberWin%{\n #}
		pause
		rd /s /q "%SystemDrive%\WDefenderBackup" >nul 2>&1
		goto Start
	)