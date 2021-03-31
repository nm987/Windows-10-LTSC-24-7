@echo off
cls

net session >nul 2>&1
if %errorLevel% == 0 (
goto :is_admin
) else (
echo Failure: Must run this script as admin.
pause
goto :no_admin
)
:is_admin
echo.
echo.                                                               
echo                 _    _ _____ _   _   _____   ___     ________  
echo                ^| ^|  ^| ^|_   _^| \ ^| ^| / __  \ /   ^|   / /___  /  
echo                ^| ^|  ^| ^| ^| ^| ^|  \^| ^| `' / /'/ /^| ^|  / /   / /  
echo                ^| ^|/\^| ^| ^| ^| ^| . ` ^|   / / / /_^| ^| / /   / /   
echo                \  /\  /_^| ^|_^| ^|\  ^| ./ /__\___  ^|/ /  ./ /    
echo                 \/  \/ \___/\_^| \_/ \_____/   ^|_/_/   \_/     
echo.                                                               
echo                         Windows 10 24/7 setup script 
echo.
echo.
pause
cls
reg Query "HKLM\Hardware\Description\System\CentralProcessor\0" | find /i "x86" > NUL && set OS=32BIT || set OS=64BIT
echo ################################################################
echo ---------------------Windows firewall---------------------------
echo Note: Please be careful that the PC is either proteced by external 
echo firewall or not connected to the Internet as this can be a serious
echo security threat.
:firewall_choice
set /P firewall=Do you want to disable the firewall[Y/N]?
if /I "%firewall%" EQU "Y" goto :firewall_yes
if /I "%firewall%" EQU "N" goto :firewall_no
goto :firewall_choice
:firewall_yes
NetSh Advfirewall set allprofiles state off
echo.
echo Firewall disabled
:firewall_no
pause
cls
echo ################################################################
echo ---------------------Windows Defender---------------------------
echo Disabling Windows Defender can pose an serious security threat.
echo If the computer is not connected to the Internet and no suspicious
echo files are used, it is OK to disable it.
:defender_choice
set /P defender=Do you want to disable the Windows Defender[Y/N]?
if /I "%defender%" EQU "Y" goto :defender_yes
if /I "%defender%" EQU "N" goto :defender_no
goto :defender_choice
:defender_yes
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender" /v DisableRoutinelyTakingAction /t REG_DWORD /d 1 /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" /va /f
echo.
echo Windows Defender disabled
:defender_no
pause
cls
echo ################################################################
echo -----------------------Power options----------------------------
echo It will be done automatically
echo The selected power profile is "High performance"
echo "Put the computer to sleep" is set to never 
echo "Turn off hard disk" is set to never
echo "Turn off the display" is set to never
echo Sleep, Lock, Hibernate options are removed  
powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -change -monitor-timeout-ac 0
powercfg -change -standby-timeout-ac 0
powercfg -change -hibernate-timeout-ac 0
powercfg -change -disk-timeout-ac 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 0
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings /v ShowHibernateOption /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings /v ShowLockOption /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings /v ShowSleepOption /t REG_DWORD /d 0 /f
pause
cls
echo.
echo ################################################################
echo ------------------Security and Maintenance----------------------
echo 1. "Change user Account Control settings" set to "Never notify" - done automatic
echo 2. "Change Windows SmartScreen Settings" - set to "Don't do anything" - done automatic
echo 3. "Change Security and Maintenance settings" - deselect manually everything
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer /v SmartScreenEnabled /t REG_SZ /d Off /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings /v NOC_GLOBAL_SETTING_TOASTS_ENABLED /t REG_DWORD /d 0 /f 
wscui.cpl
pause
cls
echo.
echo ################################################################
echo ----------------------Windows Update----------------------------
echo It will be done automatically
reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f
net stop wuauserv
sc config wuauserv start= disabled
for /f "tokens=1 delims=," %%a in (
    'schtasks /Query /FO csv ^| find /V "Disabled" ^| find "Microsoft\Windows\WindowsUpdate"'
) do (
    schtasks /change /tn %%a /disable
)

for /f "tokens=1 delims=," %%a in (
    'schtasks /Query /FO csv ^| find /V "Disabled" ^| find "Microsoft\Windows\UpdateOrchestrator"'
) do (
    schtasks /change /tn %%a /disable
)
pause
cls
echo.
echo ################################################################
echo --------------------------OneDrive------------------------------
echo It will be done automatically
taskkill /f /im OneDrive.exe
ping 127.0.0.1 -n 2 >NUL
if %OS%==64BIT %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
if %OS%==32BIT %SystemRoot%\System32\OneDriveSetup.exe /uninstall
reg add HKLM\Software\Policies\Microsoft\Windows\OneDrive /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f
rd "%UserProfile%\OneDrive" /Q /S
rd "%LocalAppData%\Microsoft\OneDrive" /Q /S
rd "%ProgramData%\Microsoft OneDrive" /Q /S
rd "C:\OneDriveTemp" /Q /S
REG Delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
REG Delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
schtasks /Delete /TN "OneDrive Standalone Update Task v2" /F
pause
cls
echo.
echo ################################################################
echo ---------Disable Windows Error Recovery on startup--------------
echo It will be done automatically
bcdedit /set {default} bootstatuspolicy ignoreallfailures
pause
cls
echo.
echo ################################################################
echo ---------------Disable Windows Error Reporting------------------
echo It will be done automatically
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f
pause
cls
echo.
echo ################################################################
echo -----------------Disable Windows Telemetry----------------------
echo Disables Windows 10 diagnostics and telemetry reports
echo It will be done automatically
net stop diagtrack
sc config diagtrack start= disabled
net stop dmwappushservice
sc config dmwappushservice start= disabled
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection /v AllowTelemetry /t REG_DWORD /d 0 /f
pause
cls
echo ################################################################
echo -----------------Visual and other settings----------------------
echo Removes Explorer Quick Access
echo Disables Action center
echo Removes Most used applications from the start menu
echo Uses small taskbar
echo Removes Search and Task View from the task bar
echo Adds Network and This PC icons on the Desktop
echo Control Panel items are not grouped (Classic style)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v HubMode /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DisableLogonBackgroundImage /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarSmallIcons /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v ForceClassicControlPanel /t REG_DWORD /d 1 /f
pause
cls
echo               ______ _____ _   _  _____ 
echo               ^|  _  \  _  ^| \ ^| ^|^|  ___^|
echo               ^| ^| ^| ^| ^| ^| ^|  \^| ^|^| ^|__  
echo               ^| ^| ^| ^| ^| ^| ^| . \` ^|^|  __^|
echo               ^| ^|/ /\ \_/ / ^|\  ^|^| ^|___ 
echo               ^|___/  \___/\_^| \_/\____/ 
echo.                           
echo.                            
echo Please reboot this pc.
:reboot_choice
set /P reboot=Do you want to reboot now[Y/N]?
if /I "%reboot%" EQU "Y" goto :reboot_yes
if /I "%reboot%" EQU "N" goto :reboot_no
goto reboot_choice
:reboot_yes
shutdown -r -t 0 -f
:reboot_no
:no_admin

