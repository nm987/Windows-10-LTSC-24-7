# Windows 10 LTSC 24/7 operation script
 Setup Windows 10 LTSC (LTSB) for 24/7 operation

## About
 I wrote an initial version of this script several years ago in order to help me deploy embedded systems based on Windows 10 LTSB (now called LTSC). It is designed to stop all background processes which can affect continuous system operation (eg. Windows update). It defines power settings, which will ensure that the monitor will not turn off and that no PC components will be turned off for power conservation, which can undermine system performance. Lastly, it will partially automate the removal of the majority of Windows pop-ups and messages that can occur which are difficult to dismiss in systems without HID devices.
 
 ## Action description
 * Disable Windows Firewall (optional)
 * Disable Windows Defender (optional) - can introduce some CPU spikes
 * Power option set to "High performance"
 * Disable UAC and Windows notifications
 * Disable Windows Update
 * Complete OneDrive uninstallation
 * Disable Windows Error Recovery on startup - Windows will always try to boot in normal mode
 * Disable Windows Error Reporting - if application crashes there will be no "application crashed" dialog (useful for systems without HID)
 * Disable Windows Telemetry
 * Visual tweaks (my personal taste, can be ommited)
 
 ## Tested OS version
 * Windows 10 Enterprise 2016 LTSB