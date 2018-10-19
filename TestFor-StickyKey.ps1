function Get-FileHash-Cust{
    param (
    [string]
    $Path
    )
     $HashAlgorithm = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider;
     $Hash = [System.BitConverter]::ToString($hashAlgorithm.ComputeHash([System.IO.File]::ReadAllBytes($Path.FullName)));
     $Properties = @{'Algorithm' = 'MD5';
                     'Path' = $Path;
                     'Hash' = $Hash.Replace('-', '');
                     };
     return $Hash.Replace('-', '')
}	
	
	$ipaddress=(gwmi Win32_NetworkAdapterConfiguration| ?{$_.ipenabled}).IPAddress
	$computername=get-childitem env:computername
	$date=get-date
	$computername=$computername.value
	$ipaddress=$ipaddress[0]
	$head=$computername+" "+$date+" "+$ipaddress
	$logpath ="\\some\net\path\$computername.txt"
    $cmdHash = Get-FileHash-Cust -Path $env:windir\System32\cmd.exe
	$psHash = Get-FileHash-Cust -Path $env:windir\System32\WindowsPowerShell\v1.0\powershell.exe
    $explorerHash = Get-FileHash-Cust -Path $env:windir\explorer.exe
    $sethcHash = Get-FileHash-Cust -Path $env:windir\System32\sethc.exe
    $oskHash = Get-FileHash-Cust -Path $env:windir\System32\osk.exe
    $narratorHash = Get-FileHash-Cust -Path $env:windir\System32\Narrator.exe
    $magnifyHash = Get-FileHash-Cust -Path $env:windir\System32\Magnify.exe
    $displayswitchHash = Get-FileHash-Cust -Path $env:windir\System32\DisplaySwitch.exe
    if ($cmdHash -eq $sethcHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. sethc.exe replaced with cmd.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "cmd.exe: $($cmdHash)"
        add-content $logpath "sethc.exe: $($sethcHash)"
        add-content $logpath ""

        } 

    if ($explorerHash -eq $sethcHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. sethc.exe replaced with explorer.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "explorer.exe: $($explorerHash)"
        add-content $logpath "sethc.exe: $($sethcHash)"
        add-content $logpath ""

        } 

    if ($psHash -eq $sethcHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. sethc.exe replaced with powershell.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "powershell.exe: $($psHash)"
        add-content $logpath "sethc.exe: $($sethcHash)"
        add-content $logpath ""

        } 

    if ($cmdHash -eq $oskHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. osk.exe replaced with cmd.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "cmd.exe: $($cmdHash)"
        add-content $logpath "osk.exe: $($oskHash)"
        add-content $logpath ""

        } 

    if ($explorerHash -eq $oskHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. osk.exe replaced with explorer.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "explorer.exe: $($explorerHash)"
        add-content $logpath "osk.exe: $($oskHash)"
       add-content $logpath ""

        } 

    if ($psHash -eq $oskHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. osk.exe replaced with powershell.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "powershell.exe: $($psHash)"
        add-content $logpath "osk.exe: $($oskHash)"
        add-content $logpath ""

        } 

    if ($cmdHash -eq $narratorHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. narrator.exe replaced with cmd.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "cmd.exe: $($cmdHash)"
        add-content $logpath "narrator.exe: $($narrator)"
        add-content $logpath ""

        }

    if ($explorerHash -eq $narratorHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. narrator.exe replaced with explorer.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "explorer.exe: $($explorerHash)"
        add-content $logpath "narrator.exe: $($narratorHash)"
        add-content $logpath ""

        } 

    if ($psHash -eq $narratorHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. narrator.exe replaced with powershell.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "powershell.exe: $($psHash)"
        add-content $logpath "narrator.exe: $($oskHash)"
        add-content $logpath ""

        } 

    if ($cmdHash -eq $magnifyHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. magnify.exe replaced with powershell.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "cmd.exe: $($cmdHash)"
        add-content $logpath "magnify.exe: $($magnifyHash)"
        add-content $logpath ""

        } 

     if ($explorerHash -eq $magnifycHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. sethc.exe replaced with explorer.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "explorer.exe: $($explorerHash)"
        add-content $logpath "magnify.exe: $($magnifyHash)"
        add-content $logpath ""

        } 

    if ($psHash -eq $magnifyHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. magnify.exe replaced with powershell.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "powershell.exe: $($psHash)"
        add-content $logpath "magnify.exe: $($magnifyHash)"
        add-content $logpath ""

        } 

    if ($cmdHash -eq $displayswitchHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. displayswitch.exe replaced with powershell.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "cmd.exe: $($cmdHash)"
        add-content $logpath "displayswitch.exe: $($displayswitchHash)"
        add-content $logpath ""

        } 

    if ($explorerHash -eq $displayswitchHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. displayswitch.exe replaced with explorer.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "explorer.exe: $($explorerHash)"
        add-content $logpath "displayswitch.exe: $($displayswitchHash)"
        add-content $logpath ""

        } 

    if ($psHash -eq $displayswitchHash) {
		add-content $logpath $head
		add-content $logpath ""
        add-content $logpath "Possible backdoor found. displayswitch.exe replaced with powershell.exe"
        add-content $logpath ""
        add-content $logpath "Checked the following hashes:"
        add-content $logpath "powershell.exe: $($psHash)"
        add-content $logpath "displayswitch.exe: $($magnifyHash)"
        add-content $logpath ""

        } 

    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'
    $nameSethc = 'sethc.exe'
    $nameUtilman = 'utilman.exe'
    $property = 'Debugger'

    if (Test-Path -Path ($key + $nameSethc)) {
          
          $tb = Get-Item -Path ($key + $nameSethc)
          
          if ($tb.GetValue($property) -ne $null) {
				add-content $logpath $head
				add-content $logpath ""
                add-content $logpath "Possible backdoor identified at:"
                Get-Item -Path ($key + $nameSethc)
                add-content $logpath ""
                add-content $logpath "Investigate to determine if value of Debugger property set to system-level shell 
                - e.g., cmd.exe"
                add-content $logpath ""
            
            }

    }

    if (Test-Path -Path ($key + $nameUtilman)) {
          
          $tb = Get-Item -Path ($key + $nameUtilman)
          
          if ($tb.GetValue($property) -ne $null) {
				add-content $logpath $head
				add-content $logpath ""
                add-content $logpath "Possible backdoor identified at:"
                Get-Item -Path ($key + $nameUtilman)
                add-content $logpath ""
                add-content $logpath "Investigate to determine if value of Debugger property set to system-level shell 
                - e.g., cmd.exe"
                add-content $logpath ""
            
            }

    }


