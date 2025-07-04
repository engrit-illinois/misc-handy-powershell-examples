# Documentation home: https://github.com/engrit-illinois/misc-handy-powershell-examples
# By mseng3

# To prevent anyone from blindly running this as a script:
Exit

# -----------------------------------------------------------------------------

# Note: this file has examples primarily is for general administrative tasks. For a separate file dedicated to tasks relating to MECM, see:
# https://github.com/engrit-illinois/org-shared-mecm-deployments/blob/main/org-shared-deployments-misc.ps1

# -----------------------------------------------------------------------------

# Do something remotely on multiple computers, in parallel...
# https://devblogs.microsoft.com/powershell/powershell-foreach-object-parallel-feature/
# Note the parallel functionality of ForEach-Object requires PowerShell 7
# To do them NOT in parallel, just remove the -ThrottleLimit and -Parallel parameters from ForEach-Object

# ...based on specific given computer names
$compNames = "MEL-1001-10","KH-105-03","KH-107-03","EH-406B8-28"... # etc., etc.

# ...based on an AD name query
$comps = Get-ADComputer -Filter { Name -like "gelib-4c-*" }

# ...based on one or more AD name queries
$queries = "gelib-4c-*","dcl-l426-*","mel-1001-01"
$searchBase = "OU=Instructional,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"
$comps = $queries | ForEach-Object { Get-ADComputer -SearchBase $searchBase -Filter "name -like `"$_`"" -Properties "*" }

# ...based on direct membership rules of an MECM collection
$compNames = Get-CMCollectionDirectMembershipRule -CollectionName "UIUC-ENGR-IS mseng3 Test VMs (direct membership)" | Select -ExpandProperty RuleName | Sort

# ...based on sequentially-named computers (i.e. a lab)
$lab = "ECEB-9999"
$nums = @(4,5,7,11,14)
$comps = @()
$nums | ForEach-Object {
    $num = ([string]$_).PadLeft(2,"0")
    $comps += "$lab-$($num)"
}

# Doing the thing
$compNames = $comps | Select -ExpandProperty "Name" # if the members of $comps are AD or otherwise PowerShell object, instead of just strings
$compNames | ForEach-Object -ThrottleLimit 15 -Parallel {
    Write-Host "Processing $_..."
    Invoke-Command -ComputerName $_ -ScriptBlock {
        # Do stuff here
    }    
}

# -----------------------------------------------------------------------------

# Start a new, elevated PowerShell process in the current directory:
# Useful because Windows does not allow Powershell to  elevate an existing session
# https://superuser.com/a/1256947/137753
Start-Process powershell -Verb runas -ArgumentList "-NoExit -c cd '$pwd'"

# -----------------------------------------------------------------------------

# Create a new shortcut
$pathLnk = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Protege.lnk"
$pathTarget = "C:\Program Files\Protege.exe"

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($pathLnk)
$shortcut.TargetPath = $pathTarget
$shortcut.Save()

# -----------------------------------------------------------------------------

# Modify the target field of all existing shortcuts in the current directory
$lnks = dir "*.lnk"
$lnks | ForEach-Object {
    # Create a temporary shortcut object to work with
    $lnk = (New-Object -ComObject 'WScript.Shell').CreateShortCut($_.FullName)
    # Modifies the base target file path
    $lnk.TargetPath = $lnk.TargetPath.Replace("appv1.exe","appv2.exe")
    # Modifies the arguments given to the target file
    $lnk.Arguments = $lnk.Arguments.Replace("-Param1 `"Hello World!`"","Param2 `"Hello.`"")
    # Modifies the "Start in" path
    $lnk.WorkingDirectory = $lnk.WorkingDirectory.Replace("c:\program files\","d:\test\")
    # Apply the changes to the actual shortcut file
    $lnk.Save()
}

# -----------------------------------------------------------------------------

# Create large dummy files
# https://www.windows-commandline.com/how-to-create-large-dummy-file/
Invoke-Command -ComputerName "computer-name" -ScriptBlock { fsutil file createnew c:\bigtestfile.txt 100000000000 } #100GB

# -----------------------------------------------------------------------------

# Find 10 largest files
# https://social.technet.microsoft.com/Forums/ie/en-US/838ed753-2bcf-49b8-9321-775c5ef12f13/finding-largest-files?forum=winserverpowershell
Get-ChildItem "c:\users\" -Recurse -File | Sort "length" -Descending | Select @{Name="Size";Expression={"$([math]::Round(($_.length / 1MB),2))MB"}},"FullName","CreationTime","LastWriteTime","LastAccessTime" -First 10 | Format-Table

# -----------------------------------------------------------------------------

# Find the largest user profiles greater than 1GB across multiple computers
$comps = Get-ADComputer -Filter "name -like 'ncsab-1104-*'" -SearchBase "OU=Instructional,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"
$data = $comps | ForEach-Object {
	$comp = $_.Name
	Invoke-Command -ComputerName $comp -ScriptBlock {
		Get-Item -Path "c:\users\*" | ForEach-Object {
			Get-ChildItem $_ -Recurse -File | Measure-Object -Property length -Sum -Maximum | Add-Member -NotePropertyName "User" -NotePropertyValue $_.Name -PassThru
		}
	}
} | Select PSComputerName,User,Count,@{N="Max (GB)";E={[int]($_.Maximum/1GB)}},@{N="Sum (GB)";E={[int]($_.Sum/1GB)}}
$data = $data | Where { $_."Sum (GB)" -ge 1 }
$data | Sort PSComputerName,@{Expression="Sum (GB)";Descending=$true} | Format-Table

# -----------------------------------------------------------------------------

# Test whether a specific folder (or file, registry entry, etc.) exists on multiple computers
Get-ADComputer -Filter "Name -like 'eh-406b*'" | Select -ExpandProperty Name | ForEach-Object -Parallel {
    [PSCustomObject]@{
        "Name" = $_
        "Exists" = Invoke-Command -ComputerName $_ -ScriptBlock { Test-Path "c:\macrosenabled" } -ErrorAction SilentlyContinue
    }
}

# -----------------------------------------------------------------------------

# Get the (human-readable) total size of all files in a given directory
"{0:N} MB" -f ([math]::Round(((Get-ChildItem "\\comp-name-01\c$\users\netid" -Recurse -Force | Measure-Object -Property Length -Sum | Select -ExpandProperty Sum) / 1MB), 2))

# -----------------------------------------------------------------------------

# Disk cleaning actions

function Clear-TempFiles($ComputerNameQuery) {
    $comps = Get-ADComputer -Filter "name -like '$ComputerNameQuery'" -SearchBase "OU=Instructional,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"
	Write-Host "Computers:"
	$compsString = "`"" + ($comps.Name -join "`",`"") + "`""
	Write-Host "    $compsString"
    $ErrorActionPreference = 'SilentlyContinue'
    $comps | ForEach-Object -ThrottleLimit 25 -Parallel {
		$comp = $_.Name
        $ts = Get-Date -Format "HH:mm:ss"
        Write-Host "[$ts] Processing $($comp)..."
        Invoke-Command -ComputerName $comp -ScriptBlock {
            $ErrorActionPreference = 'SilentlyContinue'

            # Empty recycle bin
            # https://github.com/PowerShell/PowerShell/issues/6743
            # https://serverfault.com/questions/822514/clear-recyclebin-on-remote-computer-fails
            Clear-RecycleBin -Force -DriveLetter "C"

            # Delete temporary files
            Remove-Item "c:\temp" -Recurse -Force
            Remove-Item "c:\windows\temp" -Recurse -Force
            Remove-Item "c:\users\*\appdata\local\crashdumps\*" -Recurse -Force

            # Blow away default-location Dropbox folders
            Remove-Item "c:\users\*\dropbox" -Recurse -Force
            Remove-Item "c:\users\*\AppData\Local\Dropbox" -Recurse -Force

            # Run disk cleanup
            # http://www.theservergeeks.com/how-todisk-cleanup-using-powershell/
            # Note: this sometimes hangs and doesn't always seem to have an effect, possibly due to waiting for user GUI interaction. Use with caution.
            # Might be able to be improved with advice at the following link. I haven't had time to investigate.
            # https://stackoverflow.com/questions/28852786/automate-process-of-disk-cleanup-cleanmgr-exe-without-user-intervention
            $HKLM = [UInt32] “0x80000002”
            $strKeyPath = “SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches”
            $strValueName = “StateFlags0065”
            $subkeys = gci -Path HKLM:\$strKeyPath -Name
            foreach($subkey in $subkeys) {
                try { New-ItemProperty -Path HKLM:\$strKeyPath\$subkey -Name $strValueName -PropertyType DWord -Value 2 -ErrorAction SilentlyContinue| Out-Null }
                catch {}
                try { Start-Process cleanmgr -ArgumentList “/sagerun:65” -Wait -NoNewWindow -ErrorAction SilentlyContinue -WarningAction SilentlyContinue }
                catch { }
            }
            foreach($subkey in $subkeys) {
                try { Remove-ItemProperty -Path HKLM:\$strKeyPath\$subkey -Name $strValueName | Out-Null }
                catch { }
            }
        }
        $ts = Get-Date -Format "HH:mm:ss"
        Write-Host "[$ts] Done processing $($comp)."
    }
}

# Example:
Clear-TempFiles "comp-name-*"

# -----------------------------------------------------------------------------

# Ping multiple machines
# This has been made into a proper module, here: https://github.com/engrit-illinois/Ping-All
# Test-ConnectionAsync is a custom module: https://gallery.technet.microsoft.com/scriptcenter/Multithreaded-PowerShell-0bc3f59b#content
Import-Module "~/temp/powershell scripts/Test-ConnectionAsync.ps1m"
(Get-ADComputer -Filter { Name -like "computer-name-*" }).Name | Test-ConnectionAsync -Count 1 | Format-Table

# -----------------------------------------------------------------------------

# Run gpupdate on multiple computers
# This has been turned into its own module here: https://github.com/engrit-illinois/GpUpdate-Computer
# Kept here for reference, and because the module uses the 5.1+ code, while this snippet demonstrates 6.0+ code

$lab = "ECEB-9999"
$nums = @(4,5,7,11,14)
$comps = @()
$nums | ForEach-Object {
    $num = ([string]$_).PadLeft(2,"0")
    $comps += "$lab-$($num)"
}

# The following works on client computers with PS 5.1+
$comps | ForEach-Object -ThrottleLimit 35 -Parallel {
    Write-Host "Processing $($_)..."
    Invoke-Command -ComputerName $_ -ScriptBlock { echo "n" | gpupdate /force }
}

# The following only works on client computers with PS 6.0+
# https://docs.microsoft.com/en-us/powershell/module/grouppolicy/invoke-gpupdate?view=windowsserver2022-ps
$comps | ForEach-Object -ThrottleLimit 35 -Parallel {
    Write-Host "Processing $($_)..."
    Invoke-GPUpdate -Force -Computer $_ # Both computer and user policy
    # Invoke-GPUpdate -Target "Computer" -Force -Computer $_ # Computer policy only
    # Invoke-GPUpdate -Target "User" -Force -Computer $_ # User policy only
}


# -----------------------------------------------------------------------------

# Add multiple computer objects with sequentially-numbered and zero-padded names to an OU in AD
# e.g. "COMPUTER-NAME01", "COMPUTER-NAME02", etc.
foreach($int in @(1..10)) {
    $num = ([string]$int).PadLeft(2,"0")
    $name = "COMPUTER-NAME$($num)"
    Write-Host $name
    New-ADComputer -Name $name -SamAccountName $name -Path "OU=MyOU,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"
}

# -----------------------------------------------------------------------------

# Rename a single computer and immediately restart
$creds = Get-Credential "uofi\su-netid"
Invoke-Command -ComputerName "SIEBL-4107-01" -ArgumentList $creds -ScriptBlock {
    param($creds)
    Rename-Computer -NewName "NCSA-1104-01" -DomainCredential $creds
    Restart-Computer
}

# -----------------------------------------------------------------------------

# Rename multiple computers and immediately restart them
# Remove the -Restart parameter to not restart
# e.g. rename ENGR-100-01 through ENGR-100-10 to ENGR-999-01 through ENGR-999-10
$remoteCreds = Get-Credential -Message "Enter creds for invoking commands on remote machines" -UserName "uofi\netid"
$renameCreds = Get-Credential -Message "Enter creds for renaming remote machines" -UserName "uofi\su-netid"

$scriptBlock = {
	param(
	    [string]$newName,
            [System.Management.Automation.PSCredential]$renameCreds
	)
	Rename-Computer -DomainCredential $renameCreds -NewName $newName
	Restart-Computer
}

foreach($int in @(1..10)) {
    $num = ([string]$int).PadLeft(2,"0")
    $oldName = "COMP-OLDNAME-$($num)"
    $newName = "COMP-NEWNAME-$($num)"
    Invoke-Command -ComputerName $oldName -Credential $remoteCreds -ScriptBlock $scriptBlock -ArgumentList $newName,$renameCreds
}

# -----------------------------------------------------------------------------

# If you get one of the following errors when trying to rename a computer:

# When renaming using the GUI:
# “The PC name can’t be updated in Azure Active Directory.”

# When renaming via the Rename-Computer PowerShell cmdlet:
# "Fail to rename computer '<old name>' to '<new name>' due to the following exception: Unable to update hostname in Azure AD. Check the event log for detailed error information."

# Then run this command in an elevated prompt:
dsregcmd /leave

# And then rename as usual using commands documented above.
# I came across this error when attempting to swap the names of two computers.
# I renamed the first computer to a 3rd temp name, and then accidentally renamed the second computer to the first computer's original name before the first computer had a chance to complete its rename.
# The second computer then showed these errors anytime I tried to rename it again, until I used the fix above.

# It's also apparently a potential side effect of the Oct. 2022 domain-join hardening:
# https://www.reddit.com/r/Intune/comments/yfp1ho/computer_rename/

# -----------------------------------------------------------------------------

# Find GPO named like...
$gpos = Get-GPO -All -Domain "ad.uillinois.edu"
$gpos | Where { $_.DisplayName -like "engr ews*license*" } | Select DisplayName,Id

# -----------------------------------------------------------------------------

# Get all GPOs linked to a given OU:
$oudn = "OU=Helpdesk,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"
$links = Get-ADOrganizationalUnit $oudn | Select -ExpandProperty LinkedGroupPolicyObjects
$guids = $links | ForEach-Object { $_.Substring(4,36) }
$gpos = $guids | ForEach-Object { Get-GPO -Guid $_ }
$gpos | Select DisplayName,Id

# -----------------------------------------------------------------------------

# Get all OUs where a given GPO is linked:
$gpo = "ENGR US WSUS Settings"
$guid = (Get-GPO -Name $gpo | Select Id).Id
$ous = Get-ADOrganizationalUnit -LDAPFilter "(gPLink=*$guid*)"
$ous | Select Name,DistinguishedName

# -----------------------------------------------------------------------------

# Reset EWS guest accounts:
# This has been made into a proper script here:
# https://github.com/engrit-illinois/Recycle-EWSGuestAccounts

# -----------------------------------------------------------------------------

# Trigger a scheduled task (on a remote computer):
Start-ScheduledTask -CimSession "computer-name" -TaskName "Task name"

# -----------------------------------------------------------------------------

# Enable the PowerShell AD module:
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability –Online

# -----------------------------------------------------------------------------

# Find properties of an object where the property name, or the property's value is like "string*"
# Useful if you have a large object you're not familiar with and you're looking for a property name or value somewhere in it
(Get-ComputerInfo).PSObject.Properties | Where { $_.Value -like "engrit*" } | Select Name,Value | Format-Table

# -----------------------------------------------------------------------------

# Get last bootup time of remote computer(s):
Get-CimInstance "Win32_OperatingSystem" -ComputerName $_ | Select LastBootUpTime
(get-adcomputer -filter 'name -like "eceb-3077-*"' | Select name).name | foreach { Get-CimInstance "Win32_OperatingSystem" -ComputerName $_ | Select CSName,LastBootUpTime }

systeminfo /s $_ | findstr "Host Time:"
(get-adcomputer -filter 'name -like "eceb-3073-*"' | Select name).name | foreach { systeminfo /s $_ | findstr "Host Time:" }

# -----------------------------------------------------------------------------

# Get boot and shutdown history for a computer:
# This has been turned into a proper script here:
# https://github.com/engrit-illinois/Get-UptimeHistory

# https://serverfault.com/questions/702828/windows-server-restart-shutdown-history
# https://www.whatsupgold.com/blog/how-to-find-restart-info-for-machines-on-your-network-using-powershell-and-windows-event-logs
$EVENT_IDS = @(
	[PSCustomObject]@{id = 6005; name = ""},
	[PSCustomObject]@{id = 6006; name = ""},
	[PSCustomObject]@{id = 6008; name = ""}
)

$filter = @{
	LogName = "System"
	ProviderName = "Microsoft-Windows-Security-Auditing"
	Id = $EVENT_IDS.id
	StartTime = $After
	EndTime = $Before
}
Get-WinEvent -ComputerName $comp -FilterHashTable $filter

# -----------------------------------------------------------------------------

# Command line syntax documentation guidelines:
# https://stackoverflow.com/questions/9725675/is-there-a-standard-format-for-command-line-shell-help-text
# Unix: http://docopt.org/
# GNU: http://www.gnu.org/prep/standards/standards.html#g_t_002d_002dhelp
# Microsoft: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-powershell-1.0/ee156811(v=technet.10)?redirectedfrom=MSDN
# Microsoft: https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/command-line-syntax-key
# IBM: https://www.ibm.com/support/knowledgecenter/SSMLQ4_11.3.0/com.ibm.nex.optimd.tdm.doc/Acmdline/opmoveuse-c-command_line_interface.html
# IEEE: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html#tag_12_01

# -----------------------------------------------------------------------------

# Get the expiration date of all AD user objects in a given OU
$ou = "OU=MyOU,OU=Admin,OU=UsersAndGroups,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"
Get-ADUser -SearchBase $ou -Filter 'Name -like "*"' -Properties Name,AccountExpirationDate | Select Name,AccountExpirationDate

# -----------------------------------------------------------------------------

# Update the expiration date of all AD user objects in a given OU
$ou = "OU=MyOU,OU=Admin,OU=UsersAndGroups,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"
$expiry = "2020-12-25"
$users = (Get-ADUser -SearchBase $ou -Filter 'Name -like "*"' -Properties Name | Select Name).Name
foreach($user in $users) {
    Set-ADUser -Identity $user -AccountExpirationDate $expiry
}

# -----------------------------------------------------------------------------

# Find and count all members of Engineering AD groups and/or Banner groups for a given class:
# This has been turned into a proper module here:
# https://github.com/engrit-illinois/Get-ClassSize

# -----------------------------------------------------------------------------

# Get the (direct) membership of all groups in a given OU
Get-ADGroup -SearchBase "OU=RD User Groups,OU=Instructional,OU=UsersAndGroups,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu" -Filter "*" | ForEach-Object { "`n`n$($_.Name)`n-------------"; (Get-ADGroupMember -Identity $_.Name | Select Name).Name }

# -----------------------------------------------------------------------------

# Force the MECM client to re-evaluate its assignments
# Useful if deployments just won't show up in Software Center
# https://github.com/engrit-illinois/force-software-center-assignment-evaluation
$Assignments = (Get-WmiObject -Namespace root\ccm\Policy\Machine -Query "Select * FROM CCM_ApplicationCIAssignment").AssignmentID
ForEach ($Assignment in $Assignments) {
    $Trigger = [wmiclass] "\root\ccm:SMS_Client"
    $Trigger.TriggerSchedule("$Assignment")
    Start-Sleep 1
}

# -----------------------------------------------------------------------------

# For a bunch of handy MECM-related Powershell commands see this other doc:
https://github.com/engrit-illinois/org-shared-mecm-deployments/blob/master/org-shared-deployments-misc.ps1

# -----------------------------------------------------------------------------

# Gather some stats about an EWS homedir
# This has been turned into a proper module here: https://github.com/engrit-illinois/Poke-EwsHomeDir

# -----------------------------------------------------------------------------

# Searching powershell history

# Current session:
Get-History

# Previous sessions:
# https://serverfault.com/questions/891265/how-to-search-powershell-command-history-from-previous-sessions
Get-Content (Get-PSReadlineOption).HistorySavePath | Where { $_ -like '*adobe*' }

# Previous session history file location:
(Get-PSReadlineOption).HistorySavePath
# i.e. "C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

# -----------------------------------------------------------------------------

# Restart the clipboard service used to copy content between RDP sessions
# https://www.svenbit.com/2014/11/restart-copy-and-paste-clipboard-functionality-in-rdp/
# Run on remote server:
Get-Process rdpclip | Stop-Process; rdpclip

# -----------------------------------------------------------------------------

# Find the MSI product code for an application
# https://stackoverflow.com/questions/29937568/how-can-i-find-the-product-guid-of-an-installed-msi-setup
# This can take a while to run
$apps = get-wmiobject Win32_Product
$apps | Select Name,IdentifyingNumber | Sort Name

# -----------------------------------------------------------------------------

# Handy, feature-rich log functions by mseng3
# This has been moved to its own repo here: https://github.com/engrit-illinois/handy-log-functions

# -----------------------------------------------------------------------------

# Send a pop up dialog with a custom message and an "OK" button, to logged in users of a remote computer:
Invoke-Command -ComputerName "computer-name" -ScriptBlock { msg * /v "Test message" }

# or just
msg * /v /server:"computer-name" "Test message"

# -----------------------------------------------------------------------------

# Find AD objects with a given string in their description field:
Get-ADComputer -Filter { Description -Like "*query*" } -Properties Description | Select Name,Description

# -----------------------------------------------------------------------------

# Speak a given message
# Note: only seems to work in an interactive session
# i.e., can't be used for its intended purpose of pranking fellow IT pros :'(
# https://www.get-itguy.com/2020/01/run-scripts-with-parameters-in-memcm.html

$msg = "This is a test message."

# Call up your speech assembly
Add-Type -AssemblyName System.Speech
$speaker = New-Object System.Speech.Synthesis.SpeechSynthesizer

#$speaker.SelectVoice("Microsoft Zira Desktop")
$speaker.SelectVoice("Microsoft David Desktop")
$speaker.Volume = 100
$speaker.Speak($Message)
$speaker.Dispose()

# -----------------------------------------------------------------------------

# Remove all stored credentials from Credential Manager relating to the university
# Useful to clear out credentials when you've changed your NetID password
# Note cmdkey.exe has a bug which causes it to fails removing credentials which contain parentheses, or combinations of spaces and hyphens,
# these will have to be removed manually.

# Define wildcard queries to target desired credentials
$targets = @(
	"*illinois.edu*",
	"*uofi*",
	"*office365*",
	"*MicrosoftOffice*",
	"*msteams*",
	"*OneDrive*",
	"*engrit*",
	"*gelib-idea*",
	"*ews*",
	"*mseng3*"
)

# Get all credential items
$items = cmdkey /list | Where { $_ -like "*Target:*" }

# Get all credential items which match queries
$targetItems = @()
foreach($item in $items) {
	foreach($target in $targets) {
		if($item -like $target) {
			$targetItems += $item
		}
	}
}

# For each matching item
foreach($item in $targetItems) {
	$item = $item.Replace("Target:","")
	$item = $item.Replace("LegacyGeneric:","")
	$item = $item.Replace("Domain:","")
	$item = $item.Replace("target=","")
	$item = $item.Trim()
	Write-Host $item
	cmdkey /del:$item
}

# -----------------------------------------------------------------------------

; # Quick and dirty AHK script to automate removing credential entries from the Windows Credential Manager GUI.
; # Mostly because the cmdkey.exe executable (which can properly automate this), doesn't support deleting entries with special characters like parentheses and combinations of hyphens and spaces.
; # https://stackoverflow.com/questions/51565300/cmdkey-delete-credentials-with-dashes-and-spaces-on-the-name
; # https://social.technet.microsoft.com/forums/Exchange/en-US/3cca73c6-20ad-4958-a2e0-71613959917b/cmdkey-syntax?forum=ITCG

; # Update: For an easier way, see: https://forflukesake.co.za/wp/clear-credential-manager-fast/
; # Enter "rundll32.exe keymgr.dll, KRShowKeyMgr" to open a dialog which contains a similar list, and you can use Alt+R and Enter to clear out many entries quickly.

#NoEnv
#SingleInstance Force
SetWorkingDir %A_ScriptDir%
SetKeyDelay, 100, 50 ; First number is delay between key presses, second is press duration, both in ms.

; Select the first entry you want to delete and delete it. The focused element will return to the very top of the window.
; Press tab until the focus loops around to the "expand" arrow of the next entry you want to delete. Count that number of tab presses and enter it here.
TabsToFirstEntry = 17
; Approximate number of sequential entries you want to delete. Err on the low side to be safe.
Iterations = 70

; Start with focus on the "expand" arrow of the first entry you want to delete.
; Hit F1 and don't touch anything
Hotkey, F1, StartScript ; Define label to goto when F1 is pressed
Hotkey, F4, ReloadScript ; Define label to goto when F4 is pressed
Return ; Do nothing more until a hotkey is pressed

StartScript:
	SoundBeep 1000
	Loop %Iterations% {
		Send {Space} ; Expands entry
		Send {Tab 2} ; Navigates to "Remove" link
		Send {Enter} ; Selects "Remove" link
		Sleep 200 ; Waits for confirmation dialog to pop up
		Send {y} ; Selects "yes" on confirmation dialog
		Send {Tab %TabsToFirstEntry%} ; Tabs from top of window down to first entry to delete
	}
	SoundBeep 1500 ; Beep to signify completion
	Return

ReloadScript:
	; Make sure all relevant keys are not still virtually pressed.
	Send {Space up}
	Send {Tab up}
	Send {Enter up}
	Send {y up}
	
	; Beeps to signify reload
	SoundBeep 1000
	SoundBeep 1000
	SoundBeep 1000
	Reload

; EOF

# -----------------------------------------------------------------------------

# Get the last logon timestamp for a group of machines:
# Must be run as your SU account to get the lastLogonTimestamp field data
# https://stackoverflow.com/questions/13091719/converting-lastlogon-to-datetime-format
$query = "esb-6104-*"
Get-ADComputer -Filter "name -like '$query'" -Properties * | Select Name,lastLogonTimestamp,@{Name="lastlogonTimestampDateTime";Expression={[datetime]::FromFileTime($_.lastLogonTimestamp)}}

# -----------------------------------------------------------------------------

# Search your Powershell command history for commands sent matching a given string:
# https://serverfault.com/a/891268/270130
$query = "*something*"
Get-Content (Get-PSReadlineOption).HistorySavePath | Where { $_ -like $query }

# Or open the file directly
# C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
(Get-PSReadlineOption).HistorySavePath

# -----------------------------------------------------------------------------

# Get the InstallDate from a group of machines (to tell when they were imaged):
$comps = Get-ADComputer -Filter { Name -like "computer-name-*" }
$data = @()
foreach($comp in $comps.Name) {
	Write-Host "Querying $comp..."
	$compData = Invoke-Command -ComputerName $comp -ScriptBlock {
		get-ciminstance win32_operatingsystem -OperationTimeoutSec 60
	}
	$data += @($compData)
}
$data | Select PSComputerName,installdate | Format-Table -AutoSize

# -----------------------------------------------------------------------------

# Handy utility function to reliably count members of an array that might be empty

# Because of Powershell's weird way of handling arrays containing null values
# i.e. null values in arrays still count as items in the array
function count($array) {
	$count = 0
	if($array) {
		# If we didn't check $array in the above if statement, this would return 1 if $array was $null
		# i.e. @().count = 0, @($null).count = 1
		$count = @($array).count
		# We can't simply do $array.count, because if it's null, that would throw an error due to trying to access a method on a null object
	}
	$count
}

# -----------------------------------------------------------------------------

# Shorthand for an annoying common line to add new members to objects

function addm($property, $value, $object, $adObject = $false) {
	if($adObject) {
		# This gets me EVERY FLIPPIN TIME:
		# https://stackoverflow.com/questions/32919541/why-does-add-member-think-every-possible-property-already-exists-on-a-microsoft
		$object | Add-Member -NotePropertyName $property -NotePropertyValue $value -Force
	}
	else {
		$object | Add-Member -NotePropertyName $property -NotePropertyValue $value
	}
	$object
}

# -----------------------------------------------------------------------------

# Get the raw value of the property of a calculated array of objects, without using annoying ($array | Where { something }).property syntax,
# which requires you to backtrack your cursor to add an opening parenthesis.
# Also more parentheses tend to lead to more complicated, less-readable, error-prone code.

# Example:
$array = Get-Process

# With a singular, non-calculated object, it's easy:
$array.Name

# With a "calculated" object, it's annoying:
($array | Where { $.Name -like "*test*" }).Name

# But you can do this instead:
# It's, more keystrokes, but avoids using parenthesis, and keeps the pipeline syntax flowing
$array | Where { $_.Name -like "*test*" } | Select -ExpandProperty Name

# Similarly, using method call syntax to get a count (which is a common task) is annoying for the same reasons:

# Usual method:
$count = (Get-GPO -All | Where { $_.DisplayName -like "ENGR*"}).count
$count # Outputs an integer
$count.GetType() # Int32

# Get "Measure" object using only pipeline syntax:
$count2 = Get-GPO -All | Where { $_.DisplayName -like "ENGR*"} | Measure
$count2 # Outputs an object
$count2.GetType() # GenericMeasureInfo

# Get count child object of Measure object using only pipline syntax:
$count3 = Get-GPO -All | Where { $_.DisplayName -like "ENGR*"} | Measure | Select Count
$count3 # Outputs an object
$count3.GetType() # PSCustomObject

# Get raw count value of count child object of Measure object using only pipline syntax:
$count4 = Get-GPO -All | Where { $_.DisplayName -like "ENGR*"} | Measure | Select -ExpandProperty Count
$count4 # Outputs an integer
$count4.GetType() # Int32

# -----------------------------------------------------------------------------

# Extract icon from an EXE

# Define paths
$filePath = "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe"
$iconPath = "c:\engrit\posh-icon.ico"

# Get icon data from EXE
$file = Get-Item -Path $filePath
Add-Type -AssemblyName System.Drawing
$icon = [System.Drawing.Icon]::ExtractAssociatedIcon($file.FullName)

# Get BMP from icon data
$bmp = $icon.ToBitmap()
# Get BMP from existing BMP file instead
#$bmpPath = "c:\engrit\posh-icon.bmp"
#$bmp = [System.Drawing.Bitmap]::FromFile($bmpPath)

# Save as ICO
$bmp.Save($iconPath,"icon")

# Sources
# https://jdhitsolutions.com/blog/powershell/7931/extracting-icons-with-powershell/
# https://community.spiceworks.com/topic/592770-extract-icon-from-exe-powershell
# https://docs.microsoft.com/en-us/dotnet/api/system.drawing.icon.extractassociatedicon?view=net-5.0
# https://docs.microsoft.com/en-us/dotnet/api/system.drawing.icon?view=net-5.0
# https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/converting-bitmaps-to-icons

# -----------------------------------------------------------------------------

# Get info from Lens API

# Moved to its own module here: https://github.com/engrit-illinois/Get-LensObject
# For pulling info about a specific computer, see: https://github.com/engrit-illinois/Get-LensInfo

# -----------------------------------------------------------------------------

# Export a variable from one Powershell session and import to another
# Useful for grabbing data in a powershell session running as one user and processing it in a session running as another user.
# e.g. Grab data from MECM as normal account, and process it as SU account, which doesn't have MECM permissions
# https://stackoverflow.com/questions/56637777/how-to-pass-powershell-variable-from-one-session-to-another-or-from-one-stage-to

# In normal user session
$compsNoDescMecm = Get-CMCollectionMember -CollectionName "UIUC-ENGR-Has no AD description (IS)"
$compsNoDescMecm | export-clixml -path c:\mseng3-ctemp\temp-psvar.xml

# In SU user session
$compsNoDescMecm = import-clixml -path C:\mseng3-ctemp\temp-psvar.xml

# -----------------------------------------------------------------------------

# Download a (public) file
# https://adamtheautomator.com/powershell-download-file/
# https://www.reddit.com/r/PowerShell/comments/ckn1q7/how_do_you_outfile_and_force_to_create_the/

$source = "https://raw.githubusercontent.com/engrit-illinois/misc-handy-powershell-examples/main/misc-handy-powershell-examples.ps1"
$destination = "$HOME\Downloads\somefolder\misc-handy-powershell-examples.ps1"

# For public files
Invoke-WebRequest -Uri $source -OutFile (New-Item -Path $destination -Force)

# For (basic auth?) protected files (untested)
$creds = Get-Credential
Invoke-WebRequest -Uri $source -OutFile (New-Item -Path $destination -Force) -Credential $creds

# -----------------------------------------------------------------------------

# Fix the "lost trust relationship with domain" error, without needing to unjoin/reboot/rejoin
# https://www.reddit.com/r/PowerShell/comments/8d4tsr/a_quick_powertip_the_trust_relationship_between/
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-computersecurechannel?view=powershell-5.1

# Test if the machine is properly domain-joined:
Test-ComputerSecureChannel # returns $true if so, $false if not
# Repair it
Test-ComputerSecureChannel -Repair -Credential "uofi\mseng3" # also returns $true if so, $false if not
# Test again
Test-ComputerSecureChannel # should return $true now

# -----------------------------------------------------------------------------

# Join computer to domain while creating a new, currently-non-existent AD object, in a specified OU:
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-computer?view=powershell-5.1

# Especially helpful after MS hardening change requiring join actions to be performed by the same account which created the object.
# https://support.microsoft.com/en-au/topic/kb5020276-netjoin-domain-join-hardening-changes-2b65a0f3-1f4c-42ef-ac0f-1caaf421baf8
# https://www.anoopcnair.com/fix-kb5020276-domain-join-hardening-changes/

# Local computer
Add-Computer -DomainName "ad.uillinois.edu" -OUPath "OU=Instructional,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu" -Force
# Note: -Force suppresses confirmation prompt

# For a remote computer, add:
-ComputerName "comp-name-01"

# If your current user doesn't have local admin permissions on the target machine, add:
-LocalCredential "comp-name-01\admin"

# If your current user doesn't have permissions to create objects in the target OU, add one of:
-Credential "uofi\netid"
-Credential "uofi\su-netid"

# If you still need to join a machine to an existing object with a different user account,
# then here is the code to implement the reghack which (for now) overrides the hardening and allows this:
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NetJoinLegacyAccountReuse" -Value 1
# Remember to undo the reghack afterward:
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NetJoinLegacyAccountReuse"

# If you want to restart the machine immediately afterward, add:
-Restart
# or use a second line like:
Restart-Computer -ComputerName "comp-name-01" [-Force]

# -----------------------------------------------------------------------------

# Force a computer to re-register its IP with AD DNS
# For when pinging a computer by it's NETBIOS name, or FQDN returns "Ping request could not find host <computer-name>.ad.uillinois.edu. Please check the name and try again.".

# Run this on the offending host (locally):
ipconfig /registerdns

# or the native PowerShell equivalent:
Register-DnsClient

# Then wait for a bit for AD to register the machine/IP and replicate the info

# Here's a version you can run remotely, using the machine's IP (or regular DNS hostname) since the AD DNS name may not work:
# https://techibee.com/powershell/force-dns-registration-on-remote-computers-using-powershell/2617
$comp = "dcl-l416-05.ews.illinois.edu"
([WMIClass]"\\$comp\ROOT\CIMv2:Win32_Process").Create("cmd.exe /c ipconfig /registerdns")

# After doing the above, flush your local DNS cache (requires elevation):
ipconfig /flushdns

# -----------------------------------------------------------------------------

# Check to make sure AD DNS names match Windows OS names
$query = "comp-name-*"
$comps = Get-ADComputer -Filter "name -like `"$query`""
Write-Host "Computers: $($comps.Name -join ", ")"
$comps.Name | ForEach-Object -Parallel {
	function log($msg) { Write-Host $msg }
	if(Test-Connection -TargetName $_ -IPv4 -Count 2 -Quiet -TimeoutSeconds 2) {
		$name = Invoke-Command -ComputerName $_ -ScriptBlock {
			$env:ComputerName
		}
	}
	else {
		$err = "$_ did not pong."
	}
	[PSCustomObject]@{
		Comp = $_
		Name = $name
		Error = $err
	}
} | Sort Comp

# -----------------------------------------------------------------------------

# Get resolution of monitors in a lab
# https://stackoverflow.com/questions/7967699/get-screen-resolution-using-wmi-powershell-in-windows-7
$monitors = foreach($int in @(1..39)) {
    $num = ([string]$int).PadLeft(2,"0")
    $name = "dcl-l520-$num"
    Get-CimInstance -ComputerName $name -Class Win32_VideoController
}
# Filter out any active remote desktop session resolutions
$monitors | Where { $_.Caption -notlike "*remote*" } | Select PSComputerName,Caption,CurrentHorizontalResolution,CurrentVerticalResolution,VideoModeDescription | Format-Table 

# -----------------------------------------------------------------------------

# Get monitor information
# https://learn.microsoft.com/en-us/answers/questions/216983/how-to-get-the-serial-number-of-the-monitors-using.html

$monitors = Get-CimInstance -ClassName "WmiMonitorID" -Namespace "root\wmi" -ComputerName "computer-name" | Select *
$monitors | ForEach-Object {
    $_ | Add-Member -NotePropertyName "Make" -NotePropertyValue ([System.Text.Encoding]::ASCII.GetString($_.ManufacturerName).Trim(0x00))
    $_ | Add-Member -NotePropertyName "ModelNum" -NotePropertyValue ([System.Text.Encoding]::ASCII.GetString($_.ProductCodeID).Trim(0x00))
    $_ | Add-Member -NotePropertyName "Serial" -NotePropertyValue ([System.Text.Encoding]::ASCII.GetString($_.SerialNumberID).Trim(0x00))
    $_ | Add-Member -NotePropertyName "ModelName" -NotePropertyValue ([System.Text.Encoding]::ASCII.GetString($_.UserFriendlyName).Trim(0x00))
    $_
} | Select PSComputerName,Active,Make,ModelName,ModelNum,Serial,WeekOfManufacture,YearOfManufacture,InstanceName | Format-Table

# -----------------------------------------------------------------------------

# This example shows both how to pull the most recently-modified file matching a given name
# and how to check if a text file contains a specific string

$latestLog = Get-ChildItem -Path "c:\engrit\logs" -Filter "filename_*.log" | Sort LastWriteTime -Descending | Select -First 1

$content = $latestLog | Get-Content
$string = "Some text."
if($content | Select-String -Pattern $string) {
	Write-Host "The file `"$($latestLog.Name)`" does contain the string `"$($string)`"."
}
else {
	Write-Host "The file `"$($latestLog.Name)`" does NOT contain the string `"$($string)`"."
}

# -----------------------------------------------------------------------------

# Count the number of lines, words, and characters across all text files in a given directory, with given extensions:
$path = ".\*"
$include = "*.php","*.js","*.html","*.ps1"
$exclude = "*.gif","*.jpg","*.png","*.psd1","*.xcf","*.zip"
Get-ChildItem -Path $path -File -Recurse -Include $include -Exclude $exclude | Get-Content | Measure-Object -Line -Word -Character

# -----------------------------------------------------------------------------

# Get the latest boot time of multiple machines:
# Relies on Get-UptimeHistory: https://github.com/engrit-illinois/Get-UptimeHistory
# Useful for running before and after a mass reboot, to compare and identify which machines successfully rebooted

$query = "computer-name-*"
$data = Get-ADComputer -Filter { Name -like $query } | ForEach-Object -TimeoutSeconds 300 -Parallel {
    $_ | Add-Member -PassThru -Force -NotePropertyName "_UptimeHistory" -NotePropertyValue (Get-UptimeHistory -ComputerName $_.Name -ErrorAction Ignore | Sort Date)
}
$summary = $data | Sort Name | Select Name,@{Name="LatestBoot";Expression={$_._UptimeHistory | Select -ExpandProperty Date | Select -Last 1}}
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$summary | Export-Csv -NoTypeInformation -Encoding "Ascii" -Path "c:\engrit\logs\UptimeHistory_$($ts).csv"
$summary

# -----------------------------------------------------------------------------

# Pull Name, NetID, and UIN for all members of a given AD group

$group = "engrit-usi-labs"
Get-ADGroup engrit-usi-labs | Get-ADGroupMember | Get-ADUser -Properties * | Select DisplayName,Name,uiucEduUIN

# -----------------------------------------------------------------------------

# Lock login session from command line
# https://www.howtogeek.com/686575/how-to-lock-your-windows-10-pc-using-command-prompt/

Rundll32.exe user32.dll,LockWorkStation

# -----------------------------------------------------------------------------

# Get video card model from multiple machines:
$comps = Get-ADComputer -Filter { Name -like "mel-1009-*" }
$cards = $comps | ForEach-Object {
    Get-CimInstance -ComputerName $_.Name -ClassName "Win32_VideoController"
}
$cards | Select PSComputerName,Name,Caption,Description

# -----------------------------------------------------------------------------

# Lock session via commandline
# https://www.cocosenor.com/articles/windows-10/8-ways-to-lock-computer-in-windows-10.html#way-6
rundll32.exe user32.dll,LockWorkStation

# -----------------------------------------------------------------------------

# Excel formula for pulling "<y>" out of a string formatted like "<x>-<y>-<z>", or "<x>-<y>".
# e.g. Pulls "9999" from "MEL-9999-01", or "TEST01" from "EWS-TEST01".
# Splitting a string like this in excel via a formula is, to this day, WAY harder than it should be.
# This can be done as a one-time operation using the "Text to columns" feature, but that is dumb.
# Without a proper "SPLIT()" function, you must cobble it together out of LEFT(), MID(), RIGHT(), and FIND() or SEARCH().
# And it only gets more complicated with more than 2 delimiters.

# a = value from cell with computer name
# b = length of computer name
# x = position of first hyphen
# y = position of second hyphen (or error if no second hyphen)
# z = length of second term (between first delimiter and second delimiter or end of string)

=LET(a,A2,b,LEN(a),x,FIND("-",a),y,FIND("-",a,x+1),z,IF(ISERROR(y),b,y-1),MID(a,x+1,z-x))

# -----------------------------------------------------------------------------

# Estimate how hard a spinning disk is being pegged

# Get list of counters
(Get-Counter -ListSet PhysicalDisk).PathsWithInstances

# Get current disk queue length counter
# Values over 1 are a good metric to identify if a disk is struggling
Get-Counter -Counter "\PhysicalDisk(0 C:)\Current Disk Queue Length"

# -----------------------------------------------------------------------------

# Get a quick list of all files/folders in the root of C:\ across multiple machines
$comps = Get-ADComputer -Filter "Name -like 'dcl-l520-*'" | Select -ExpandProperty Name
$files = $comps | ForEach-Object -Parallel {
    $cfiles = Get-ChildItem -Path "\\$($_)\c$\" | Select -ExpandProperty Name
    $cfilesString = $cfiles -join "`",`""
    [PSCustomObject]@{
        "Computer" = $_
        "CFiles" = $cfiles
        "CFilesString" = "`"$cfilesString`""
    }
}
$files | Select Computer,CFilesString | Sort Computer | Format-Table

# -----------------------------------------------------------------------------

# Quickly test whether RDP is responding on a machine:
# https://deploymentbunny.com/2014/07/02/powershell-is-kingtest-rdp-connection-and-connect/
$comp = "computer-name-01"
Test-NetConnection -ComputerName $comp -CommonTCPPort RDP

# Test on multiple machines:
$query = "computer-name-*"
$searchbase = "OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"
$comps = Get-ADComputer -SearchBase $searchbase -Filter "name -like `"$query`"" | Select -ExpandProperty Name
$results = $comps | ForEach-Object -ThrottleLimit 50 -Parallel {
    Write-Host "Testing `"$_`"..."
    Test-NetConnection -ComputerName $_ -CommonTCPPort "RDP"
}
$results | Format-Table -AutoSize

# -----------------------------------------------------------------------------

# Get last "DescUpdated" date from EngrIT IS custom AD description format for target computers
# Relies on other custom functions in mseng3's profile
Get-ADComputerLike "dcl-l520-*" | Select Name,@{"Name"="Description";"Expression"={($_.Description -split ";")[($strings.length - 2)]}}

# -----------------------------------------------------------------------------

# Get a report of TPM-related settings from a list of machines
# https://docs.microsoft.com/en-us/powershell/module/trustedplatformmodule/?view=windowsserver2022-ps
function Get-TpmInfo($query) {
	$searchbase = "OU=Instructional,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"
	$comps = Get-ADComputer -SearchBase $searchbase -Filter "name -like `"$query`"" | Select -ExpandProperty Name
	$results = $comps | ForEach-Object -ThrottleLimit 100 -Parallel {
		Write-Host "Polling `"$_`"..."
		Invoke-Command -ComputerName $_ -ScriptBlock { Get-Tpm }
	}
	$results | Sort PSComputerName | Select PSComputerName,TpmPresent,TpmReady,TpmEnabled,TpmActivated,TpmOwned,ManufacturerVersion,AutoProvisioning | Format-Table
}
Get-TpmInfo "dcl-l*-*"

# -----------------------------------------------------------------------------

# Get AD info for local computer/user without RSAT installed
# https://social.technet.microsoft.com/forums/windowsserver/en-US/fd0b0a1c-b6dc-4657-8a95-21b6a11377df/using-ad-module-without-loading-rsat?forum=winserverpowershell

$user = "user"
$adInfo = (([adsisearcher]"(&(objectCategory=User)(samaccountname=$user))").findall()).properties
$adInfo

$comp = "computer-name-01"
$adInfo = (([adsisearcher]"(&(objectCategory=Computer)(name=$comp))").findall()).properties
$adInfo

# -----------------------------------------------------------------------------

# Get LastLogon and LastLogonTimestamp attributes of all AD computer objects in an OU, and display them in a readable format
# Note these caveats to the accuracy of these attributes: https://stackoverflow.com/a/25898184/994622
# To summarize:
# - LastLogon is more accurate, but is not replicated across DCs, so you must query all DCs to find the latest LastLogon
# - LastLogonTimestamp is replicated, but is only accurate to ~1-2 weeks.
Get-ADComputer -Filter "name -like 'esb-5101-*'" -SearchBase "OU=PHYS,OU=Instructional,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu" -Properties * | Select Name,@{N='LastLogon'; E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}},@{N='LastLogonTimestamp'; E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}}

# -----------------------------------------------------------------------------

# Create/set/get/delete a system-level ("Machine"-level) environment variable:
# https://www.delftstack.com/howto/powershell/powershell-refresh-environment-variables/
# https://adamtheautomator.com/powershell-environment-variables/
# https://www.itprotoday.com/powershell/powershell-one-liner-creating-and-modifying-environment-variable
# https://www.digitalcitizen.life/remove-edit-clear-environment-variables/
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables?view=powershell-7.2

# Note to manipulate system-level ("Machine"-level) scoped environment variables, you MUSt use the .NET syntax.
# The variable syntax and Net/Set/Get-Item cmdlet syntax can only manipulate user/process/session scoped variables.

# Create/set
[Environment]::SetEnvironmentVariable("Name", "Value", "Machine")

# Get
[Environment]::GetEnvironmentVariable("Name","Machine")

# Delete
[Environment]::SetEnvironmentVariable("Name", "", "Machine")

# -----------------------------------------------------------------------------

# Re-use an existing function in the parent scope/runspace inside a ForEach-Object -Parallel loop:
# https://tighetec.co.uk/2022/06/01/passing-functions-to-foreach-parallel-loop/

# Define function
$letter = "A"
function Test-Function($number) {
	Write-Host "Test $letter $number"
}

# Save function as string variable
$testFunction = ${function:Test-Function}.ToString()
 
@(1, 2, 3) | ForEach-Object -Parallel {
	# Recreate function in local parallel scope
	${function:Test-Function} = $using:testFunction
	
	# Make sure to also define any parent-scope variables used by the function!
	$letter = $using:letter
	
	# Use function
    	Test-Function $_
}

# -----------------------------------------------------------------------------

# Get extended OS version info, including build revision number (UBR):

$comps = Get-ADComputer -SearchBase "OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu" -Filter "name -like 'gelib-057-*'" | Select -ExpandProperty Name
$creds = Get-Credential "uofi\mseng3"
$revs = $comps | ForEach-Object -Parallel {
	$creds = $using:creds
	Write-Host "Processing $_..."
	$data = Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' }
	$data | Add-Member -NotePropertyName "Computer" -NotePropertyValue $_
	$data
}
$revs | Select Computer,CurrentMajorVersionNumber,CurrentMinorVersionNumber,CurrentBuild,CurrentBuildNumber,UBR,DisplayVersion,ReleaseId | Sort Computer | Format-Table

# P.S. Microsoft appears to have deprecated the "ReleaseId" property, in favor of "DisplayVersion".
# https://learn.microsoft.com/en-us/answers/questions/162274/confused-about-windows-10-release-id.html
# https://borncity.com/win/2021/05/26/windows-10-21h1-reports-releaseid-2009/
# https://forum.bigfix.com/t/windows-10-releaseid-or-display-version/38226/3

# Here's a version that works for machines which don't have PSRemoting configured, and can be authenticated via a local admin:
# https://stackoverflow.com/questions/7030887/how-to-get-the-data-from-a-value-from-the-registry-using-powershell
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-itemproperty?view=powershell-7.2&viewFallbackFrom=powershell-7.1#parameters
function Get-OsBuild($comp) {
	$creds = Get-Credential "$comp\Administrator"
	
	$hklm = 2147483650
	$key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
	
	$wmi = Get-WMIObject -List "StdRegProv" -Namespace "root\default" -ComputerName $comp -Credential $creds
	
	$wmi.GetStringValue($hklm,$key,"ProductName").svalue
	$wmi.GetStringValue($hklm,$key,"DisplayVersion").svalue
	$wmi.GetStringValue($hklm,$key,"ReleaseId").svalue
	$wmi.GetDWORDValue($hklm,$key,"CurrentMajorVersionNumber").uvalue
	$wmi.GetDWORDValue($hklm,$key,"CurrentMinorVersionNumber").uvalue
	$wmi.GetStringValue($hklm,$key,"CurrentBuild").svalue
	$wmi.GetStringValue($hklm,$key,"CurrentBuildNumber").svalue
	$wmi.GetDWORDValue($hklm,$key,"UBR").uvalue
}
Get-OsBuild "computer-name"

# -----------------------------------------------------------------------------

# Dynamically combine/merge properties from two objects into a single object

# In this example, we'll merge objectA INTO objectB
$objectA = [PSCustomObject][ordered]@{ "prop1" = "string1"; "prop2" = 2 }
$objectA | Out-String

$objectB = [PSCustomObject][ordered]@{ "prop3" = "string3"; "prop4" = 4 }
$objectB | Out-String

# Merge objects:
# https://stackoverflow.com/questions/33380808/combine-object-properties-into-one-object-in-powershell
$objectAProps = $objectA | Get-Member -MemberType "NoteProperty"
$objectAProps | ForEach-Object {
    $objectB | Add-Member -NotePropertyName $_.Name -NotePropertyValue $objectA.$($_.Name)
}
$objectB | Out-String

# objectB's properties will be in the order they were added (e.g. prop 3, prop 4, prop 1, prop 2).
# Let's sort objectB's properties by their property name:
# https://stackoverflow.com/questions/23719057/sort-properties-of-object-powershell
$objectBProps = $objectB | Get-Member -MemberType "NoteProperty" | Select -ExpandProperty Name
$objectB | Select $objectBProps | Out-String

# -----------------------------------------------------------------------------

# Handy function for quickly returning the Distinguished Name (OUDN) and Canonical Name of OUs with a matching Name:
# Useful because many AD cmdlets have a "-SearchBase" parameter which accepts an OUDN.

function Get-Ou($name) {
	$ous = Get-ADOrganizationalUnit -Filter "name -like '$name'" -Properties *
	$ous | Select Name,CanonicalName,DistinguishedName
}

# Support wildcards, e.g.:
Get-Out "*name*"

# -----------------------------------------------------------------------------

# Demonstrate the Win10 problem which prevents identifying "old" user profiles for the purposes of deletion
# See this link for details about the problem: https://techcommunity.microsoft.com/t5/windows-deployment/issue-with-date-modified-for-ntuser-dat/m-p/102438
Get-ChildItem -Path "c:\users\*\ntuser.dat" -Hidden | Select "FullName","CreationTime","LastWriteTime","LastAccessTime" -First 50

# -----------------------------------------------------------------------------

# Test the current PowerShell version for compatibility checks

function Test-SupportedPowershellVersion {
	$ver = $Host.Version
	Write-Host "Powershell version is `"$($ver.Major).$($ver.Minor)`"." -L 1
	
	# Return $true if 5.1, or $false otherwise
	if(
		($ver.Major -eq 5) -and
		($ver.Minor -eq 1)
	) {
		return $true
	}
	return $false
}

# -----------------------------------------------------------------------------

# Copy a folder to the local drive of multiple machines in a lab

# Make this function available. See below for example usage.
# Change the parameter default values if you want. Right now they are most convenient for Matt's VMs.
function CopyFolderTo-Lab {
	param(
		[string]$Lab = "engrit-mms-tvm",
		[string]$Separator = "",
		[int[]]$Nums = @(0..9),
		[int]$NumCharCount = 1,
		[Parameter(Mandatory=$true)]
		[string]$Source, # Should be the path to a folder without a trailing slash and without an asterisk
		[string]$Destination = "c$",
		[switch]$Force # Overwrite if destination path/files already exist
	)
	
	function log($Msg, $L=0) {
		$ts = Get-Date -Format "HH:mm:ss"
		$indent = ""
		for($i = 0; $i -lt $L; $i += 1) {
			$indent = "    $indent"
		}
		Write-Host "[$($ts)]$($indent) $msg"
	}
	
	log "Beginning copy of `"$Source`" to `"$Lab`" lab..."
	
	$logFunction = ${function:log}.ToString()	
	$Nums | ForEach-Object -Parallel {
		${function:log} = $using:logFunction
		$Lab = $using:Lab
		$Separator = $using:Separator
		$NumCharCount = $using:NumCharCount
		$Source = $using:Source
		$Destination = $using:Destination
		$Force = $using:Force
		
		$num = ([string]$_).PadLeft($NumCharCount,"0")
		$comp = "$($Lab)$($Separator)$($num)"
		
		$dest = "\\$($comp)\$Destination"
		
		log "Copying to `"$dest`"..." 1
		
		# Must create destination folder if it doesn't exist, otherwise Copy-Item behaves differently:
		# https://stackoverflow.com/questions/35288023/copy-item-behaves-differently-depending-on-whether-target-folder-exists
		if(-not (Test-Path -PathType "Container" -Path $dest)) {
			New-Item -ItemType "Directory" -Force -Path $dest | Out-Null
		}
		
		$params = @{
			Force = $Force
		}
		
		Copy-Item -Path $Source -Destination $dest -Recurse -ErrorAction "Stop" @params
	}
	
	log "Done copying."
}

# Examples

# Copy "\\engr-wintools\packagedsoftware$\Lambda Research Corp\TracePro\23.10.23067" folder to C: drive on all Matt's test VMs
# e.g. Results in "\\engrit-mms-tvm#\c$\23.10.23067"
CopyFolderTo-Lab -Source "\\engr-wintools\packagedsoftware$\Lambda Research Corp\TracePro\23.10.23067"

# Copy ".\test" folder to "C:\blah" on all 3 machines in NCEB-2ND lab
# e.g. Results in "\\nceb-2nd-##\c$\blah\test"
CopyFolderTo-Lab -Lab "nceb-2nd" -Separator "-" -Nums @(1..3) -NumCharCount 2 -Source ".\test" -Destination "c$\blah"

# -----------------------------------------------------------------------------

# Find occurrences of a string in any text file in a folder
# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/findstr
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-string?view=powershell-7.3
Select-String -Path "\\engrit-mms-tvm0\c$\windows\ccm\logs\*.*" -Pattern "TracePro" | Select Filename,LineNumber,Line | Sort Filename,LineNumber | Format-Table -Wrap

# -----------------------------------------------------------------------------

# Quickly test for existence of a folder across many machines and output nicely formatted results
$comps = Get-ADComputer -Filter "name -like 'gelib-4c-*'" -SearchBase "OU=Instructional,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu" 
$results = $comps.Name | ForEach-Object -OutVariable "results" -Parallel {
    Invoke-Command -ComputerName $_ -ScriptBlock {
        [PSCustomObject]@{
            Name = $env:computername
            Exists = Test-Path -Path "c:\users\mseng3" -PathType "Container"
        }
    }
}
$results | Sort "Name" | Format-Table

# -----------------------------------------------------------------------------

# Get list of user profile folders across many machines
$comps = Get-ADComputer -Filter "name -like 'tl-206-*'" -SearchBase "OU=Instructional,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu" 
$results = $comps.Name | ForEach-Object -OutVariable "results" -Parallel {
    Invoke-Command -ComputerName $_ -ScriptBlock {
        [PSCustomObject]@{
            Name = $env:computername
            Profiles = Get-ChildItem -Path "c:\users"
        }
    }
}
$results | Sort "Name" | Select Name,{$_.Profiles.Name} | Format-Table

# -----------------------------------------------------------------------------

# Pull the status of a Windows Feature (.NET 3.5 in this case) from multiple machines
$comps = Get-ADComputer -Filter "name -like 'mel-1001-*'"
$comps | ForEach-Object -ThrottleLimit 25 -Parallel {
    Invoke-Command -ComputerName $_.Name -ScriptBlock {
        [PSCustomObject]@{
            "Computer" = $env:ComputerName
            ".NET3.5" = Get-WindowsOptionalFeature -Online -FeatureName "*NetFx3*" | Select -ExpandProperty "State"
        }
    }
} | Select "Computer",".NET3.5" | Sort "Computer" | ft

# -----------------------------------------------------------------------------

# Use CCTK to set, explort, or import BIOS settings, change BIOS passwords, etc.
# This has been made into its own module here: https://github.com/engrit-illinois/Invoke-CCTK

# -----------------------------------------------------------------------------

# This code is just a reminder and demonstration that PowerShell objects (but not primitives/strings) only contain a reference to the object in memory
# To truly get a unique copy of an object you must actually clone the underlying object in some way, so as to create an entirely new object.
# A simple way is demonstrated below. However note that this solution still only creates a "shallow" copy,
# i.e. any properties of the successfully cloned parent object which themselves contain objects will still be holding pointers to the same underlying objects present in the original parent object's properties.
# https://stackoverflow.com/a/60102611/994622
# https://stackoverflow.com/questions/9581568/how-to-create-new-clone-instance-of-psobject-object
# https://stackoverflow.com/questions/9204829/deep-copying-a-psobject/62559171#62559171
# https://www.reddit.com/r/PowerShell/comments/6rq03i/powershell_challenge_create_a_copy_of_a_hashtable/

# $hash2 is a "copy" of $hash1, but both variables actually just contain references to the same object in memory, so modifying $hash2 also modifies $hash1
$hash1 = @{ foo = "apple" }
$hash2 = $hash1
$hash2.bar = "banana"
Write-Host $hash1.bar # Returns "banana"

# $hash4 is a "real" copy of $hash3, i.e. each variable contains a reference to a different object in memory, thus modifying $hash4 does NOT also modify $hash3
$hash3 = @{ foo = "apple" }
$hash4 = $hash3.PSObject.Copy()
$hash4.bar = "banana"
Write-Host $hash3.bar # Returns nothing

# As a side note, be aware that while $var.PSObject.Copy() will throw an error when $var is explicitly equal to $null, if $var is equal to the "enumerable null" or "automation null", it will succeed.
# It may be preferable to use the clone() method for a particular object, should that object type implement it.
# https://stackoverflow.com/a/79300085/994622
# https://stackoverflow.com/questions/79296217/what-is-the-difference-between-null-and-the-empty-output-of-where-object
# https://stackoverflow.com/questions/22343187/why-is-an-empty-powershell-pipeline-not-the-same-as-null
# https://docs.microsoft.com/en-US/dotnet/api/System.Management.Automation.Internal.AutomationNull.Value
# https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-null?view=powershell-7.4

$a = $null # Sets $a explicitly to $null
$null -eq $a # Returns $true
$a.PSObject.Copy() # Throws "You cannot call a method on a null-valued expression."

$b = Get-Process | Where-Object { $false } # Sets $b to the "automation null"
$null -eq $b # Returns $true
$c = $b.PSObject.Copy() # Succeeds
$null -eq $c # Returns $false

# -----------------------------------------------------------------------------

# Get product code from MSI without installing app:

function Get-MsiProductCode($msi) {
	function log($msg) { Write-Host $msg }
	log "`n`n`nMSI: `"$($msi)`":"
	log "=============================================================================================================================================================="
	
	# Try with Get-AppLockerFileInformation
	$app = Get-AppLockerFileInformation -Path $msi
	log "`nAppLockerFileInformation:"
	log "-------------------------"
	$app | Format-List

	# Try by making the MSI generate a log and parsing it
	$log = "c:\engrit\logs\temp-product-code-log.log"
	# Just manually cancel out of the installer GUI when it launches; the log will still be generated
	Start-Process -Wait -FilePath "msiexec.exe" -Argumentlist "/i",$msi,"/l*v",$log
	$regex = '[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12}'
	$results = Select-String -Path $log -Pattern $regex
	Remove-Item -Path $log -Force
	log "`nLog info:"
	log "---------"
	$results
	log "`n=============================================================================================================================================================="
}

Get-MsiProductCode "\\engr-wintools\packagedsoftware$\FreeFlyer\7.4\Installer\FreeFlyer_7.4.1.52527_Installer.msi"

# -----------------------------------------------------------------------------

# Enable multi-line pasting in Windows Terminal
# This code edits your terminal's settings.json file and removes some lines, which enables native multi-line pasting (why isn't this default behavior?)
# Note: the settings.json path may need to be modified, for different versions of Windows Terminal (specifically for the Preview branch)

# Update: It looks like the regex for finding/replacing the necessary lines is no longer working. Need to troubleshoot.
# The lines to be removed look like this, and are under the "actions" node:
<#
    {
        "command": "paste",
        "id": "User.paste",
        "keys": "ctrl+v"
    },
#>
# The regex is supposed to match everything between the first and third lines above (including the curly brackets with any whitespace between)

# Note: newer version of settings.json seem to separate this between the "actions" node and "keybindings" node, like so:
<#
    "actions": 
    [
        {
            "command": "paste",
            "id": "User.paste"
        }
    ],
    "keybindings": 
    [
        {
            "id": "User.paste",
            "keys": "ctrl+v"
        }
    ]
#>

$path = "$($env:LocalAppData)\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
$content = Get-Content $path | Out-String
$regex = '{\s*"command": "paste",\s*"keys": "ctrl\+v"\s*},\s*'
$newContent = $content -replace $regex,""
$newContent | Set-Content $path

# -----------------------------------------------------------------------------

# Test running commands as the system account:
# Note: you may be slapped by TS Security for this when Crowdstrike reports it.

# From an elevated prompt:
psexec.exe -s powershell.exe # For v5.1. Use pwsh.exe for v7.

# From a standard prompt:
Start-Process -FilePath "psexec.exe" -Verb "RunAs" -ArgumentList "-s powershell.exe"

# On remote machine
Start-Process -FilePath "psexec.exe" -Verb "RunAs" -ArgumentList "\\comp-name-01 -s powershell.exe"

# -----------------------------------------------------------------------------

# Get-Process doesn't provide user info
# This code gathers it from WMI and combines it with info from Get-Process
# https://stackoverflow.com/a/35195953/994622
# https://devblogs.microsoft.com/scripting/get-process-owner-and-other-info-with-wmi-and-powershell/
$procs = Get-CimInstance Win32_Process | Where { ($_.ProcessName -eq "pwsh.exe") -or ($_.ProcessName -eq "powershell.exe") }
$procsWithOwner = $procs | ForEach-Object {
    $owner = Invoke-CimMethod -InputObject $_ -MethodName "GetOwner" | Select -ExpandProperty "User"
    $_ | Add-Member -NotePropertyName "Owner" -NotePropertyValue $owner -PassThru
}
$procsWithOwner | Select Name,ProcessId,Owner

# -----------------------------------------------------------------------------

# Get a report of all user profile folders that exist on a set of machines

$comps = Get-AdComputerName dcl-l520-*,siebl-0403a-*,gelib-057-*
$data = $comps | ForEach-Object -ThrottleLimit 50 -Parallel {
	$comp = $_
	$users = Get-ChildItem -Path "\\$_\c`$\Users"
	$users | ForEach-Object {
		$_ | Add-Member -NotePropertyName "Computer" -NotePropertyValue $comp -PassThru
	}
	Write-Host "$comp`n    $($users.Name)"
}
$ts = Get-Date -Format "FileDateTime"
$data | Sort "Computer","Name" | Export-CSV -Path "c:\engrit\logs\cbtf-users_$($ts).csv"

# -----------------------------------------------------------------------------

# Delete all user profile folders except given exceptions on a set of machines.
# Note: this should NOT be used to delete actual profiles, just profile folders. This code is intended for use when orphaned profile folders exist for non-existent profiles.

$comps = Get-AdComputerName siebl-0403a-01 -SearchBase "OU=CBTF,OU=Instructional,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"
$comps | ForEach-Object -ThrottleLimit 50 -Parallel {
	Invoke-Command -ComputerName $_ -ScriptBlock {
		$profiles = Get-CIMInstance -ClassName "Win32_UserProfile" -OperationTimeoutSec 300
		$profiles = $profiles | Where { $_.LocalPath -notlike "*$env:SystemRoot*" }
		$profiles = $profiles | Where { $_.LocalPath -notlike "*mseng3*" }
		$profiles = $profiles | Where { $_.LocalPath -notlike "*ews-labadm*" }
		$folders = Get-ChildItem -Path "c:\users"
		$folders2 = $folders | Where { $_.Name -notlike "*public*" }
		$folders2 = $folders2 | Where { $_.Name -notlike "*mseng3*" }
		$folders2 | ForEach-Object {
			$_ | Remove-Item -Recurse -Force
		}
		$folders3 = Get-ChildItem -Path "c:\users"
		Write-Host "$($env:computername): Profiles: `"$($profiles.count)`", Folders: `"$($folders.count)`", Deletable folders: `"$($folders2.count)`", Folders after deletion: `"$($folders3.count)`""
	} *>&1
}

# -----------------------------------------------------------------------------

# Passing named parameters as arguments to PowerShell.exe process
# https://stackoverflow.com/questions/76581014/powershell-how-to-give-args-to-a-powershell-script-launched-from-command-line
# https://stackoverflow.com/questions/56551242/how-to-specify-switch-parameter-when-calling-a-script-from-batch-file

powershell.exe -Command "& \"%~dp0\foo.ps1\" -Name 'abc' -MySwitch:$false"

# -----------------------------------------------------------------------------

# These functions will log the ancestry of the process running the script.
# Useful if you need to configure a local firewall to allow communication from a script process, its parents, and the user(s) running those processes

function log($msg) { Write-Host $msg }

function Log-Process($process, $level) {
	$indent = ""
	for($i = 0; $i -lt $level; $i += 1) {
		$indent = "    $indent"
	}
	$start = "Process"
	if($level -gt 0) { $start = "Parent process" }
	$id = $process.Id
	$name = $process.Name
	$desc = $process.Description
	$path = $process.Path
	
	$ownerUser = "<unknown>"
	$processWmi = Get-CimInstance -Class "Win32_Process" -Filter "ProcessId='$id'"
	$owner = $processWmi | Invoke-CimMethod -MethodName "GetOwner" -ErrorAction "SilentlyContinue"
	if($owner) { $ownerUser = $owner | Select -ExpandProperty "User" }
	
	$parentId = $processWmi.ParentProcessId
	$parent = $process.Parent
	$parentName = "<unknown>"
	if($parent) { $parentName = $parent.Name }
	
	$cmd = "<unknown>"
	if($process.CommandLine) { $cmd = $process.CommandLine }
	
	log "$($indent)$($start) is ID: `"$id`", Name: `"$name`", Description: `"$desc`", Path: `"$path`", Owner: `"$ownerUser`", Parent ID: `"$parentId`", Parent Name: `"$parentName`", CommandLine: $cmd"
	
	if($parent) {
		Log-Process $parent ($level + 1)
	}
}

function Log-ProcessWmi($process, $level) {
	$indent = ""
	for($i = 0; $i -lt $level; $i += 1) {
		$indent = "    $indent"
	}
	$start = "Process"
	if($level -gt 0) { $start = "Parent process" }
	$id = $process.ProcessId
	$name = $process.ProcessName
	$desc = $process.Description
	$path = $process.Path
	
	$ownerUser = "<unknown>"
	$owner = $process | Invoke-CimMethod -MethodName "GetOwner" -ErrorAction "SilentlyContinue"
	if($owner) { $ownerUser = $owner | Select -ExpandProperty "User" }
	
	$parentId = $process.ParentProcessId
	$parent = Get-CimInstance -Class "Win32_Process" -Filter "ProcessId='$parentId'"
	$parentName = "<unknown>"
	if($parent) { $parentName = $parent.Name }
	
	$cmd = "<unknown>"
	if($process.CommandLine) { $cmd = $process.CommandLine }
	
	log "$($indent)$($start) is ID: `"$id`", Name: `"$name`", Description: `"$desc`", Path: `"$path`", Owner: `"$ownerUser`", Parent ID: `"$parentId`", Parent Name: `"$parentName`", CommandLine: $cmd"
	
	if($parent) {
		Log-Process $parent ($level + 1)
	}
}

function Log-ProcessInfo {
	$user = whoami
	log "Running as `"$user`"."
	
	log "Logging process info via Get-Process cmdlet..."
	$process = [System.Diagnostics.Process]::GetCurrentProcess()
	Log-Process $process 1
	
	log "Logging process info via Get-CimInstance cmdlet..."
	$processWmi = Get-CimInstance -Class "Win32_Process" -Filter "ProcessId='$($process.Id)'"
	Log-ProcessWmi $processWmi 1
}

# Usage:
Log-ProcessInfo

# -----------------------------------------------------------------------------

# This code will nslookup the IPv4 address of a given domain/subdomain, a given number of times, and report all of the unique IPs that were resolved.
# Useful for learning the majority of IPs that might be used for an internet service using load distribution, or other IP trickery.

function Resolve-AllIpsOfHostname {
	param(
		[string]$Hostname,
		[int]$TestCount = 60,
		[int]$TestIntervalSeconds = 1,
		[switch]$PassThru
	)
	
	function log {
		param(
			[string]$Msg,
			[switch]$NoNewline
		)
		$params = @{
			Object = $Msg
			NoNewline = $false
		}
		if($NoNewline) { $params.NoNewline = $true }
		Write-Host @params
	}
	
	function Do-Stuff {
		$allIps = @()
		
		log "Polling `"$Hostname`" $TestCount times, once every $TestIntervalSeconds second(s)..."
		for($i = 0; $i -lt $TestCount; $i += 1) {
			$attempt = $i + 1
			log "    Attempt #$($attempt): " -NoNewline
			$results = $null
			$results = Resolve-DnsName -Name $Hostname
			if($results) {
				$resultsCount = $results.count
				#log "        $resultsCount results."
				
				$attemptIps = @()
				$results | ForEach-Object {
					$result = $_
					if($result.QueryType.ToString() -eq "A") {
						if($result.IP4Address) {
							$attemptIps += @($result.IP4Address)
						}
					}
				}
				if($attemptIps) {
					$attemptIpsCount = $attemptIps.count
					if($attemptIpsCount -eq 0) {
						log "Found IPs, but the count was 0!"
					}
					elseif($attemptIpsCount -eq 1) {
						log $attemptIps
						$allIps += @($attemptIps)
					}
					else {
						$attemptIpsString = $attemptIps -join ", "
						log $attemptIpsString
						$allIps += @($attemptIps)
					}
				}
				else {
					log "Found no IPs!"
				}
			}
			else {
				log "No results!"
			}
			Start-Sleep -Seconds $TestIntervalSeconds
		}
		log "Done polling."
		
		if($allIps) {
			$allIpsCount = $allIps.count
			$allIpsString = $allIps -join ", "
			log "`nFound $allIpsCount total IPs: $allIpsString."
			
			$uniqueIps = $allIps | Select -Unique
			$uniqueIpsCount = $uniqueIps.count
			#$uniqueIpsString = $uniqueIps -join ", "
			log "`nFound $uniqueIpsCount unique IPs:"
			$uniqueIps | ForEach-Object { log "    $_" }
			
			if($PassThru) {
				$uniqueIps
			}
		}
		else {
			log "`nFound no IPs!"
		}
	}
	
	Do-Stuff
}

# Usage:
Resolve-AllIpsOfHostname "dl.dell.com" -TestCount 600

# -----------------------------------------------------------------------------

# This code repeats a Get-NetTCPConnection (i.e. netstat) every second and looks for connections to a specific IP
# Useful for learning whether a certain action relies on contacting a specific host, which executable is actually performing that communication, and which user owns that process
# Which is useful for creating firewall rules

$ip = "172.22.230.162"
$timeoutSeconds = 10
$results = (1..$timeoutSeconds) | ForEach-Object {
	Write-Host $_
	$hits = $null
	$hits = Get-NetTCPConnection -State "Established" -RemoteAddress $ip -ErrorAction "SilentlyContinue"
	$ts = Get-Date
	$hits | ForEach-Object {
		$hit = $_
		$processId = $hit.OwningProcess
		$process = Get-Process -Id $processId
		$hit | Add-Member -NotePropertyName "TimeSeen" -NotePropertyValue $ts
		$hit | Add-Member -NotePropertyName "Process" -NotePropertyValue $process -PassThru
	}
	Start-Sleep -Seconds 1
}

$results | Select TimeSeen,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,{$_.Process.Name},{$_.Process.Path} | Format-Table

# -----------------------------------------------------------------------------

# Pulls the version of Microsoft Edge from multiple remote computers
# Note: The "AppxProvisionedPackageVersion" will likely be whatever version the machine had when it was imaged.
# The other versions should reflect the version of the live, installed app.

$comps = Get-ADComputer -Filter "*" -SearchBase "OU=CBTF,OU=Urbana,DC=ad,DC=uillinois,DC=edu"

$results = $comps | ForEach-Object -ThrottleLimit 50 -Parallel {
	$comp = $_.Name
	try {
		Invoke-Command -ComputerName $comp -ErrorAction "Stop" -ScriptBlock {
			try {
				$appxPackage = Get-AppxProvisionedPackage -Online -ErrorAction "Stop" | Where { $_.DisplayName -eq "Microsoft.MicrosoftEdge.Stable" }
				$exe = Get-ItemProperty "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ErrorAction "Stop"
				$regItem = Get-Item "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" -ErrorAction "Stop" | Get-ItemProperty -ErrorAction "Stop"
			}
			catch {
				$err = $_
				$errMsg = $err.Exception.Message
			}

			[PSCustomObject]@{
				ComputerName = $env:ComputerName
				AppxProvisionedPackageVersion = $appxPackage.Version
				ExeFileVersion = $exe.VersionInfo.FileVersion
				ExeProductVersion = $exe.VersionInfo.ProductVersion
				RegistryDisplayVersion = $regItem.DisplayVersion
				RegistryVersion = $regItem.Version
				Error = $errMsg
			}
		}
	}
	catch {
		$err = $_
		$errMsg = $err.Exception.Message
		
		[PSCustomObject]@{
			ComputerName = $comp
			Error = $errMsg
		}
	}
}

$results | Select -ExcludeProperty PSComputerName,RunspaceId | Sort ComputerName | ft

# -----------------------------------------------------------------------------

# Using the first-party Microsoft PowerShell SecretStore module to create a local secrets vault
# Useful for securely storing and conveniently using service account credentials, for example
# https://learn.microsoft.com/en-us/powershell/utility-modules/secretmanagement/get-started/using-secretstore?view=ps-modules

# Create the vault
Install-Module Microsoft.PowerShell.SecretManagement
Install-Module Microsoft.PowerShell.SecretStore
Import-Module Microsoft.PowerShell.SecretManagement
Import-Module Microsoft.PowerShell.SecretStore
Register-SecretVault -Name "MyVault" -ModuleName Microsoft.Powershell.SecretStore -DefaultVault

# Create a secret
$creds = Get-Credential
Set-Secret -Name "MyServiceAccount" -Vault "MyVault" -Secret $creds

# List secrets
Get-SecretInfo

# Retrieve a secret
Get-Secret -Name "MyServiceAccount"

# Use a secret in-line
Do-SomethingThatRequiresCredentials -Credential (Get-Secret -Name "MyServiceAccount")

# -----------------------------------------------------------------------------

# For a given AD OU, return the number of different kinds of AD objects inside the given OU and each immediate sub-OU.
# Useful for checking whether any unexpected objects exist in a given OU its sub-OUs, in preparation for deleting an entire OU.
# The output will list one column for each 

# Keep track of which types of objects exist in all of the target OUs
$propsToSelect = @("CanonicalName")

# For the parent OU and each immediate sub-OU
$ous = Get-ADOrganizationalUnit -Filter "*" -SearchBase "OU=Students,OU=Classes,OU=UsersAndGroups,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu" -Properties $propsToSelect | ForEach-Object {
	$ou = $_
	
	# Get all objects in this OU/sub-OU
	# Using -SearchScope 1 so as to only look at immediate children
	# https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adobject?view=windowsserver2025-ps#-searchscope
	$objects = Get-ADObject -Filter "*" -SearchScope 1 -SearchBase $ou.DistinguishedName
	
	# If there are any objects
	$objectsCount = 0
	if($objects) {
		$objectsCount = @($objects).count
		
		# Get an array containing a list of the different unique types of objects that exist
		$uniqueTypes = $objects | Select -ExpandProperty "ObjectClass" | Select -Unique
		
		# For each type of object
		$uniqueTypes | ForEach-Object {
			$type = $_
			
			# Keep track of which object types exist across all target OUs
			$typeCountProperty = "$($type)Count"
			$propsToSelect += @($typeCountProperty)
			
			# Keep track of how many of this object type exists in this OU/sub-OU
			$objectsOfType = $objects | Where { $_.ObjectClass -eq $type }
			$objectsOfTypeCount = 0
			if($objectsOfType) { $objectsOfTypeCount = @($objectsOfType).count }
			$ou | Add-Member -NotePropertyName $typeCountProperty -NotePropertyValue $objectsOfTypeCount -Force
		}
	}
	$ou
}

# Output results
$propsToSelect = $propsToSelect | Select -Unique
# Note that a value of "{}" (i.e. an empty array) is just what AD cmdlets return object types return when selecting non-existent properties from them, for some reason.
# This just means that there are 0 of that object type under that OU.
# If there are no columns for a certain type of object (e.g. no "userCount") column, that means that none of the OUs contained any objects of that type.
# So if a column exists in the output, at least one OU should contain an object of that type.
$ous | Select $propsToSelect | Sort "CanonicalName"

# -----------------------------------------------------------------------------

# Determine whether a network adapter is connected, disconnected, disabled, etc. on multiple machines

$laptops = Get-ADComputerName "cbtf-cart01-*"
$adapters = $laptops | ForEach-Object -ThrottleLimit 40 -Parallel {
    Invoke-Command -ComputerName $_ -ScriptBlock {
        Get-NetAdapter | Select *
    }
}

$adapters | Where { $_.InterfaceDescription -eq "Intel(R) Wi-Fi 6 AX201 160MHz" } | Select "PSComputerName","InterfaceDescription","Status" | Sort "PSComputerName"

# -----------------------------------------------------------------------------

# Various API documentation:

# Lens
# https://answers.uillinois.edu/search.php?q=lens+api
# https://github.com/engrit-illinois/Get-LensInfo
# https://github.com/engrit-illinois/Get-LensObject
# https://github.com/engrit-illinois/lens-new-api-testing

# Infoblox (IPAM)
# https://wiki.illinois.edu/wiki/display/ipamdocs/Using+the+IPAM+API
# https://ipam.illinois.edu/wapidoc/
# https://ipam.illinois.edu/wapidoc/additional/sample.html
# https://community.infoblox.com/t5/API-Integration/The-definitive-list-of-REST-examples/m-p/1214/highlight/true#M2
# https://www.infoblox.com/wp-content/uploads/infoblox-deployment-infoblox-rest-api.pdf
# https://github.com/engrit-illinois/New-IpamHostRecord
# https://github.com/engrit-illinois/Set-IpamHostRecord
# https://github.com/engrit-illinois/Add-MacToIpamIpv4MacFilter
# https://github.com/engrit-illinois/Get-IpamIpv4MacFilterEntry

# TDX
# https://github.com/techservicesillinois/SecOps-Powershell-TDXTickets/

# Confluence
# https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-page/#api-pages-get

# -----------------------------------------------------------------------------

