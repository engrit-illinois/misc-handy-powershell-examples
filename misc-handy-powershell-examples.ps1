# Documentation home: https://github.com/engrit-illinois/misc-handy-powershell-examples
# By mseng3

# To prevent anyone from blindly running this as a script:
Exit

# -----------------------------------------------------------------------------

# Do something on multiple computers remotely
$comps = Get-ADComputer -Filter { Name -like "gelib-4c-*" }
foreach($comp in $comps.Name) {
    Write-Host "Processing $comp..."
    Invoke-Command -ComputerName $comp -ScriptBlock {
        # Do stuff here
    }    
}

# -----------------------------------------------------------------------------

# Create a new shortcut
$pathLNK = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Protege.lnk"
$pathTarget = "C:\Program Files\Protege.exe"

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($pathLNK)
$shortcut.TargetPath = $pathTarget
$shortcut.Save()

# -----------------------------------------------------------------------------

# Create large dummy files
# https://www.windows-commandline.com/how-to-create-large-dummy-file/
Invoke-Command -ComputerName "computer-name" -ScriptBlock { fsutil file createnew c:\bigtestfile.txt 100000000000 } #100GB

# -----------------------------------------------------------------------------

# Find large files
# https://social.technet.microsoft.com/Forums/ie/en-US/838ed753-2bcf-49b8-9321-775c5ef12f13/finding-largest-files?forum=winserverpowershell
Get-ChildItem "c:\temp\*" -Recurse -File | Sort "length" -Descending | Select "length","fullname" -First 10 #10 largest
# Alias
dir "c:\temp\*" -Recurse -File | Sort "length" -Descending | Select "length","fullname" -First 10

# -----------------------------------------------------------------------------

# Empty recycle bins
# https://github.com/PowerShell/PowerShell/issues/6743
# https://serverfault.com/questions/822514/clear-recyclebin-on-remote-computer-fails
Invoke-Command -ComputerName "computer-name" -ScriptBlock { Clear-RecycleBin -Force -DriveLetter C }

# -----------------------------------------------------------------------------

# Run disk cleanup remotely
# http://www.theservergeeks.com/how-todisk-cleanup-using-powershell/

# -----------------------------------------------------------------------------

# Blow away all default-location Dropbox folders on a set of machines:
$ErrorActionPreference = 'SilentlyContinue' 
$pcs = Get-ADComputer -filter 'name -like "computer-name-*"'
foreach($pc in $pcs.Name) {
    invoke-command -computername $pc -scriptblock {remove-item "c:\users\*\dropbox" -recurse -force -ErrorAction Ignore}
    invoke-command -computername $pc -ScriptBlock {remove-item "c:\users\*\AppData\Local\Dropbox" -recurse -force -ErrorAction Ignore}
}

# -----------------------------------------------------------------------------

# Ping multiple machines
# Test-ConnectionAsync is a custom module: https://gallery.technet.microsoft.com/scriptcenter/Multithreaded-PowerShell-0bc3f59b#content
Import-Module "~/temp/powershell scripts/Test-ConnectionAsync.ps1m"
(Get-ADComputer -Filter { Name -like "computer-name-*" }).Name | Test-ConnectionAsync -Count 1 | Format-Table

# -----------------------------------------------------------------------------

# Find GPO named like...
$query = "engr ews*license*"
$gpos = Get-GPO -All -Domain "ad.uillinois.edu" | Where { $_.DisplayName -like $query }
$gpos | Select DisplayName,Id

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
Get-Content (Get-PSReadlineOption).HistorySavePath | ? { $_ -like '*adobe*' }

# Previous session history file location:
(Get-PSReadlineOption).HistorySavePath
# i.e. "C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

# -----------------------------------------------------------------------------

# Find the MSI product code for an application
# https://stackoverflow.com/questions/29937568/how-can-i-find-the-product-guid-of-an-installed-msi-setup
# This can take a while to run
$apps = get-wmiobject Win32_Product
$apps | Select Name,IdentifyingNumber | Sort Name

# -----------------------------------------------------------------------------

# Handy, feature-rich log function by mseng3

# If you're making a module, you can use this, otherwise you can take them out of the param() and just make them global variables.
param(
	# Uncomment one of these depending on whether output goes to the console by default or not, such that the user can override the default
	#[switch]$ConsoleOutput,
	[switch]$NoConsoleOutput,
	
	[switch]$Log,
	[string]$LogPath = "c:\engrit\logs\logname_$(Get-Date -Format `"yyyy-MM-dd_HH-mm-ss`").log",
	[string]$Indent = "    ",
	[int]$Verbosity = 0,
	
	#[string]$LogTimestampFormat = "[yyyy-MM-dd HH:mm:ss:ffff] "
	[string]$LogTimestampFormat = "[HH:mm:ss] "
	#[string]$LogTimestampFormat = $null # For no timestamp
)

function log {
	param (
		[Parameter(Position=0)]
		[string]$Msg = "",

		[int]$L = 0, # level of indentation
		[int]$V = 0, # verbosity level
		
		[ValidateScript({[System.Enum]::GetValues([System.ConsoleColor]) -contains $_})]
		[string]$FC = (get-host).ui.rawui.ForegroundColor, # foreground color
		[ValidateScript({[System.Enum]::GetValues([System.ConsoleColor]) -contains $_})]
		[string]$BC = (get-host).ui.rawui.BackgroundColor, # background color
		
		[switch$E, # error
		[switch]$NoTS, # omit timestamp
		[switch]$NoNL, # omit newline after output
		[switch]$NoConsole, # skip outputting to console
		[switch]$NoLog # skip logging to file
	)
		
	if($E) { $FC = "Red" }
	
	# Custom indent per message, good for making output much more readable
	for($i = 0; $i -lt $L; $i += 1) {
		$Msg = "$Indent$Msg"
	}
	
	# Add timestamp to each message
	# $NoTS parameter useful for making things like tables look cleaner
	if(!$NoTS) {
		if($LogTimestampFormat) {
			$ts = Get-Date -Format $LogTimestampFormat
		}
		$Msg = "$ts$Msg"
	}

	# Each message can be given a custom verbosity ($V), and so can be displayed or ignored depending on $Verbosity
	# Check if this particular message is too verbose for the given $Verbosity level
	if($V -le $Verbosity) {
	
		# Check if this particular message is supposed to be output to console
		if(!$NoConsole) {

			# Uncomment one of these depending on whether output goes to the console by default or not, such that the user can override the default
			#if($ConsoleOutput) {
			if(!$NoConsoleOutput)
			
				# If we're allowing console output, then Write-Host
				if($NoNL) {
					Write-Host $Msg -NoNewline -ForegroundColor $FC -BackgroundColor $BC
				}
				else {
					Write-Host $Msg -ForegroundColor $FC -BackgroundColor $BC
				}
			}
		}

		# Check if this particular message is supposed to be logged
		if(!$NoLog) {

			if($Log) {
				# If we're allowing logging, then log to file
				
				# Check that the logfile already exists, and if not, then create it (and the full directory path that should contain it)
				if(!(Test-Path -PathType leaf -Path $LogPath)) {
					New-Item -ItemType File -Force -Path $LogPath | Out-Null
				}

				if($NoNL) {
					$Msg | Out-File $LogPath -Append -NoNewline
				}
				else {
					$Msg | Out-File $LogPath -Append
				}
			}
		}
	}
}

# -----------------------------------------------------------------------------

# Handy function for logging just the useful bits of error records in a readable format
# Designed for use with above log() function
# https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-exceptions?view=powershell-7.1

function Log-Error($e, $L) {
	log "$($e.Exception.Message)" -L $l
	log "$($e.InvocationInfo.PositionMessage.Split("`n")[0])" -L ($L + 1)
}

try {
	[System.IO.File]::ReadAllText( '\\test\no\filefound.log')
}
catch {
	log "Custom message explaining what happened in English" -L 1
	Log-Error $_ 2
}

# -----------------------------------------------------------------------------

# Handy function for logging whole objects as lists, while still preserving custom indentation
# Designed for use with above log() function
function Log-ObjectList($object) {
	$string = ($object | Format-List | Out-String)
	$string = $string.Replace("`n", "`n$Indent").Trim()
	$string = "$Indent$string"
	log $string
}

# -----------------------------------------------------------------------------

# Outputting ENTIRE error records in a readable format
# https://stackoverflow.com/a/57548069/994622

try {
	[System.IO.File]::ReadAllText( '\\test\no\filefound.log')
}
catch {
	Write-Host ($_ | ConvertTo-Json)
}

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

# Get the last logon timestamp for a group of machines:
# Must be run as your SU account to get the lastLogonTimestamp field data
# https://stackoverflow.com/questions/13091719/converting-lastlogon-to-datetime-format
$query = "esb-6104-*"
Get-ADComputer -Filter "name -like '$query'" -Properties * | Select Name,lastLogonTimestamp,@{Name="lastlogonTimestampDateTime";Expression={[datetime]::FromFileTime($_.lastLogonTimestamp)}}

# -----------------------------------------------------------------------------

# Search your Powershell command history for commands sent matching a given string:
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
