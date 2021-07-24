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
# This has been made into a proper module, here: https://github.com/engrit-illinois/Ping-All
# Test-ConnectionAsync is a custom module: https://gallery.technet.microsoft.com/scriptcenter/Multithreaded-PowerShell-0bc3f59b#content
Import-Module "~/temp/powershell scripts/Test-ConnectionAsync.ps1m"
(Get-ADComputer -Filter { Name -like "computer-name-*" }).Name | Test-ConnectionAsync -Count 1 | Format-Table

# -----------------------------------------------------------------------------

# Add multiple computer objects with sequentially-numbered and zero-padded names to an OU in AD
# e.g. "COMPUTER-NAME01", "COMPUTER-NAME02", etc.
foreach($int in @(1..10)) {
    $num = ([string]$int).PadLeft(2,"0")
    $name = "COMPUTER-NAME$($num)"
    New-ADComputer -Name $name -SamAccountName $name -Path "OU=MyOU,OU=Desktops,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"
}

# -----------------------------------------------------------------------------

# Rename a single computer and immediately restart
# Remove the -Restart parameter to not restart
Invoke-Command -ComputerName "COMP-NAME-OLD" -ScriptBlock { Rename-Computer -NewName "COMP-NAME-NEW" -DomainCredential "uofi\su-netid" -Force -Restart }

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
	Rename-Computer -DomainCredential $renameCreds -NewName $newName -Force -Restart
}

foreach($int in @(1..10)) {
    $num = ([string]$int).PadLeft(2,"0")
    $oldName = "COMP-OLDNAME-$($num)"
    $newName = "COMP-NEWNAME-$($num)"
    Invoke-Command -ComputerName $oldName -Credential $remoteCreds -ScriptBlock $scriptBlock -ArgumentList $newName,$renameCreds
}

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

# Logging parameters
# If you're making a module, you can use this param block, otherwise you can take them out of the param() and just make them global variables.
param(
	# ":ENGRIT:" will be replaced with "c:\engrit\logs\$($MODULE_NAME)_:TS:.log"
	# ":TS:" will be replaced with start timestamp
	[string]$Log,

	[switch]$NoConsoleOutput,
	[string]$Indent = "    ",
	[string]$LogFileTimestampFormat = "yyyy-MM-dd_HH-mm-ss",
	[string]$LogLineTimestampFormat = "[HH:mm:ss] ", # Minimal timestamp
	#[string]$LogLineTimestampFormat = "[yyyy-MM-dd HH:mm:ss:ffff] ", # Full timestamp
	#[string]$LogLineTimestampFormat = $null, # No timestamp
	[int]$Verbosity = 0
)

# Logic to determine final filename
$MODULE_NAME = "Module-Name"
$ENGRIT_LOG_DIR = "c:\engrit\logs"
$ENGRIT_LOG_FILENAME = "$($MODULE_NAME)_:TS:"
$START_TIMESTAMP = Get-Date -Format $LogFileTimestampFormat

if($Log) {
	$Log = $Log.Replace(":ENGRIT:","$($ENGRIT_LOG_DIR)\$($ENGRIT_LOG_FILENAME).log")
	$Log = $Log.Replace(":TS:",$START_TIMESTAMP)
}
if($Csv) {
	$Csv = $Csv.Replace(":ENGRIT:","$($ENGRIT_LOG_DIR)\$($ENGRIT_LOG_FILENAME).csv")
	$Csv = $Csv.Replace(":TS:",$START_TIMESTAMP)
}

# Actual log function
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

		[switch]$E, # error
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
		if($LogLineTimestampFormat) {
			$ts = Get-Date -Format $LogLineTimestampFormat
		}
		$Msg = "$ts$Msg"
	}

	# Each message can be given a custom verbosity ($V), and so can be displayed or ignored depending on $Verbosity
	# Check if this particular message is too verbose for the given $Verbosity level
	if($V -le $Verbosity) {

		# Check if this particular message is supposed to be output to console
		if(!$NoConsole) {

			# Check if we're allowing console output
			if(!$NoConsoleOutput) {

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

			# Check if we're allowing logging
			if($Log) {

				# Check that the logfile already exists, and if not, then create it (and the full directory path that should contain it)
				if(-not (Test-Path -PathType "Leaf" -Path $Log)) {
					New-Item -ItemType "File" -Force -Path $Log | Out-Null
					log "Logging to `"$Log`"."
				}

				if($NoNL) {
					$Msg | Out-File $Log -Append -NoNewline
				}
				else {
					$Msg | Out-File $Log -Append
				}
			}
		}
	}
}

# -----------------------------------------------------------------------------

# Handy function for logging just the useful bits of error records in a readable format
# Designed for use with above log() function
# https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-exceptions?view=powershell-7.1

function Log-Error($e, $L=0) {
	$msg = $e.Exception.Message
	$inv = ($e.InvocationInfo.PositionMessage -split "`n")[0]
	log $msg -L $l -E
	log $inv -L ($L + 1) -E
}

try {
	[System.IO.File]::ReadAllText( '\\test\no\filefound.log')
}
catch {
	log "Custom message explaining what happened in English" -L 1
	Log-Error $_ 2
}

# -----------------------------------------------------------------------------

# Handy function for logging whole objects, while still preserving custom timestamp and indentation markup
# Designed for use with above log() function
function Log-Object {
	param(
		[PSObject]$Object,
		[string]$Format = "Table",
		[int]$L = 0,
		[int]$V = 0,
		[switch]$NoTs,
		[switch]$E
	)
	if(!$NoTs) { $NoTs = $false }
	if(!$E) { $E = $false }

	switch($Format) {
		"List" { $string = ($object | Format-List | Out-String) }
		#Default { $string = ($object | Format-Table | Out-String) }
		Default { $string = ($object | Format-Table -AutoSize | Out-String) }
	}
	$string = $string.Trim()
	$lines = $string -split "`n"

	$params = @{
		L = $L
		V = $V
		NoTs = $NoTs
		E = $E
	}

	foreach($line in $lines) {
		$params["Msg"] = $line
		log @params
	}
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
function Get-LensData {
	param(
		[string]$DataType,
		[string]$Query,
		[switch]$All
	)
	function Get-LensHeaders {
		$creds = Get-Credential
		$user = $creds.UserName
		$pass = $creds.GetNetworkCredential().Password
		$credsString = "${user}:${pass}"
		$bytes = [System.Text.Encoding]::ASCII.GetBytes($credsString)
		$base64 = [System.Convert]::ToBase64String($bytes)
		$basicAuthValue = "Basic $base64"
		$headers = @{ Authorization = $basicAuthValue }
		$headers
	}
	function Get-LensUri($dataType, $query) {
		$baseUrl = "https://lens-api.cites.illinois.edu/lens/uiuc-lens"
		$contentType = "content-type=application/json"
		$uri = $baseUrl + "/" + $dataType + "?" + $query + "&" + $contentType
		$uri
	}
	$headers = Get-LensHeaders
	$uri = Get-LensUri $DataType $Query
	$results = Invoke-RestMethod -Uri $uri -Headers $headers -Method "get"
	if($All) { return $results }
	$resultId = $results.result
	$result = $results.objects.$dataType.$resultId
	$result
}

# Examples:

# Get mac_port info of MAC
Get-LensData -DataType "mac_port" -Query "mac=C8F750D03D07"

# Get device (i.e. switch) info of switch
Get-LensData -DataType "device" -Query "device_name=sw-grainger5"

# Get interface (i.e. switch port) info of switch port
Get-LensData -DataType "interface" -Query "device_name=sw-grainger5&ifname=C24"

# Get subnet info of CIDR-formatted subnet range
Get-LensData -DataType "subnet" -Query "subnet=130.126.253.64/26"

# List of data (a.k.a. object) types:
# https://answers.uillinois.edu/illinois/48347
# See table of "Essential attributes" on any given object type page for a list of properties that can be queried for that object type

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
Test-ComputerSecureChannel -repair -credential "uofi\mseng3" # also returns $true if so, $false if not
# Test again
Test-ComputerSecureChannel # should return $true now

# -----------------------------------------------------------------------------

# Force a computer to re-register its IP with AD DNS
# For when pinging a computer by it's NETBIOS name, or FQDN returns "Ping request could not find host <computer-name>.ad.uillinois.edu. Please check the name and try again.".

# Run this on the offending host (locally)
ipconfig /registerdns
# Then wait for a bit for AD to register the machine/IP and replicate the info

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

