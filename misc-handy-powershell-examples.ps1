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

# Prepare a connection to SCCM so you can directly use ConfigurationManager Powershell cmdlets without opening the admin console app
function Prep-MECM {
	$SiteCode = "MP0" # Site code 
	$ProviderMachineName = "sccmcas.ad.uillinois.edu" # SMS Provider machine name

	# Customizations
	$initParams = @{}
	#$initParams.Add("Verbose", $true) # Uncomment this line to enable verbose logging
	#$initParams.Add("ErrorAction", "Stop") # Uncomment this line to stop the script on any errors

	# Import the ConfigurationManager.psd1 module 
	if((Get-Module ConfigurationManager) -eq $null) {
		Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
	}

	# Connect to the site's drive if it is not already present
	if((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
		New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName @initParams
	}

	# Set the current location to be the site code.
	Set-Location "$($SiteCode):\" @initParams
}

# -----------------------------------------------------------------------------

# Use the above Prep-MECM function (which must change your working directory to MP0:\), perform some commands, and return to your previous working directory

$myPWD = $pwd.path
Prep-MECM

# Some commands, e.g.:
Get-CMDeviceCollection -Name "UIUC-ENGR-All Systems"

Set-Location $myPWD

# -----------------------------------------------------------------------------

# Update the expiration date of all AD user objects in a given OU
$ou = "OU=MyOU,OU=Admin,OU=UsersAndGroups,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu"
$expiry = "2020-12-25"
$users = (Get-ADUser -SearchBase $ou -Filter 'Name -like "*"' -Properties Name | Select Name).Name
foreach($user in $users) {
    Set-ADUser -Identity $user -AccountExpirationDate $expiry
}

# -----------------------------------------------------------------------------

# Find and count all members of Engineering AD groups for a given class:
# These are named like "<unit>-<course>-stu", "<unit>-<course>-stf", "<unit>-<course>-grd", "<unit>-<course>-ext", etc.
# e.g. "ae-100-stu"
$class = "ae-100*"
function logMembers($name, $members) {
    Write-Output "$name ($(@($members).count) members):"
    Write-Output "-----------------------------"
    if(@($members).count -lt 1) { Write-Output "{none}" }
    else { Write-Output $members }
    Write-Output " "
}
$groups = (Get-ADGroup -SearchBase "OU=Classes,OU=UsersAndGroups,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu" -Filter "*" | Where { $_.Name -like $class } | Select Name).Name | Sort
$all = @()
foreach($group in $groups) {
    $members = (Get-ADGroupMember -Identity $group | Select Name).Name | Sort
    logMembers $group @($members)
    $all += @($members)
}
logMembers "Total" @($all)
$unique = $all | Select -Unique
logMembers "Unique" @($unique)

# -----------------------------------------------------------------------------

# Find and count all members of campus Banner AD groups for a given class:
# These groups are named like "<course number> <section> <year> <semester> <CRN>", where "<course number>" is "<unit> <num>"
# e.g. "CS 125 AL2 2020 Fall CRN35878"
$class = "cee 538*2021 spring*"
$totalMembers = @()
$groups = Get-ADGroup -Filter { Name -like $class }
foreach ($group in $groups) {
	$members = $group | Get-ADGroupMember -Recursive | where { $_.ObjectClass -eq 'user'}
	$totalMembers += @($members)
}
$uniqueMembers = $totalMembers.samAccountName | Select -Unique
$count = $uniqueMembers.count
Write-Output "Total: $count"

# -----------------------------------------------------------------------------

# Get the (direct) membership of all groups in a given OU
Get-ADGroup -SearchBase "OU=RD User Groups,OU=Instructional,OU=UsersAndGroups,OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu" -Filter "*" | ForEach-Object { "`n`n$($_.Name)`n-------------"; (Get-ADGroupMember -Identity $_.Name | Select Name).Name }

# -----------------------------------------------------------------------------

# Find which MECM collections contain a given machine:
# Note: this will probably take a long time (15+ minutes) to run
Get-CMCollection | Where { (Get-CMCollectionMember -InputObject $_).Name -contains "machine-name" } | Select Name

# -----------------------------------------------------------------------------

# Find the difference between two MECM collections:
$one = (Get-CMCollectionMember -CollectionName "UIUC-ENGR-Collection 1" | Select Name).Name
$two = (Get-CMCollectionMember -CollectionName "UIUC-ENGR-Collection 2" | Select Name).Name
$diff = Compare-Object -ReferenceObject $one -DifferenceObject $two
$diff
@($diff).count

# -----------------------------------------------------------------------------

# Get the current/authoritative list of valid ENGR computer name prefixes directly from MECM:
$rule = (Get-CMDeviceCollectionQueryMembershipRule -Name "UIUC-ENGR-All Systems" -RuleName "UIUC-ENGR-Imported Computers").QueryExpression
$regex = [regex]'"([a-zA-Z]*)-%"'
$prefixesFound = $regex.Matches($rule)
# Make array of prefixes, removing extraneous characters from matches
$prefixesFinal = @()
foreach($prefix in $prefixesFound) {
	# e.g pull "CEE" out of "`"CEE-%`""
	$prefixClean = $prefix -replace '"',''
	$prefixClean = $prefixClean -replace '-%',''
	$prefixesFinal += @($prefixClean)
}
$prefixesFinal | Sort-Object

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

# Get the revision number of a local MECM assignment named like "*Siemens NX*":
# Compare the return value with the revision number of the app (as seen in the admin console).
# If it's not the latest revision , use the "Update machine policy" action in the Configuration Manager control panel applet, and then run this code again.
function Get-RevisionOfAssignment($name) {
    $assignments = Get-WmiObject -Namespace root\ccm\Policy\Machine -Query "Select * FROM CCM_ApplicationCIAssignment" | where { $_.assignmentname -like $name }
	foreach($assignment in $assignments) {
		$xmlString = @($assignment.AssignedCIs)[0]
		$xmlObject = New-Object -TypeName System.Xml.XmlDocument
		$xmlObject.LoadXml($xmlString)
		$rev = $xmlObject.CI.ID.Split("/")[2]
		$assignment | Add-Member -NotePropertyName "Revision" -NotePropertyValue $rev
	}
	$assignments | Select Revision,AssignmentName
}

Get-RevisionOfAssignment "*autocad*"


# -----------------------------------------------------------------------------

# Get the refresh schedules of all MECM device collections, limit them to those that refresh daily, and print them in a table, sorted by refresh time and then by collection name:
$colls = Get-CMDeviceCollection
$colls | Select Name,@{Name="RecurStartDate";Expression={$_.RefreshSchedule.StartTime.ToString("yyyy-MM-dd")}},@{Name="RecurTime";Expression={$_.RefreshSchedule.StartTime.ToString("HH:mm:ss")}},@{Name="RecurIntervalDays";Expression={$_.RefreshSchedule.DaySpan}},@{Name="RecurIntervalHours";Expression={$_.RefreshSchedule.HourSpan}},@{Name="RecurIntervalMins";Expression={$_.RefreshSchedule.MinuteSpan}} | Where { $_.RecurDays -eq 1 } | Sort RefreshTime,Name | Format-Table

# -----------------------------------------------------------------------------

# Get all MECM device collections named like "UIUC-ENGR-CollectionName*" and set their refresh schedule to daily at 3am, starting 2020-08-28
$sched = New-CMSchedule -Start "2020-08-28 03:00" -RecurInterval "Days" -RecurCount 1
Get-CMDeviceCollection | Where { $_.Name -like "UIUC-ENGR-CollectionName*" } | Set-CMCollection -RefreshSchedule $sched

# -----------------------------------------------------------------------------

# Get all MECM Collections and apps named like "UIUC-ENGR *" and rename them to "UIUC-ENGR-*"

$colls = Get-CMCollection | Where { $_.Name -like "UIUC-ENGR *" }
$colls | ForEach {
	$name = $_.Name
	$newname = $name -replace "UIUC-ENGR ","UIUC-ENGR-"
	Write-Host "Renaming collection `"$name`" to `"$newname`"..."
	Set-CMCollection -Name $name -NewName $newname
}

$apps = Get-CMApplication -Fast | Where { $_.LocalizedDisplayName -like "UIUC-ENGR *" }
$apps | ForEach {
	$name = $_.LocalizedDisplayName
	$newname = $name -replace "UIUC-ENGR ","UIUC-ENGR-"
	Write-Host "Renaming app `"$name`" to `"$newname`"..."
	Set-CMApplication -Name $name -NewName $newname
}

# -----------------------------------------------------------------------------

# Gather some stats about an EWS homedir
function global:Poke-HomeDir {
	param(
		[string]$user,
		[switch]$debug
	)
	$largestCount = 10
	
	function log($msg) {
		if($debug) {
			if($loud) { Write-Host $msg }
		}
		else { Write-Host $msg }
	}
	
	log "Getting path..." -debug
	$homes = @("1abc","2defgh","3ijkl","4mnop","5qrs","6tuvwxyz")
	$homeNum = ($homes | Where { $_ -like "*$($user.substring(0,1))*" }).substring(0,1)
	$dir = "\\ews-unity.ad.uillinois.edu\fs$($homeNum)-homes\$user\"
	log "Path: `"$dir`""
	
	log "Getting files..." -debug
	$files = Get-ChildItem $dir -Force -Recurse -File
	$fileCount = @($files).count
	log "File count: $fileCount"
	
	log "Getting directories..." -debug
	$dirs = Get-ChildItem $dir -Force -Recurse -Directory
	$dirCount = @($dirs).count
	log "Dir count: $dirCount"
	
	log "Calculating total filesize..." -debug
	$size = [math]::round(($files | Measure-Object -Sum Length).Sum/1MB,1)
	log "`nTotal size: $size MB"
	
	log "Identifying $largestCount largest files..." -debug
	$largest = $files | Sort "length" -Descending | Select "length","fullname" -First $largestCount | Select @{Name="Length"; Expression={"$([math]::round($_.Length/1MB,1)) MB"}},FullName
	log "$largestCount largest files:"
	$largest | Format-Table -Autosize -Wrap
}

Poke-HomeDir "mseng3"

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

