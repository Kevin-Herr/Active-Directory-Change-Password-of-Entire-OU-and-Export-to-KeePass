###########################################################################
# Change Passwords For User Accounts in OU and Export to KeePass
###########################################################################
# Sources of some pieces:
#   Random Password Generation code from...  https://www.sharepointdiary.com/2020/04/powershell-generate-random-password.html
#   KeePass Password Manager code from...    https://www.sans.org/blog/powershell-for-keepass-password-manager/
#   Secure Strings for PS v5.1 code from...  https://gist.github.com/JeremyTBradshaw/10c67244cf380a66b6ca0e59139cd11d

$PasswordCharacterCount  = "20"
$AccountOU               = "OU=Service Accounts,OU=Accounts,DC=contoso,DC=org"
$KeePassInstallDir       = "C:\Program Files\KeePass*"                               # * is required here.
$KeePassFile             = "$($env:USERPROFILE)\Desktop\KeePassTestFile.kdbx"


###########################################################################
## Random Password Function
###########################################################################
Function Get-RandomPassword
{
    # Define Parameters
    param([int]$PasswordLength = 10)
 
    # ASCII Character Set for Password
    $CharacterSet = @{
            Uppercase   = (97..122) | Get-Random -Count 10 | % {[char]$_}
            Lowercase   = (65..90)  | Get-Random -Count 10 | % {[char]$_}
            Numeric     = (48..57)  | Get-Random -Count 10 | % {[char]$_}
            SpecialChar = (33..47)+(58..64)+(91..96)+(123..126List of users should just be in a text file with new accounts on new lines.) | Get-Random -Count 10 | % {[char]$_}

    }
 
    # Frame Random Password from given character set
    $StringSet = $CharacterSet.Uppercase + $CharacterSet.Lowercase + $CharacterSet.Numeric
     -join(Get-Random -Count $PasswordLength -InputObject $StringSet)
}


###########################################################################
## KeePass Secure String to Plain Text Function
###########################################################################
Function Convert-FromSecureStringToPlaintext ( $SecureString ) {
	[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString))
}

###########################################################################
## KeePass Module Imports and Connection Creation
###########################################################################
### Load the classes from KeePass.exe:
$KeePassProgramFolder = Dir $KeePassInstallDir | Select-Object -Last 1
$KeePassEXE = Join-Path -Path $KeePassProgramFolder -ChildPath "KeePass.exe"
[Reflection.Assembly]::LoadFile($KeePassEXE)

### Fetch KeePass database password for a composite key.
$CompositeKey = New-Object -TypeName KeePassLib.Keys.CompositeKey #From KeePass.exe

$Password = Read-Host -Prompt "Enter Passphrase" -AsSecureString
$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))   
$KcpPassword = New-Object -TypeName KeePassLib.Keys.KcpPassword($Password)

$CompositeKey.AddUserKey( $KcpPassword )

### Prepare KeePass File Path
$IOConnectionInfo = New-Object KeePassLib.Serialization.IOConnectionInfo
$IOConnectionInfo.Path = $KeePassFile

### Open KeePass Status Logger
$StatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

### Open the KeePass database with key, path and logger objects.
$PwDatabase = New-Object -TypeName KeePassLib.PwDatabase #From KeePass.exe
$PwDatabase.Open($IOConnectionInfo, $CompositeKey, $StatusLogger)

### List KeePass Groups
# $PwDatabase.RootGroup.Groups
# $PwDatabase.RootGroup.Groups | Format-Table Name,LastModificationTime,Groups -AutoSize

### List all entries from all groups, including nested groups.
#$PwDatabase.RootGroup.GetEntries($True) |
# ForEach { $_.Strings.ReadSafe("Title") + " : " + $_.Strings.ReadSafe("UserName") }

### Get a particular group named "General" and show some of its properties.
$Group = $PwDatabase.RootGroup.Groups | Where { $_.Name -eq 'General' }
$Group.GetEntriesCount($True) #Count of all entries, including in subgroups.

### Get the unique UUID for the "General" group. Objects in KeePass have unique ID numbers so that multiple objects may have the same name.
$Group.Uuid.ToHexString()
[Byte[]] $byteArray = $Group.Uuid.UuidBytes

###########################################################################
## Function to add an entry to a KeePass database.
###########################################################################
 
function New-KeePassEntry {
	<#
	.SYNOPSIS
		Adds a new KeePass entry.
	.DESCRIPTION
		Adds a new KeePass entry. The database must be opened first. The name
		of a top-level group/folder in KeePass and an entry title are mandatory,
		but all other arguments are optional. The group/folder must be at the top
		level in KeePass, i.e., it cannot be a nested subgroup. The password, if
		any, is passed in as plaintext unless you specify a PSCredential object,
		in which case the secure string from the PSCredential is converted to
		plaintext and then saved to the KeePass entry. The PSCredential object
		is normally created using the Get-Credential cmdlet.
 
	.PARAMETER PwDatabase
		The previously-opened KeePass database object (mandatory).
 
	.PARAMETER TopLevelGroupName
		Name of the KeePass folder (mandatory). Must be top level, cannot be
		nested, and must be unique, i.e., no other groups of the same name.
 
	.PARAMETER Title
		The title of the entry to add (mandatory). If possible, avoid
		duplicate titles for the sake of other KeePass scripts.
 
	.PARAMETER PSCredential
		A PowerShell secure string credential object (optional), typically
		created with the Get-Credential cmdlet. If this is specified, any
		UserName and Password parameters are ignored and the KeePass entry
		will be created using the user name and plaintext password of
		the PSCredential object. Other data, such as Notes or URL, may
		still be added. The KeePass entry will have the plaintext password
		from the PSCredential in the KeePass GUI, not the secure string.
 
	.PARAMETER UserName
		The user name of the entry to add, if no PSCredential.
 
	.PARAMETER Password
		The password of the entry to add, in plaintext, if no PSCredential.
 
	.PARAMETER URL
		The URL of the entry to add.
 
	.PARAMETER Notes
		The Notes of the entry to add.
	#>
	 
	[CmdletBinding(DefaultParametersetName="Plain")]
	Param(
		[Parameter(Mandatory=$true)] [KeePassLib.PwDatabase] $PwDatabase,
		[Parameter(Mandatory=$true)] [String] $TopLevelGroupName,
		[Parameter(Mandatory=$true)] [String] $Title,
		[Parameter(ParameterSetName="Plain")] [String] $UserName,
		[Parameter(ParameterSetName="Plain")] [String] $Password,
		[Parameter(ParameterSetName="Cred")] [System.Management.Automation.PSCredential] $PSCredential,
		[String] $URL,
		[String] $Notes
	)
	# This only works for a top-level group, not a nested subgroup:
	$PwGroup = @( $PwDatabase.RootGroup.Groups | where { $_.name -eq $TopLevelGroupName } )
	 
	# Confirm that one and only one matching group was found
	if ($PwGroup.Count -eq 0) { throw "ERROR: $TopLevelGroupName group not found" ; return }
	elseif ($PwGroup.Count -gt 1) { throw "ERROR: Multiple groups named $TopLevelGroupName" ; return }
	 
	# Use PSCredential, if provided, for username and password:
	if ($PSCredential){
		$UserName = $PSCredential.UserName
		$Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PSCredential.Password))
	}
	 
	# The $True arguments allow new UUID and timestamps to be created automatically:
	$PwEntry = New-Object -TypeName KeePassLib.PwEntry( $PwGroup[0], $True, $True )
	 
	# Protected strings are encrypted in memory:
	$pTitle = New-Object KeePassLib.Security.ProtectedString($True, $Title)
	$pUser = New-Object KeePassLib.Security.ProtectedString($True, $UserName)
	$pPW = New-Object KeePassLib.Security.ProtectedString($True, $Password)
	$pURL = New-Object KeePassLib.Security.ProtectedString($True, $URL)
	$pNotes = New-Object KeePassLib.Security.ProtectedString($True, $Notes)
	 
	$PwEntry.Strings.Set("Title", $pTitle)
	$PwEntry.Strings.Set("UserName", $pUser)
	$PwEntry.Strings.Set("Password", $pPW)
	$PwEntry.Strings.Set("URL", $pURL)
	$PwEntry.Strings.Set("Notes", $pNotes)
	 
	$PwGroup[0].AddEntry($PwEntry, $True)
	 
	# Notice that the database is automatically saved here!
	$StatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger
	$PwDatabase.Save($StatusLogger)
 
}
###########################################################################
## Function to Update an entry from a KeePass database.
###########################################################################
 
function Update-KeePassEntryByTitle {
	<#
	.SYNOPSIS
		Find and update a KeePass entry from a group based on entry title.
		Only works for Top Level groups.
	 
	.DESCRIPTION
		After opening a KeePass database, provide the function with the name
		of a top-level group in KeePass (cannot be a nested subgroup) and the
		title of a unique entry in that group. The function returns the username,
		password, URL and notes for the entry by default, all in plaintext.
		Alternatively, just a PSCredential object may be returned instead; an
		object of the same type returned by the Get-Credential cmdlet. Note that
		the database is not closed by the function.
	 
	.PARAMETER PwDatabase
		The previously-opened KeePass database object.
	 
	.PARAMETER TopLevelGroupName
		Name of the KeePass folder. Must be top level, cannot be nested, and
		must be unique, i.e., no other groups/folders of the same name.
	 
	.PARAMETER Title
		The title of the entry to return. Must be unique.
	
	.PARAMETER NewPassword
		The new password that will be added to the unique entry.
	
	.EXAMPLE
		Update-KeePassEntryByTitle -PwDatabase $PwDatabase -TopLevelGroupName "General" -Title "Sample Entry" -NewPassword "Test123"
	 #> 
	 
	[CmdletBinding()]
	Param
	(
	[Parameter(Mandatory=$true)] [KeePassLib.PwDatabase] $PwDatabase,
	[Parameter(Mandatory=$true)] [String] $TopLevelGroupName,
	[Parameter(Mandatory=$true)] [String] $Title,
	[Parameter(Mandatory=$true)] [String] $NewPassword
	)
	 
	# This only works for a top-level group.
	$PwGroup = @( $PwDatabase.RootGroup.Groups | where { $_.name -eq $TopLevelGroupName } )
	 
	# Confirm that only one matching group was found.
	if ($PwGroup.Count -eq 0) { throw "ERROR: $TopLevelGroupName group not found" ; return }
	elseif ($PwGroup.Count -gt 1) { throw "ERROR: Multiple groups named $TopLevelGroupName" ; return }
	 
	# Confirm that only one matching entry was found.
	$entry = @( $PwGroup[0].GetEntries($True) | Where { $_.Strings.ReadSafe("Title") -eq $Title } )

	if ($entry.Count -eq 0) { 
		Write-Output "Creating New Entry for Account."
		New-KeePassEntry -PwDatabase $PwDatabase -TopLevelGroupName 'General' -Title $Title -UserName $Title -Password $NewPassword -Notes "Entry created by script."
		return 
	}
	elseif ($entry.Count -gt 1) { 
		throw "ERROR: Multiple entries named $Title" ; 
		return 
	}

	## Convert to PS Object
	$KeePassPsObject = New-Object -TypeName PSObject -Property ([ordered]@{
		'Uuid'                    = $entry[0].Uuid;
		'ParentGroup'             = $entry[0].ParentGroup.Name;
		'FullPath'                = $entry[0].ParentGroup.GetFullPath('/', $true);
		'Title'                   = $entry[0].Strings.ReadSafe('Title');
		'UserName'                = $entry[0].Strings.ReadSafe('UserName');
		'Password'                = $entry[0].Strings.ReadSafe('Password');
		'Notes'                   = $entry[0].Strings.ReadSafe('Notes');
	})
	
	## Display Old PS Object Details
	$KeePassPsObject
		
	## Convert Password to Secure String
	$KeePassSecurePasswordString = $NewPassword
	$KeePassSecurePasswordString = New-Object KeePassLib.Security.ProtectedString($True, $KeePassSecurePasswordString)
	
	## Update KP Password 
	$entry[0].Strings.Set('Password', $KeePassSecurePasswordString)

	## Save the Change
	$PwDatabase.Save($StatusLogger)

}


###########################################################################
## Process User Account Changes and KeePass Updates
###########################################################################

## Gather OU User Objects
$OUUsersList = Get-ADUser -Filter * -SearchBase $AccountOU

foreach ($username in $OUUsersList) {
	write-output $username.Name
	$newpassword = Get-RandomPassword -PasswordLength $PasswordCharacterCount
	write-output $newpassword
	#$newpasswordsecure = ConvertTo-SecureString -AsPlainText $newpassword -Force
	#Set-ADAccountPassword -Identity $username -NewPassword  $newpasswordsecure
	Update-KeePassEntryByTitle -PwDatabase $PwDatabase -TopLevelGroupName "General" -Title $username.Name -NewPassword $newpassword
}

## Close KeePass DB
$PwDatabase.Close()
