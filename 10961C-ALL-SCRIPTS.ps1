#10961C - Automating Administration with Windows PowerShell

#Module 1: Getting started with Windows PowerShell

#Lesson 1

#Switch Powershell Engine
PowerShell.exe -Version 2

#View Powershell Version
$psversiontable.psversion

#Lab A: Configuring Windows PowerShell


#Lesson 2 Understanding command syntax

Get-Item

Get-ChildItem C:\

Get-ChildItem -Path C:\


Get-ChildItem -Path C:\ -Recurse -Verbose


#Using Get-Help

Get-Help Get-ChildItem

Get-Help Get-ChildItem -Examples

Get-Help Get-ChildItem -Full

Get-Help Get-ChildItem -Online

Get-Help Get-ChildItem -ShowWindow

Get-Help Get-ChildItem -Parameter Filter

Get-Help *process*

Get-Help Get-EventLog -Parameter LogName

#Updating help

Update-Help

#Save Help to a Location
#https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/save-help?view=powershell-7.1
Save-Help -DestinationPath "C:\tmp\PoshHelp" -UICulture pt-br,en-us -Force -Verbose

Get-Help About_aliases

Get-Help About_EventLogs


#About files

Get-Help About_Common_Parameters -Online

Get-Help About*

Get-help About_Hidden -ShowWindow


#Demonstration: Viewing help


#Demonstration Steps
#1. Display basic help for a command.

Get-Help -Name Get-UcsAaaOrg

#2. Display help in a floating window.

Get-help -Name New-ItemProperty -ShowWindow

#3. Display usage examples.

get-help -Name New-ADComputer -Examples

#4. If connected to the Internet, display online help.

Get-Help -Name Remove-ADComputerServiceAccount -Online

#It redirects to: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adcomputerserviceaccount?view=winserver2012r2-ps&redirectedfrom=MSDN


Get-EventLog -LogName Application

Get-EventLog Application

Get-EventLog –LogName Application –ComputerName LON-CL1,LON-DC1


#Demonstration: Using About files

<#

Demonstration Steps
1. View a list of About help file topics.
2. View the about_aliases help topic.
3. View the about_eventlogs help topic in a window.
4. View a help topic that will explain how to make the console beep.
Question: How would you search for a cmdlet that retrieves the properties of a computer
from Active Directory?

#>

#1.
Get-Help About*

#2.

Get-Help About_aliases -ShowWindow



##########PAREI NA PAGINA 45

<#

You wish to join multiple computers to the Adatum domain. The Add-Computer
cmdlet’s -ComputerName parameter accepts multiple values. Which of the following
is a set of valid values for this parameter?

-Computername Lon-CL2,LON-CL3,LON-CL4

-Computername "Lon-CL2,LON-CL3,LON-CL4"

#>

#LESSON 3 - Finding Commands


<#

In Windows PowerShell version 3.0 and newer, modules autoload if you run a cmdlet that is not currently
loaded. This works if the module that contains the cmdlet is in a folder under the module load paths. By
default, these are %systemdir%\WindowsPowerShell\v1.0\Modules and %userprofiles%\Documents
\WindowsPowerShell\Modules. Within Windows PowerShell, these pThe Get-Help command uses
autoloading when searching for help topics. The Get-Command command also uses autoloading.

#>


Get-Module -All

get-module -ListAvailable

#RSAT ON WINDOWS 10
#http://woshub.com/install-rsat-feature-windows-10-powershell/

Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property DisplayName, State

Add-WindowsCapability –online –Name “Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0”

Add-WindowsCapability –online –Name “Rsat.Dns.Tools~~~~0.0.1.0”

Add-WindowsCapability -Online -Name Rsat.FileServices.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.IPAM.Client.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.LLDP.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.NetworkController.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.NetworkLoadBalancing.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.BitLocker.Recovery.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.CertificateServices.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.DHCP.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.RemoteAccess.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.RemoteDesktop.Services.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.ServerManager.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.Shielded.VM.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.StorageMigrationService.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.StorageReplica.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.SystemInsights.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.VolumeActivation.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.WSUS.Tools~~~~0.0.1.0


#To install all the available RSAT tools at once, run:

Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability –Online

#To install only disabled RSAT components, run:

Get-WindowsCapability -Online |? {$_.Name -like "*RSAT*" -and $_.State -eq "NotPresent"} | Add-WindowsCapability -Online


#https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-command?view=powershell-7.1
Get-Command -Name *event*

Get-Command -Noun event* -Verb Get

Get-Command -Module NetAdapter

Get-Command -noun *ipv4*

Get-Command -Name *event* -ParameterName *Computer*

Get-Alias di*

new-alias -Name 'list' -Value get-childitem -Description 'list files in a folder' 


get-alias | Where-Object -FilterScript {$psitem.ReferencedCommand -like 'Get-ChildItem'}

Show-Command -Name new-alias

get-command -Noun *dns*


#What command would you run to resolve a DNS name?

(Resolve-DnsName -Name TBAMBEV-VVM0221).IPAddress

#What command would you run to make changes to a network adapter? After finding such a
#command, what parameter would you use to change its MAC address (on adapters that support
#changes to their MAC address)?

Get-Command -Noun *adapter*


#https://docs.microsoft.com/en-us/powershell/module/netadapter/set-netadapter?view=win10-ps

Set-NetAdapter -Name "Ethernet 1" -MacAddress "00-10-18-57-1B-0D"

#What command would let you enable a previously disabled scheduled task?

Get-ScheduledTask | Where-Object -FilterScript {$_.TaskName -like '*Windows 2000*'} | Enable-ScheduledTask -Verbose

#What command would let you block access to a file share by a particular user?

Get-Command -Noun *share*

Revoke-SmbShareAccess -Name ClusterLog$ -AccountName "brdiv0346" -Force

#What command would you run to clear your computer’s local BranchCache cache?

Get-Command -Noun *cache*

Clear-BCCache -Force -Verbose

#What command would you run to display a list of Windows Firewall rules? What parameter of that command would display only enabled rules?

get-command -Noun *firewall*

Get-NetFirewallRule

Get-NetFirewallRule | Where-Object -FilterScript {$PSItem.Enabled -eq $True}

#What command would you run to display a list of all locally bound IP addresses?

Get-NetIPAddress

#What command would you run to suspend an active print job in a print queue?

Get-Command -Noun *print*

$Printer = Get-Printer -Name "PrinterName" 
Suspend-PrintJob -PrinterObject $Printer -ID 1

#What native Windows PowerShell command would you run to read the content of a text file?

get-content -Path C:\temp\cert.txt


$svcToAlterStartType = Get-service -Name BITS 

$svcStartType = $svcToAlterStartType.StartType


get-help about_Signing

makecert #to create self signed certificates


Get-ADUser -Identity janedoe -Properties Department,EmailAddress

Get-ADUser -Filter * -Properties *

New-ADUser "Jane Doe" -Department IT

New-ADGroup -Name FileServerAdmins -GroupScope Global

New-ADComputer -Name LON-CL10 -Path "ou=marketing,dc=adatum,dc=com" -Enabled $true

New-ADOrganizationalUnit -Name Sales -Path "ou=marketing,dc=adatum,dc=com" -ProtectedFromAccidentalDeletion $true


New-ADObject -Name JohnSmithcontact -Type contact -DisplayName “John Smith (Contoso.com)”

Get-ADObject -Filter ‘ObjectClass -eq “contact”’

Set-ADObject -Identity “CN=Lara Raisic,OU=IT,DC=Adatum,DC=com" -Description “Member of support team”

Get-ADUser Lara -Properties Description

Rename-ADObject -Identity “CN=HelpDesk,OU=IT,DC=Adatum,DC=com” -NewName SupportTeam

Get-ADGroup HelpDesk

#qual dos verbos a seguir não está associado com aduser - get, update, new, remote, set
Get-Command -Noun *aduser*

#The default value for the -ProtectedFromAccidentalDeletion parameter of New-ADOrganizationalUnit is $true.
$item = (get-help -Name New-ADOrganizationalUnit -Parameter 'ProtectedFromAccidentalDeletion')

$item.defaultValue

#LESSON 2 - NETWORK CMDLETS

New-NetIPAddress -IPAddress 192.168.1.10 -InterfaceAlias “Ethernet” -PrefixLength 24 -DefaultGateway 192.168.1.1

New-NetRoute -DestinationPrefix 0.0.0.0/24 -InterfaceAlias “Ethernet” -DefaultGateway 192.168.1.1

Set-DnsClient -InterfaceAlias Ethernet -ConnectionSpecificSuffix “adatum.com”

Enable-NetFirewallRule -DisplayGroup “Remote Access”

Set-NetFirewallRule -DisplayGroup “Remote Access” -Enabled True

<#

Cmdlet Description
New-NetIPAddress Creates a new IP address
Get-NetIPAddress Displays properties of an IP address
Set-NetIPAddress Modifies properties of an IP address
Remove-NetIPAddress Deletes an IP address

New-NetRoute Creates an entry in the IP routing table
Get-NetRoute Retrieves an entry from the IP routing table
Set-NetRoute Modifies properties of an entry in the IP routing table
Remove-NetRoute Deletes an entry from the IP routing table
Find-NetRoute Identifies the best local IP address and route to reach a remote address


Get-DnsClient Gets details about a network interface
Set-DnsClient Sets DNS client configuration settings for a network interface
Get-DnsClientServerAddress Gets the DNS server address settings for a network interface
Set-DnsClientServerAddress Sets the DNS server address for a network interface

New-NetFirewallRule Creates a new firewall rule
Set-NetFirewallRule Sets properties for a firewall rule
Get-NetFirewallRule Gets properties for a firewall rule
Remove-NetFirewallRule Deletes a firewall rule
Rename-NetFirewallRule Renames a firewall rule
Copy-NetFirewallRule Makes a copy of a firewall rule
Enable-NetFirewallRule Enables a firewall rule
Disable-NetFirewallRule Disables a firewall rule
Get-NetFirewallProfile Gets properties for a firewall profile
Set-NetFirewallProfile Sets properties for a firewall profile


#>

New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 172.16.0.30 -PrefixLength 16

Remove-NetIPAddress -InterfaceAlias Ethernet -IPAddress 172.16.0.40

Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddress 172.16.0.11

Remove-NetRoute -InterfaceAlias Ethernet -DestinationPrefix 0.0.0.0/0

New-NetRoute -InterfaceAlias Ethernet -DestinationPrefix 0.0.0.0/0 -NextHop 172.16.0.2

Get-NetIPConfiguration

#Question: Which two parameters can you use with *-NetIPAddress cmdlets to identify a network interface?

Get-Help Get-NetIPAddress -Parameter InterfaceAlias

Get-Help Get-NetIPAddress -Parameter InterfaceIndex


#HYPER-V CMDLETS

<#

Get-VM Gets properties of a VM
Set-VM Sets properties of a VM
New-VM Creates a new VM
Start-VM Starts a VM
Stop-VM Stops a VM
Restart-VM Restarts a VM
Suspend-VM Pauses a VM
Resume-VM Resumes a paused VM
Import-VM Imports a VM from a file
Export-VM Exports a VM to a file
Checkpoint-VM Creates a checkpoint of a VM


#>


#IIS CMDLETS

<#

New-WebSite Creates a new IIS website
Get-WebSite Gets properties about an IIS website
Start-WebSite Starts an IIS website
Stop-WebSite Stops an IIS website
New-WebApplication Creates a new web application
Remove-
WebApplication
Deletes a web application
New-WebAppPool Creates a new web application pool
Restart-WebAppPool Restarts a web application pool

#>

#Working with the Windows PowerShell pipeline

#example below only works on powershell console
#Get-Service ' (aspas simples) 


Get-Service | get-member

Get-Process | get-member

Get-ChildItem -Path C:\TEMP | get-member

Get-ADUser -identity jaribeiro | get-member

Get-aduser -Filter * | get-member

Get-Process | Format-List

Get-process | Format-Table -Wrap

Get-ADObject -filter * -Properties * | ft -Property Name, ObjectClass, Description -AutoSize -Wrap

Get-GPO -all | Format-Wide -Property DisplayName -Column 3

Get-ADComputer -Filter * -Properties * | Select-Object -Property Name,OperatingSystem | Format-List

Get-Service | Sort-Object –Property Name –Descending
Get-Service | Sort Name –Desc
Get-Service | Sort Status,Name

Get-Service | Sort-Object Status,Name | Format-Wide -GroupBy Status

Get-Process

Get-Process | Sort-Object -Property ID

Get-Service | Sort-Object -Property Status

Get-Service | Sort-Object -Property Status -Descending

Get-EventLog -LogName Security -Newest 30 | Sort-Object -Property TimeWritten

Get-EventLog -LogName Security -Newest 20 | Sort-Object -Property TimeWritten -Descending

Get-ADUser -Filter * | Sort-Object -Property surname | Format-Wide

Get-ADUser -Filter * | Select-Object -Property SamAccountName,Surname | Sort-Object -Property Surname | Format-Wide -Column 2

Get-ChildItem -File | Measure -Property Length -Sum -Average -Minimum -Max

#Display the number of services on your computer.
$services = Get-Service

$services | Measure-Object

#Display the number of Active Directory users.

$adUsers = Get-ADUser -Filter *


($adUsers | Measure-Object).Count

#Display the total amount and the average amount of virtual memory that the processes are using


$allProcesses = Get-Process 

($allProcesses | Measure-Object -Property VM -Sum).Sum/1GB

($allProcesses | Measure-Object -Property VM -Average).Average/1GB


Get-Process | Sort-Object -Property VM | Select-Object -First 10

Get-Service | Sort-Object -Property Name | Select-Object -Last 10

Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 5 -Skip 1

Get-ADUser -Filter * -Property Department | Sort-Object -Property Department | Select-Object -Unique

Get-Process | Select-Object –Property Name,ID,VM,PM,CPU | Format-Table

Get-Process | Sort-Object –Property CPU –Descending | Select-Object –Property Name,CPU –First 10


#Display 10 processes by largest amount of virtual memory use.

Get-Process | Sort-Object -Property VM -Descending | Select-Object -Property ProcessName,VM -First 10 

#Display the current day of week—for example, Monday or Tuesday.

Get-date -Format dddd


#Display the 10 most recent Security event log entries. Include only the event ID, time written, and event message.


Get-EventLog -LogName Security | Select-Object -Property EventID,TimeWritten,Message -First 10

#Display the names of the Active Directory computers grouped by operating system.

Get-ADComputer -Filter * -Properties Name,OperatingSystem | Select-Object -Property Name,OperatingSystem | Group-Object -Property OperatingSystem  | Format-Table -AutoSize

Get-ADComputer -Filter * -Properties Name,OperatingSystem | Select-Object -Property Name,OperatingSystem | Group-Object -Property OperatingSystem  | Sort-Object -Property Count -Descending | Format-Table -AutoSize

Get-ADComputer -Filter * -Properties Name,OperatingSystem,Enabled | Where-Object -FilterScript {$PSItem.Enabled -eq $true} | Select-Object -Property Name,OperatingSystem | Group-Object -Property OperatingSystem  | Sort-Object -Property Count -Descending | Format-Table -AutoSize

#HASH TABLE - KEY VALUE PAIR

Get-Process | Select-Object Name,ID,@{n='VirtualMemory';e={$PSItem.VM}},@{n='PagedMemory';e={$PSItem.PM}}

Get-Process | 
Select-Object -Property Name,
                        ID,
                        @{n='VirtualMemory(MB';e={'{0:N2}' -f ($PSItem.VM/1GB)}},
                        @{n='PagedMemory(MB';e={'{0:N2}' -f ($PSItem.PM/1MB)}}



#On LON-CL1, display a list of Active Directory user accounts and their creation dates.
Get-ADUser -Filter * -Properties Name,Created | Select-Object -Property Name,Created

Get-ADUser -Filter * -Properties Name,Created | Select-Object -Property Name,Created | Sort-Object -Property Created -Descending

#View a list of the same users in the same order but displaying the user name and the age of the account, in days.

$date = (get-date).AddMonths(-15)

New-TimeSpan -Start (get-date) -End ($date)

Get-ADUser -Filter * -Properties Name,Created | Select-Object -Property Name,@{n="CreatedDays";e={(New-TimeSpan -Start (Get-Date) -End $_.Created).Days}}

Get-ADUser -Filter * -Properties Name,Created | Select-Object -Property Name,@{n="CreatedDays";e={[math]::Abs((New-TimeSpan -Start (Get-Date) -End $_.Created).Days)}}


#1. Display the current day of the year.

(get-date).DayOfYear

#2. Display information about installed hotfixes.

Get-HotFix | Select-Object -Property PSComputerName,HotFixID,Caption,InstalledOn, Installedby | Format-Table -AutoSize

#3. Display a list of available scopes from the DHCP server.

Get-DhcpServerv4Scope -ComputerName ACSWDHC1

#4. Display a sorted list of enabled Windows Firewall rules.

Get-NetFirewallRule | Where-Object -FilterScript {$PSItem.Enabled -eq 'TRUE'} | Sort-Object -Property DisplayName | Select-Object -Property DisplayName,Enabled,DisplayGroup

#5. Display a sorted list of network neighbors.

Get-NetNeighbor | Sort-Object

#6. Display information from the DNS name resolution cache

Get-DnsClientCache | Select-Object -Property Name,Data,TimeToLive,TTL,Type | Sort-Object -Property Name | Format-Table -AutoSize

#Filtering objects out of the pipeline


Get-EventLog -LogName Security -Newest 100 | where {$psitem.EventID -eq 4672 -and $psitem.EntryType -eq 'SuccessAudit'}

Get-Process | Where-Object -FilterScript {$PSItem.CPU -gt 30 -and $PSItem.VM -lt 10000}


Get-Process | Where { $PSItem.Responding –eq $True }

Get-Process | Where { $PSItem.Responding }

Get-Process | Where { -not $PSItem.Responding }

Get-Service | Where {$PSItem.Name.Length –gt 15}



#1. On LON-CL1, use basic filtering syntax to display a list of the Server Message Block (SMB) shares that include a dollar sign ($) in the share name.

Get-SmbShare | Where-Object -FilterScript {$PSItem.Name -like "*$*"}


#2. Use advanced filtering syntax to display a list of the physical disks that are in healthy condition, displaying only their names and statuses.

Get-PhysicalDisk | Where-Object -FilterScript {$PSItem.HealthStatus -eq 'Healthy'} | Select-Object -Property @{label='Name';expression={$psitem.FriendlyName}},HealthStatus

#3. Display a list of the disk volumes that are fixed disks and that use the NTFS file system. Display only the drive letter, drive label, drive type, and file system type. Display the data in a single column.

Get-Volume | Where-Object -FilterScript {$PSItem.DriveType -match 'Fixed' -and $psitem.FileSystem -match 'NTFS'} | 
Select-Object -Property DriveLetter,FileSystemLabel,DriveType,FileSystem | 
Format-Wide -Property FileSystemLabel -Column 1


#4. Using advanced filtering syntax but without using the $PSItem variable, display a list of the Windows PowerShell command verbs that begin with the letter C. Display only the verb names in as compact a format as possible.

Get-Command | Where-Object -Property Verb -Like "C*" | Format-Wide -Property Name -Column 3

#1. Display a list of all the users in the Users container of Active Directory.

Get-ADUser -Filter * -SearchBase "CN=Users,dc=sth,dc=local" -SearchScope Subtree | Select-Object -Property name,SamAccountName,UserPrincipalName

#2. Create a report showing the Security event log entries that have the event ID 4624.

Get-EventLog -LogName Security -InstanceId 4624

#3. Display a list of the encryption certificates installed on the computer.

Get-ChildItem -Path Cert:\

#4. Create a report that shows the disk volumes that are running low on space.

Get-CimInstance -ClassName win32_volume | Select-Object -Property @{name='SizeGB';expression={[math]::round(($psitem.capacity/1GB),2)}},
                                                                  @{name='FreeSpaceGB';expression={[math]::round(($psitem.freespace/1GB),2)}},
                                                                  @{name='PercentFree';expression={[math]::round(($PsItem.FreeSpace/$Psitem.Capacity),2)}} |
                                                                   Where-Object -Property PercentFree -lt 0.20



#5. Create a report that displays specified Control Panel items.


Get-ControlPanelItem | Where-Object -FilterScript {$psitem.Category -match '^(\bSystem and Security\b)$'}


Get-ControlPanelItem | Where-Object -FilterScript {$psitem.Category -match '^\b(System +and +Security)\b$' -and $psitem.Category -notmatch '^\b(Hardware and Sound)\b$' }


Get-ControlPanelItem -Category 'System and Security'

Get-ControlPanelItem | Where-Object -FilterScript {$psitem.Category -match '^(System*)'}

Get-ControlPanelItem -Category 'System and Security' | Where-Object -FilterScript {-not ($PSItem.Category -notlike '*System and Security*')} | Sort Name


#Encrypt and Descript File Powershell
Get-ChildItem -File | ForEach-Object -MemberName Encrypt

Get-ChildItem -File | ForEach-Object -MemberName Decrypt

[System.IO.File]::Decrypt("C:\temp\vsphere7-course.png")

[System.IO.File]::Encrypt("C:\temp\vsphere7-course.png")

Get-ChildItem -Path C:\Temp -File | ForEach-Object -Process {$PSItem.Encrypt()}


Get-ChildItem -Path C:\Temp -File | ForEach-Object -Process {$PSItem.Decrypt()}


#Demonstration: Basic enumeration

#1. Display only the name of every service installed on the computer.

Get-Service | Select-Object -Property Name


#2. Use enumeration to clear the System event log

Clear-EventLog -LogName System 

Get-CimClass -ClassName *event*

$logApp = Get-WmiObject -Class win32_NTLogEvent | Where-Object -FilterScript {$PSItem.LogFile -eq 'Application'} 

foreach ($log in $logApp){

    $log

}


#Encrypt and Decrypt Files
Get-ChildItem -Path C:\Temp -File | ForEach-Object -Process {$PSItem.Encrypt()}

Get-ChildItem -Path C:\Temp -File | ForEach-Object -Process {$PSItem.Decrypt()}


1..100 | ForEach-Object {Get-Random}


#1. Modify all the items in the HKEY_CURRENT_USER\Network\ subkey so that all the names are uppercase.


$basePath = 'HKCU:\Network\'

Get-ChildItem -Path $basePath -Recurse | ForEach-Object -Process {
$suffix = 'za'

$tmpNumber = $PSItem.Name.Split("\").Count

$number = $tmpNumber -1 

$upperName = $PSItem.Name.Split("\")[$number].ToUpper()

$tmpName = $upperName + $suffix

$oldPath = $PSItem.Name -replace ('HKEY_CURRENT_USER','HKCU:')

Rename-Item -Path $oldPath -NewName $tmpName -Force -Verbose

$tmpNewItem = $basePath + $tmpName

#$newItem = $tmpNewItem -replace ('HKEY_CURRENT_USER','HKCU:')

Rename-Item -Path $tmpNewItem -NewName $upperName -Force -Verbose

}

#2. Create a directory named Test in all the Democode folders on the Allfiles drive, and display the path for each directory.

#Question: If you have programming or scripting experience, does ForEach-Object look familiar to you?


$itens = Get-ChildItem -Path C:\Temp -Directory -Recurse 

$itens | ForEach-Object -Process {
New-Item -Path $PSItem.FullName -ItemType Directory -Name 'Test' -Force -Verbose

}


#1. Display a list of files on the E: drive of your computer.

Get-ChildItem -Path C:\Tmp\casadocodigo -Recurse -File | Select-Object -Property fullName


#2. Use enumeration to produce 100 random numbers.

1..100 | ForEach-Object -Process {Get-Random}

#3. Run a method of a Windows Management Instrumentation (WMI) object

$prcNotepad = Get-WmiObject -Class win32_process | Where-Object -FilterScript {$PSItem.ProcessName -eq "Notepad.exe"}

$prcNotepad | get-member

$prcNotepad.GetOwner()


#Sending pipeline data as output

$svcObj = Get-Service

$svcObj.GetType().AssemblyQualifiedName

$svcObj | Get-Member | Select-Object -Property TypeName | Select-Object -First 1

$svcObj.GetValue("1")

$svcObj.GetType().Assembly

$svcObj.GetType().Attributes

$svcObj.GetType()

$svcObjFilter1 = Get-Service | Sort-Object -Property Status,Name | Select-Object -Property DisplayName,Status

$svcObjFilter1 | Get-Member | Select-Object -Property TypeName | Select-Object -First 1


#1. Convert a list of processes to HTML.

Get-Process | ConvertTo-Html -Head "Process List o $env:Computername" -Title "Process List generated today" -PreContent "Complete List" -PostContent "List On" 


#2. Create a file named Procs.html that contains an HTML-formatted list of processes.

Get-Process | Select-Object -First 15 | ConvertTo-Html -Head "Process List o $env:Computername" -Title "Process List generated today" -PreContent "Complete List" -PostContent "List On"  | Out-File -FilePath "$env:SystemDrive\temp\Procs.html"

#3. Convert a list of services to CSV.

Get-Service | Select-Object -Property Name,Status,CanStop,ServiceType,StartType | ConvertTo-Csv


#4. Create a file named Serv.csv that contains a CSV-formatted list of services.

Get-Service | Select-Object -Property Name,Status,CanStop,ServiceType,StartType | Export-Csv -NoTypeInformation -NoOverwrite -Path C:\temp\services.csv -Encoding UTF8

#5. Open Serv.csv in Notepad, and decide whether all the data was retained.


#OUT-HOST (não funciona no ISE)

Get-Service | Out-Host -Paging

Get-Service | Out-Printer -Name 'Microsoft Print to PDF'

Get-service | Out-GridView



#Display the name, department, and city for all the users in the IT department who are located in London, in alphabetical order by name.

Get-ADUser -Filter 'Office -eq "Cacapava" -and Department -eq "IT"' -Properties * | Select-Object -Property Name,Department,Office,City | Sort-Object -Property Name -Descending



#Set the Office location for all the users to LON-A/1000.


Get-ADUser -Filter * | Set-ADUser -Office 'LON-A/1000' -Verbose


#Display the list of users again, including the office assignment for each user

Get-ADUser -Filter * -Properties * | Select-Object -Property Name,Office,City

#2. Display the same list again, and then convert the list to an HTML page. Store the HTML data in E:\UserReport.html. Have the word Users appear before the list of users.

Get-ADUser -Filter * -Properties * | Select-Object -Property Name,Office,City | ConvertTo-Html -Title 'USERS' -Head 'USERS' | Out-File C:\Tmp\Users.html

#3. Use Internet Explorer to view UserReport.html.


Invoke-Item C:\Tmp\Users.html

#4. Display the same list again, and then convert it to XML.


Get-ADUser -Filter * -Properties * | Select-Object -Property Name,Office,City | ConvertTo-Xml -As String

Get-ADUser -Filter * -Properties * | Select-Object -Property Name,Office,City | Export-Clixml -Depth 2 -Path C:\temp\teste.xml

#5. Use Internet Explorer to view UserReport.xml.



#6. Display a list of all the properties of all the Active Directory users in a CSV file.

Get-ADUser -Filter * -Properties * | Export-Csv -Delimiter ';' -NoTypeInformation -Path C:\temp\AllUsers.csv


#Understanding how the pipeline works
#Two techniques for pipeline parameter binding
#Byvalue
#ByPropertyName is tried if Byvalue fails

Get-ADComputer -Filter * | Select-Object -Property @{label='Computername';expression={$PSItem.Name}}


#• Explain how to use manual parameters to override the pipeline.

Get-Process -Name OneDrive | Stop-Process -Name Notepad


#• Override the pipeline.

Get-Process -Name Notepad | Stop-Process
Get-Process -Name Notepad | Stop-Process -Name Notepad #ERROR because the pipeline is expeting an Process (by value)


#• Explain how to specify input by using parenthetical commands instead of the pipeline.

Get-ADGroup 'gl_ftp_users' | Add-ADGroupMember -Members (Get-ADUser -Filter {City -eq 'London'})


#• Use parenthetical commands.

Get-ADGroup 'gl_ftp_users' | Add-ADGroupMember -Members (Get-ADUser -Filter {City -eq 'London'})

#• Explain how to expand object properties into simple values.

Get-Process -ComputerName (Get-ADComputer -Filter * | Select-Object -ExpandProperty Name)

#• Expand property values.

Get-ADUser -Identity Neomatrix -Properties Memberof | Get-ADGroup #FAIL

Get-ADUser -Identity Neomatrix -Properties Memberof | Select-Object -ExpandProperty MemberOf | Get-ADGroup #OK


#1. Open the Windows PowerShell Integrated Scripting Environment (ISE).
#2. Run a command that will list all computers in the domain.




#3. Run a command that uses a parenthetical command to display a list of services from every computer in the domain.
4. Run a command that shows the kind of object that is produced when you retrieve information about
every computer account in the domain.
5. Review the Help for Get-Service to see what kind of object its –ComputerName parameter expects.
6. Run a command that selects only the Name property of every computer in the domain.
7. Run a command that shows the kind of object that the previous command produced.
8. Run a command that extracts the contents of the Name property of every computer in the domain.
9. Run a command that shows the kind of object that the previous command produced.
10. Modify the command in step 3 to use the command in step 8 as the parenthetical command.
11. Run the command that you created in step 10.