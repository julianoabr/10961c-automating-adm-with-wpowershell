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


#Demonstration: Viewing help (PAGE 41)

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


#Demonstration: Using About files (PAGE 45)

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

#3.

Get-Help About_EventLogs -ShowWindow

#4.

Get-Help About_Type_Accelerators -ShowWindow

Get-Help About_Type_Operators -ShowWindow

[console]::beep(500,300)

[console]::beep(2000,500)

[console]::Beep(1000,400)

<#

Question
You wish to join multiple computers to the Adatum domain. The Add-Computer
cmdlet’s -ComputerName parameter accepts multiple values. Which of the following
is a set of valid values for this parameter?
Select the correct answer.
-ComputerName LON-CL2;LON-CL3;LON-CL4
-ComputerName “LON-CL2, LON-CL3, LON-CL4”
-ComputerName LON-CL2 LON-CL3 LON-CL4
-ComputerName LON-CL2, -ComputerName LON-CL3 -ComputerName
LON-CL4
-ComputerName LON-CL2,LON-CL3,LON-CL4

#>

Get-Help -Name Add-Computer -ShowWindow

Add-Computer -ComputerName LON-CL2,LON-CL3,LON-CL4


<#
PAGE 46
In Windows PowerShell version 3.0 and newer, modules autoload if you run a cmdlet that is not currently
loaded. This works if the module that contains the cmdlet is in a folder under the module load paths. By
default, these are %systemdir%\WindowsPowerShell\v1.0\Modules and %userprofiles%\Documents
\WindowsPowerShell\Modules. Within Windows PowerShell, these pThe Get-Help command uses
autoloading when searching for help topics. The Get-Command command also uses autoloading.

#>


#LESSON 3 - Finding Commands

#Demonstration: Viewing modules (PAGE 47)
<#

Demonstration Steps
1. Open the Windows PowerShell console as an administrator on LON-DC1.
2. Display a list of currently loaded modules.
3. Run the cmdlet that returns a list of Active Directory users.
4. Display the updated list of currently loaded modules.
5. Display a list of the currently available modules, including those that are not loaded.
6. Import the module that contains cmdlets for managing features installed on a server and display the
updated list of loaded modules.

#>

#2

Get-Module

#3

Get-ADUser -Filter * -SearchBase "dc=domain,dc=intranet"

#4

Get-Module

#5

Get-Module -All

#6

Import-Module -Name ServerManager -Verbose

<#

Demonstration: Searching for cmdlets (PAGE 49)


In this demonstration, you will see how to use several techniques to discover new cmdlets.
Demonstration Steps
1. Show a list of commands that deal with IPv4 addresses.
2. There is a command able to read Windows Event Logs (actually, there are two). Find one that can
read event logs from a remote computer in addition to the local one.

#>

#1
Get-Command -Name *IPv4*

Get-Command -noun *ipv4*

Get-Command -Module NetAdapter

#2

Get-Command -Noun event* -Verb Get

Get-Command -Name *event*

Get-Command -Noun *EventLog*

Get-Command -Name *EventLog* -ArgumentList "ComputerName"

Get-Command -Name *event* -ParameterName *Computer*

#ALIASES

#Demonstration: Using aliases (PAGE 50)

#Demonstration Steps

#1. Run the dir and Get-ChildItem commands, and then compare the results.

dir
Get-ChildItem 

#Result is the same

#2. View the definition for the dir alias.

Get-Alias di*

Get-Alias -Name dir -Verbose

#3. Create a new alias, list, for the Get-ChildItem command.

Get-Help New-Alias -ShowWindow

new-alias -Name 'list' -Value get-childitem -Description 'list files in a folder' 

New-Alias -Name "List" Get-ChildItem

#4. Run the list command and compare the results to those of dir and Get-ChildItem.

List

#5. Show the definition for the list alias.

Get-Alias -Name List

get-alias | Where-Object -FilterScript {$psitem.ReferencedCommand -like 'Get-ChildItem'}

#6. Show the various aliases for Get-ChildItem.

Get-Alias | Where-Object -FilterScript {$_.ReferencedCommand -like "Get-ChildItem"}


#Using Show-Command

Show-Command –Name Get-ADUser

Show-Command Get-ADUser

Show-Command -Name new-alias

#Question: What is the difference between Get-Help and Get-Command? Why might they return different results for the same query?

#Get-Help shows examples of a Command. Shows the parameters of a Command and Online Help about a Command. 
#Get-Command open a window where you can put parameters


#Lab B: Finding and running basic commands (PAGE 52)

#On LON-CL1, ensure that you are signed in as Adatum\Administrator and determine answers to the following questions:

#What command would you run to resolve a DNS name?

$computerName = (Get-ComputerInfo -Property Cscaption).CsCaption

Resolve-DnsName -Name $computerName

(Resolve-DnsName -Name server.domain).IPAddress

#What command would you run to make changes to a network adapter? After finding such a command, what parameter would you use to change its MAC address (on adapters that support changes to their MAC address)?
#https://docs.microsoft.com/en-us/powershell/module/netadapter/set-netadapter?view=win10-ps

Get-Command -Noun *adapter*

Set-NetAdapter –Name "Ethernet 1" -MacAddress "00-10-18-57-1B-0D"


#What command would let you enable a previously disabled scheduled task?

Get-ScheduledTask -TaskPath "\UpdateTasks\" | Enable-ScheduledTask

Enable-ScheduledTask -TaskName "SystemScan"

Get-ScheduledTask | Where-Object -FilterScript {$_.TaskName -like '*Windows 2000*'} | Enable-ScheduledTask -Verbose

#What command would let you block access to a file share by a particular user?

Get-Command -Noun *share*

Block-FileShareAccess -Name "VMFiles" -AccountName "Contoso\Guest"

#What command would you run to clear your computer’s local BranchCache cache?

Get-Command -Noun *cache*

Clear-BCCache -Confirm:$false -Verbose

#What command would you run to display a list of Windows Firewall rules? What parameter of that command would display only enabled rules?

get-command -Noun *firewall*

Get-NetFirewallRule

Get-NetFirewallRule  | Where-Object -FilterScript {$PSItem.Enabled -eq $True}

#What command would you run to display a list of all locally bound IP addresses?

Get-NetIPAddress | Select-Object -Property IPAddress, InterfaceIndex, InterfaceAlias

#What command would you run to suspend an active print job in a print queue?

Get-Command -Noun *print*

$PrintJob = Get-PrintJob -PrinterName "PrinterName" -ID 1 

Suspend-PrintJob -InputObject $printJob

#What native Windows PowerShell command would you run to read the content of a text file?

Get-content .\temp06072022.txt


<#Exercise 2: Running commands
Scenario
In this exercise, you will run several basic Windows PowerShell commands. In some instances, you might
have to find the commands that you will use to complete the task.
The main task for this exercise is as follows:

1. Run commands to accomplish specified tasks.

#>

#Task 1: Run commands to accomplish specified tasks (PAGE 53)

#1. Ensure you are signed in on the LON-CL1 virtual machine as Adatum\Administrator.

whoami

Get-WmiObject -Class Win32_ComputerSystem | Select-Object -Property Username

Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property UserName,Caption

#2. Display a list of enabled Windows Firewall rules.

Get-NetFirewallRule -Enabled True

#3. Display a list of all local IPv4 addresses.

Get-NetIPAddress | Select-Object -Property InterfaceAlias, InterfaceIndex, IPAddress


#4. Set the startup type of the BITS service to Automatic:

$svcToAlterStartType = Get-service -Name BITS 

$svcStartType = $svcToAlterStartType.StartType
 
Get-service -Name Audiosrv | Set-Service -StartupType $svcStartType #get a service with automatic startup type and change another service

get-service -Name BITS | Set-Service -StartupType Automatic

#a. Open the Computer Management console and go to Services and Applications.

compmgmt.msc


#b. Locate the Background Intelligence Transfer Service (BITS) and note its startup type setting prior to and after changing the startup type in Windows PowerShell.


#5. Test the network connection to LON-DC1. Your command should return only a True or False value, without any other output.

(Test-NetConnection -ComputerName LON-DC1 -Verbose).PingSucceeded


#6. Display the newest 10 entries from the local Security event log.

Get-EventLog -LogName Security -Newest 10


#Exercise 3: Using About files (PAGE 54)

<#

Scenario
In this exercise, you will use help discovery techniques to find content in About files, and then use that
content to answer questions about global Windows PowerShell functionality.
Words in italic are clues. Remember that you must use Get-Help and wildcard characters. Because About
files are not commands, Get-Command will not be useful in this exercise.
The main tasks for this exercise are as follows:
1. Locate and read About help files.
2. Prepare for the next module.


#>

#Task 1: Locate and read About help files
#Ensure that you are still signed in to LON-CL1 as Adatum\Administrator from the previous exercise,and answer the following questions:
#What comparison operator does Windows PowerShell use for wildcard string comparisons?

Get-help about_comparison_operators -ShowWindow

#Are Windows PowerShell comparison operators typically case-sensitive?

<#No. By default, all comparison operators are case-insensitive. To make a
comparison operator case-sensitive, add a c after the -. For example, -ceq
is the case-sensitive version of -eq. To make the case-insensitivity
explicit, add an i before -. For example, -ieq is the explicitly
case-insensitive version of -eq.
#>

#How would you use $Env to display the COMPUTERNAME environment variable?

$env:Computername

#What external command could you use to create a self-signed digital certificate that is usable for signing Windows PowerShell scripts?

New-SelfSignedCertificate

makecert #to create self signed certificates

<#

Module 2
Cmdlets for administration
Contents:
Module Overview 2-1
Lesson 1: Active Directory administration cmdlets 2-2
Lesson 2: Network configuration cmdlets 2-13
Lesson 3: Other server administration cmdlets 2-19
Lab: Windows administration 2-24
Module Review and Takeaways 2-28

#>


<#For example, you can retrieve the default set of properties along with the department and email address
of a user with the SAM account janedoe by typing the following command in the console, and then
pressing Enter:
#>
Get-ADUser -Identity janedoe -Properties Department,EmailAddress

<#

The other way to specify a user or users is with the -Filter parameter. The -Filter parameter accepts a query
based on regular expressions, which later modules in this course cover in more detail. For example, to
retrieve all AD DS users and their properties, type the following command in the console, and then press
Enter:

#>

Get-ADUser -Filter * -Properties *


#To create a new group named FileServerAdmins, type the following command in the console, and then press Enter:
New-ADGroup -Name FileServerAdmins -GroupScope Global


<#Create a new global group in the IT department
1. On LON-CL1, start a Windows PowerShell session with elevated permissions.
2. Run the following command:
#>

New-ADGroup -Name HelpDesk -Path "ou=IT,dc=Adatum,dc=com" –GroupScope Global

#Create a new user in the IT department
New-ADUser -Name “Jane Doe” -Department “IT”

#Add two users from the IT department to the HelpDesk group
Add-ADGroupMember “HelpDesk” -Members “Lara”,”Jane Doe”

#Set the address for a HelpDesk group user
Get-ADGroupMember HelpDesk

Set-ADUser Lara -StreetAddress "1530 Nowhere Ave." -City "Winnipeg" -State "Manitoba" -Country "CA"

#Verify the group membership for the new user

Get-ADPrincipalGroupMembership “Jane Doe” 

#Verify the updated user properties
Get-ADUser Lara -Properties StreetAddress,City,State,Country

#The following is an example of a command that you can use to create a computer account:
New-ADComputer -Name LON-CL10 -Path "ou=marketing,dc=adatum,dc=com" -Enabled $true


#The following is an example of a command to create a new OU:
New-ADOrganizationalUnit -Name Sales -Path "ou=marketing,dc=adatum,dc=com" -ProtectedFromAccidentalDeletion $true


#The following command creates a new contact object:
New-ADObject -Name "JohnSmithcontact" -Type contact


#Create an Active Directory contact object that has no dedicated cmdlets
New-ADObject -Name JohnSmithcontact -Type contact -DisplayName “John Smith(Contoso.com)”


#Verify the creation of the contact
Get-ADObject -Filter 'ObjectClass -eq "contact"'

#Manage user properties by using Active Directory object cmdlets
Set-ADObject -Identity “CN=Lara Raisic,OU=IT,DC=Adatum,DC=com" -Description “Member of support team”


#Verify the property changes

Get-ADUser Lara -Properties Description

#Change the name of the HelpDesk group to SupportTeam

Rename-ADObject -Identity “CN=HelpDesk,OU=IT,DC=Adatum,DC=com” -NewName SupportTeam

#Verify the HelpDesk group name change

Get-ADGroup HelpDesk


<#

Which of the following cmdlet verbs is not associated with the ADUser noun?
Select the correct answer.
Get
X Update (THE ONLY VERB THAT DOES NOT APPEAR
New
Remove
Set

#>

Get-Command -Noun *Aduser*

#The default value for the -ProtectedFromAccidentalDeletion parameter of New-ADOrganizationalUnit is $true. (OK)

#Run the command

Get-help New-ADOrganizationalUnit -ShowWindow

#You will view the following info

<#

-ProtectedFromAccidentalDeletion <Boolean>
        Specifies whether to prevent the object from being deleted. When this property is set to true, you cannot delete the corresponding object without changing the value of the property. Possible values for this parameter include:
        

        Required?                    false
        Position?                    named
        Default value                $true
        Accept pipeline input?       True (ByPropertyName)
        Accept wildcard characters?  false


#>

#The default value for the -ProtectedFromAccidentalDeletion parameter of New-ADOrganizationalUnit is $true.
$item = (get-help -Name New-ADOrganizationalUnit -Parameter 'ProtectedFromAccidentalDeletion')

$item.defaultValue


#The following command creates a new IP address on the Ethernet interface:
New-NetIPAddress -IPAddress 192.168.1.10 -InterfaceAlias “Ethernet” -PrefixLength 24 -DefaultGateway 192.168.1.1

#The following command creates an IP routing table entry:
New-NetRoute -DestinationPrefix 0.0.0.0/24 -InterfaceAlias “Ethernet” -DefaultGateway 192.168.1.1


#The following command sets the connection-specific suffix for an interface:
Set-DnsClient -InterfaceAlias Ethernet -ConnectionSpecificSuffix “adatum.com”

# The following commands both enable firewall rules in the group Remote Access:
Enable-NetFirewallRule -DisplayGroup “Remote Access”

Set-NetFirewallRule -DisplayGroup “Remote Access” -Enabled True


#Run the following command:
Test-Connection LON-DC1

#Change the client IP address
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 172.16.0.30 -PrefixLength 16

Remove-NetIPAddress -InterfaceAlias Ethernet -IPAddress 172.16.0.40

#Change the DNS server for LON-CL1
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddress 172.16.0.11


#Change the default gateway for LON-CL1
Remove-NetRoute -InterfaceAlias Ethernet -DestinationPrefix 0.0.0.0/0

New-NetRoute -InterfaceAlias Ethernet -DestinationPrefix 0.0.0.0/0 -NextHop 172.16.0.2

#Confirm the network configuration changes

Get-NetIPConfiguration

#Test the effect of the changes

Test-Connection LON-DC1

#Question: Which two parameters can you use with *-NetIPAddress cmdlets to identify a network interface?

Get-Help Get-NetIPAddress -Parameter InterfaceAlias

Get-Help Get-NetIPAddress -Parameter InterfaceIndex


#Lesson 3
#Other server administration cmdlets

#Group Policy management cmdlets

#The following command creates a new GPO from a starter GPO:

New-GPO -Name “IT Team GPO” -StarterGPOName “IT Starter GPO”

#The following command links the new GPO to an AD DS container:

New-GPLink -Name “IT Team GPO” -Target “OU=IT,DC=adatum,DC=com”


#Server Manager cmdlets


#The following command installs network load balancing on the local server:
Install-WindowsFeature “nlb”


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

#You can install the Hyper-V module from within Windows PowerShell by installing the Windows feature. To do so, type the following command in the console, and then press Enter:

Enable-WindowsOptionalFeature -Feature Microsoft-Hyper-V-Management-PowerShell -Online


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

#To create a new IIS website, type the following command in the console, and then press Enter:
New-WebSite “London” -PhysicalPath C:\inetpub\wwwroot\london -IPaddress 172.16.0.15 -ApplicationPool LondonAppPool


<#Note: The WebAdministration module represents IIS as a PSDrive, which you can navigate
by using the Set-Location IIS:\ command. This allows you to navigate the IIS structure by using
cmdlets such as Get-ChildItem. You will learn more about PSDrives in Module 5, “Using
PSProviders and PSDrives.”
#>

#Question: What Windows feature must you install before you can use Hyper-V cmdlets?

Get-WindowsFeature -Name *Hyper*

Install-WindowsFeature -Name Hyper-V -IncludeAllSubFeature -IncludeManagementTools -LogPath  "$env:SystemDrive\Temp\LogInstallHyper-V.txt" -Verbose


#Task 1: Create a new organizational unit (OU) for a branch office
New-ADOrganizationalUnit -Name "London" -Path "dc=sth,dc=local" -ProtectedFromAccidentalDeletion:$true -Verbose


#Task 2: Create group for branch office administrators
New-ADGroup -Name "London Admins" -Path "Ou=London,dc=sth,dc=local" -GroupCategory Security -GroupScope Global -Confirm:$false -Verbose

#Task 3: Create a user and computer account for the branch office

#1. In the PowerShell console, create a user account for the user Ty Carlson.

$splat = @{
    Name = 'TyCarlson'
    DisplayName = "Ty Carlson"
    AccountPassword = (Read-Host -AsSecureString 'AccountPassword')
    Enabled = $true
    Path = "ou=London,dc=sth,dc=local"
    EmailAddress = "tycarson@sth.local"
}
New-ADUser @splat



#2. Add the user to the London Admins group.

Add-ADGroupMember -Identity "London Admins" -Members "TyCarlson" -Verbose

#3. Create a computer account for the LON-CL2 computer.

New-ADComputer -Name "LON-CL2" -Path "Ou=London,dc=sth,dc=local" -DisplayName "LON CL2" -Verbose

#Task 4: Move the group, user, and computer accounts to the branch office OU

Get-ADGroup -Identity "London Admins" | Move-ADObject -TargetPath "ou=Cambridge,dc=sth,dc=local" -Confirm:$false -Verbose

Get-ADUser -Identity "TyCarlson" | Move-ADObject -TargetPath "ou=Cambridge,dc=sth,dc=local" -Confirm:$false -Verbose

Get-ADComputer -Identity "LON-CL2" | Move-ADObject -TargetPath "ou=Cambridge,dc=sth,dc=local" -Confirm:$false -Verbose


# Task 1: Test the network connection and view the configuration


#1. Switch to LON-SVR1.
#2. Open Windows PowerShell.
#3. Test the connection to LON-DC1, and then note the speed of the test.

Test-NetConnection -ComputerName LON-DC1 -Verbose

#4. View the network configuration for LON-SVR1.

Get-NetIPConfiguration

#5. Note the IP address, default gateway, and DNS server.

#Task 2: Change the server IP address

#Use Windows PowerShell to change the IP address for the Ethernet network interface to 172.16.0.15/16.

New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 172.16.0.15 -PrefixLength 16

#Task 3: Change the DNS settings and default gateway for the server
#1. Change the DNS settings of the Ethernet network interface to point at 172.16.0.12.

Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 172.16.0.12

#2. Change the default gateway for the Ethernet network interface to 172.16.0.2

New-NetIPAddress -InterfaceAlias Ethernet -DefaultGateway 172.16.0.2

#Task 4: Verify and test the changes
#1. On LON-SVR1, verify the changes to the network configuration.

Get-NetIPConfiguration

#2. Test the connection to LON-DC1, and then note the difference in the test speed.

Test-NetConnection -ComputerName LON-DC1 -Verbose


#Task 1: Install IIS on the server
#• Use Windows PowerShell to install IIS on LON-SVR1.

Install-WindowsFeature -ComputerName LON-SVR1 -Name Web-Server -IncludeAllSubFeature -IncludeManagementTools -LogPath "$env:SystemDrive\Temp\InstallIISLog.log" -Confirm:$false -Verbose

#Task 2: Create a folder on the server for the website files
#• On LON-SVR1, use PowerShell to create a folder named London under C:\inetpub\wwwroot for the website files.

New-Folder -Name "London" -Location "$env:SystemDrive\inetpub\wwwroot" -Confirm:$false -Verbose

#Task 3: Create a new application pool for the website
#• On LON-SVR1, use PowerShell to create an application pool for the site named LondonAppPool.

#https://learn.microsoft.com/en-us/iis/manage/powershell/powershell-snap-in-creating-web-sites-web-applications-virtual-directories-and-application-pools

Get-Command -Name *pool*

New-WebAppPool -Name LondonAppPool

New-Item IIS:\Sites\London -PhysicalPath C:\inetpub\wwwroot\London -Bindings @{protocol="https";bindingInformation=":8080:"}
Set-ItemProperty IIS:\Sites\London -Name ApplicationPool -Value NewAppPool

#Exemples from Link
New-Item IIS:\Sites\DemoSite -physicalPath C:\DemoSite -bindings @{protocol="http";bindingInformation="172.16.0.15:8080:"}
Set-ItemProperty IIS:\Sites\DemoSite -name applicationPool -value DemoAppPool
New-Item IIS:\Sites\DemoSite\DemoApp -physicalPath C:\DemoSite\DemoApp -type Application
Set-ItemProperty IIS:\sites\DemoSite\DemoApp -name applicationPool -value DemoAppPool
New-Item IIS:\Sites\DemoSite\DemoVirtualDir1 -physicalPath C:\DemoSite\DemoVirtualDir1 -type VirtualDirectory
New-Item IIS:\Sites\DemoSite\DemoApp\DemoVirtualDir2 -physicalPath C:\DemoSite\DemoVirtualDir2 -type VirtualDirectory

<#

Task 4: Create the IIS website
1. On LON-SVR1, use PowerShell to create the IIS website by using the following configuration:
o Name: London
o Physical path: The folder that you created earlier
o IP address: The current IP address of LON-SVR1
o Application pool: LondonAppPool
2. Open the website in Internet Explorer by using the IP address, and then verify that the site is using the
provided settings.
Note: Internet Explorer displays an error message. The error message details give the
physical path of the site, which should be C:\inetpub\wwwroot\london.

#>

<#Common Issues and Troubleshooting Tips

1. Common Issue Troubleshooting Tip
When I run the Get-Help command for a cmdlet with the -Example parameter, I do
not see any examples.

Because the correct is "-Examples" and not "-Example"

2. I update the Windows PowerShell version on my system, but a new command does
not appear to do anything.

Did you validate if command really exists and syntax is correct with Verb-Noun form?

#>

#Review Questions
#Question: What command in the Windows PowerShell command-line interface can you use instead of ping.exe?

Test-NetConnection

#Question: Name at least two ways in which you can create an Active Directory Domain Services (AD DS) user account by using Windows PowerShell.

New-ADUser

New-ADObject 

##########################################################MODULE 3######################################################


<#

Module 3
Working with the Windows PowerShell pipeline
Contents:
Module Overview 3-1
Lesson 1: Understanding the pipeline 3-2
Lesson 2: Selecting, sorting, and measuring objects 3-8
Lab A: Using the pipeline 3-16
Lesson 3: Filtering objects out of the pipeline 3-19
Lab B: Filtering objects 3-25
Lesson 4: Enumerating objects in the pipeline 3-28
Lab C: Enumerating objects 3-32
Lesson 5: Sending pipeline data as output 3-34
Lab D: Sending output to a file 3-39
Module Review and Takeaways 3-41

https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pipelines?view=powershell-7.3

#>

#Demonstration: Viewing object members
#In this demonstration, you will see how to run commands in the pipeline and how to use Get-Member. Demonstration Steps
#1. Sign in to LON-CL1 as an administrator, and then start Windows PowerShell.
#2. Display the members of the Service object.

Get-Service | Get-Member


#3. Display the members of the Process object.

Get-Process | Get-Member

#4. Display the list of members for the output of the Get-ChildItem command.

Get-Member -InputObject (Get-ChildItem)

Get-ChildItem -Path C:\TEMP | get-member

$tmpOutput = Get-ChildItem -Path .\

$tmpOutput | Get-Member


#5. Display the list of members for the output of the Get-ADUser command


Get-ADUser -identity jaribeiro | get-member


#6. Display the list of members for the output of the Get-ADUser command, displaying all members.

Get-aduser -Filter * | get-member

#Demonstration: Formatting pipeline output
#In this demonstration, you will see how to format pipeline output.

#1. Display the services running on LON-CL1 by using the default output format.

Get-Service

#2. Display the names and statuses of the services running on LON-CL1 in a simple list.

Get-Service | Format-List

#3. Display a list of the computers in the current domain, including the operating systems, by using the default output format.

$adPC = Get-ADComputer -Filter * -Properties *


#4. Display a table that contains only the names and operating systems for all the computers in the current domain.

Get-ADComputer -Filter * -Properties * | Select-Object -Property Name, OperatingSystem | Format-Table -AutoSize

#5. Display a list of all the Active Directory users in the current domain.

Get-ADUser -Filter *

#6. Display the user names of all the Active Directory users in the current domain. Display the list in a multicolumn format, and let Windows PowerShell decide the number of columns.

Get-ADUser -Filter * | Format-Wide -Property Name


<#

Verify the correctness of the statement by placing a mark in the column to the right.
Statement Answer
The Format-Wide cmdlet accepts the -AutoSize and -Wrap parameters.

Autosize equals TRUE
Wrap equals FALSE

#>

#Demonstration: Sorting objects
#In this demonstration, you will see how to sort objects by using the Sort-Object command.
#Demonstration Steps
#1. Display a list of processes.

Get-Process | Select-Object -Property Name | Format-List

#2. Display a list of processes sorted by process ID.

Get-Process | Sort-Object -Property ID

#3. Display a list of services sorted by status.

Get-Service | Sort-Object -Property Status

#4. Display a list of services sorted in reverse order by status.

Get-Service | Sort-Object -Property Status -Descending

#5. Display a list of the 10 most recent Security event log entries that is sorted with the newest entry first.

Get-EventLog -LogName Security -Newest 10 | Sort-Object -Property TimeWritten

#6. Display a list of the 10 most recent Security event log entries that is sorted with the oldest entry first, and then clear the event log.

Get-EventLog -LogName Security -Newest 10 | Sort-Object -Property TimeWritten -Descending

Clear-EventLog -LogName Security -Confirm:$false -Verbose

#7. Display the user names of all Active Directory users in wide format and sorted by surname.

Get-ADUser -Filter * | Sort-Object -Property surname | Format-Wide

##################################STOPPED ON PAGE 93 #########################################












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

Get-ADComputer -Filter *


#3. Run a command that uses a parenthetical command to display a list of services from every computer in the domain.



#4. Run a command that shows the kind of object that is produced when you retrieve information about every computer account in the domain.
#5. Review the Help for Get-Service to see what kind of object its –ComputerName parameter expects.
#6. Run a command that selects only the Name property of every computer in the domain.
#7. Run a command that shows the kind of object that the previous command produced.
#8. Run a command that extracts the contents of the Name property of every computer in the domain.
#9. Run a command that shows the kind of object that the previous command produced.
#10. Modify the command in step 3 to use the command in step 8 as the parenthetical command.
#11. Run the command that you created in step 10.
