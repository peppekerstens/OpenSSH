function Install-pfSenseConfigurator{
	<#
	This function is meant to ease the preparation of the VM which is assigned to configure the pfSense VM. 
	Just run this function and everything to enable a automatic pfSense config will be in place
	This function MUST be run in an elevated Powershell session and assumes a working Internet connection
	#>

    [CmdletBinding()]
    param(
        [string]$ScheduleExecute = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        [string]$ScheduleArgument = "-NonInteractive -NoProfile -ExecutionPolicy Unrestricted -Command Import-Module pfSenseConfigurator;Start-pfSenseConfigurator",
        [string]$LogPath = 'C:\Support\Logging',
        [bool]$Logging = $false #For debugging
    )

    #Check to see if we are currently running "as Administrator"
    if ((Test-Administrator) -eq $false)
    {
        Write-Error -Message 'This function needs an elevated PowerShell session to work!'
        return
    }

    #Check if logging is wanted
    If ($Logging)
    {
        $PreviousVerbosePreference = $VerbosePreference
        $VerbosePreference = "Continue"
        If (!(Test-path -Path $LogPath)){New-Item -Path $LogPath -ItemType Directory}
        Start-Transcript "$($LogPath)\$($MyInvocation.MyCommand.Name).log"
    }

	<#
	#Check if (open)SSH is installed
	$Path = ([Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)) -split ';'
    If ($Path -notlike "C:\Program Files\OpenSSH*"){
		Install-OpenSSH
    }
	#>

	#Check if POSH-SSH is installed
	Try{
		Get-Package -Name 'Posh-SSH' -ErrorAction Stop
	}
	Catch
	{
		Find-Package -Name 'Posh-SSH'
		Install-Package -Name 'Posh-SSH' -Source 'PSGallery' -Force
	}

    #Create a scheduled task to run when machine starts
    $action = New-ScheduledTaskAction -Execute $ScheduleExecute -Argument $ScheduleArgument
    $trigger =  New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "pfSenseConfigurator" -Description "ITON one-time pfSense configuration script"

    If ($Logging)
    {
        $PreviousVerbosePreference = $VerbosePreference
        Stop-Transcript
    }
}

function Start-pfSenseConfigurator{
	<#
	This function tries to configure the pfSense VM.
	This function assumes that the VM it is running on has been prepped by running Install-pfSenseConfigurator
	#>
    [CmdletBinding()]
    param(
		[Parameter(Mandatory=$true)]
		[string]$publicIp,

		[Parameter(Mandatory=$true)]
		[string]$publicGateway,

		[Parameter(Mandatory=$true)]
		[string]$privateIp,

		[Parameter(Mandatory=$true)]
		[string]$wapIp,

		[Parameter(Mandatory=$true)]
		[string]$pfsenseAdmin,

		[Parameter(Mandatory=$true)]
		[string]$pfsensePassword,

        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_ -IsValid})]
        [string]$LogPath = 'C:\Support\Logging',

        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_ -IsValid})]
        [string]$XMLPath = 'C:\Support\Scripts',

        [ValidateNotNullOrEmpty()]
        [string]$XMLName = 'pfSenseXMLTemplate.xml',

        [bool]$Logging = $true #For debugging
    )

    If ($Logging)
    {
        $PreviousVerbosePreference = $VerbosePreference
        $VerbosePreference = "Continue"
        If (!(Test-path -Path $LogPath)){New-Item -Path $LogPath -ItemType Directory}
        Start-Transcript "$($LogPath)\$($MyInvocation.MyCommand.Name).log"
    }

	#Check if template XML file exists
	If (!(Test-Path -Path "$($XMLPath)\$($XMLName)")){
		New-XMLTemplate -Path $XMLPath -Name $XMLName
	}

	#Set temporary default pfSense IP config on LAN adapter, assuming first adapter on this VM is LAN
	New-NetIPAddress -InterfaceAlias (Get-NetAdapter)[0].Name -AddressFamily IPv4 -IPAddress 192.168.1.2 -PrefixLength 24 -DefaultGateway 192.168.1.1

	#Create a credential for the default pfSense username/password
	$securePassword = ConvertTo-SecureString “pfsense” -AsPlainText -Force
	$credential = New-Object System.Management.Automation.PSCredential (“admin”, $securePassword)

	#Try to reach pfSense interface 
	Import-Module -Name 'Posh-SSH'
	$pfsenseNotUp = $true
	while($pfsenseNotUp) {
		if(Test-Connection 192.168.1.1) {
			#..and replace config
			$SFTP = New-SFTPSession -ComputerName "192.168.1.1" -Credential $credential -AcceptKey

			$content = (Get-Content "$($XMLPath)\$($XMLName)" | Out-String)

			$content = $content.Replace("{wanip}", $publicIp)
			$content = $content.Replace("{wangateway}", $publicGateway)
			$content = $content.Replace("{lanip}", $privateIp)
			$content = $content.Replace("{wapip}", $wapIp)
			$content = $content.Replace("{adminUsername}", $pfsenseAdmin)

			Set-SFTPContent -SessionId $SFTP.SessionId -Path /cf/conf/config.xml -Value $content

			$SFTP.Disconnect();

			#Now try to reboot pfSense VM and replace admin password by navigating to right menu item
			$SSH = New-SSHSession -ComputerName "192.168.1.1" -Credential $credential -AcceptKey 
			$SSHStream = New-SSHShellStream -SessionId $SSH.SessionId
			
			Start-Sleep -s 2
			$SSHStream.WriteLine("5");
			$SSHStream.read()
			Start-Sleep -s 2
			$SSHStream.WriteLine("y");
			$SSHStream.read()

			Start-Sleep -s 30
		 } Elseif (Test-Connection $privateIp) {
			#Remove temporary IP on LAN adapter
			Get-NetIPAddress -IPAddress 192.168.1.2 | Remove-NetIPAddress -Confirm:$false
			
			$pfsenseNotUp = $false
		 }
	}

	#Now...replace password by navigating to right menu items
	$SSH = New-SSHSession -ComputerName $privateIp -Credential $credential -AcceptKey 
	$SSHStream = New-SSHShellStream -SessionId $SSH.SessionId
	$SSHStream.read()
	Start-Sleep -s 2
	$SSHStream.WriteLine("12");
	$SSHStream.read()
	$SSHStream.WriteLine('playback changepassword')
	Start-Sleep -s 2
	$SSHStream.WriteLine($pfsenseAdmin)
	Start-Sleep -s 2
	$SSHStream.WriteLine($pfsensePassword)
	Start-Sleep -s 2
	$SSHStream.WriteLine($pfsensePassword)
	Start-Sleep -s 2
	$SSHStream.read()
	Start-Sleep -s 2
	$SSHStream.WriteLine("exit");
	$SSHStream.read()
	Start-Sleep -s 2

	#...and reboot pfSense VM
	$SSHStream.WriteLine("5");
	$SSHStream.read()
	Start-Sleep -s 2
	$SSHStream.WriteLine("y");
	$SSHStream.read()

	#Wait for pfSense VM to reboot
	$pfsenseNotUp = $true
	while($pfsenseNotUp) {
		if (Test-Connection $privateIp) {
			$pfsenseNotUp = $false
		}
		Start-Sleep -s 30
	}

    #Remove this script from startup
    Unregister-ScheduledTask -TaskName "pfSenseConfigurator" -Confirm:$false


    If ($Logging)
    {
        #Clean-up
        $VerbosePreference = $PreviousVerbosePreference
        Stop-Transcript
    }
}


#region helper functions
function YesNo ($message) {
    #source: https://www.reddit.com/r/PowerShell/comments/493pl5/convert_batch_yesno_to_powershell_is_it_possible/ 

    $title = "Continue :"
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Continues with currect selection"
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","Stops currect selection"
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

    $result = $host.ui.PromptForChoice($title, $message, $options, 1) 
    $SwitchOption = $result

    switch ($SwitchOption){
            0 {return "Yes"}
            1 {return "No"}
            #default {"No"}
    }
}#This function will prompt for YesNo

Function Test-URI {
    <#
    .Synopsis
    Test a URI or URL
    .Description
    This command will test the validity of a given URL or URI that begins with either http or https. The default behavior is to write a Boolean value to the pipeline. But you can also ask for more detail.
    
    Be aware that a URI may return a value of True because the server responded correctly. For example this will appear that the URI is valid.
    
    test-uri -uri http://files.snapfiles.com/localdl936/CrystalDiskInfo7_2_0.zip
    
    But if you look at the test in detail:
    
    ResponseUri   : http://files.snapfiles.com/localdl936/CrystalDiskInfo7_2_0.zip
    ContentLength : 23070
    ContentType   : text/html
    LastModified  : 1/19/2015 11:34:44 AM
    Status        : 200
    
    You'll see that the content type is Text and most likely a 404 page. By comparison, this is the desired result from the correct URI:
    
    PS C:\> test-uri -detail -uri http://files.snapfiles.com/localdl936/CrystalDiskInfo6_3_0.zip
    
    ResponseUri   : http://files.snapfiles.com/localdl936/CrystalDiskInfo6_3_0.zip
    ContentLength : 2863977
    ContentType   : application/x-zip-compressed
    LastModified  : 12/31/2014 1:48:34 PM
    Status        : 200
    
    .Example
    PS C:\> test-uri https://www.petri.com
    True
    .Example
    PS C:\> test-uri https://www.petri.com -detail
    
    ResponseUri   : https://www.petri.com/
    ContentLength : -1
    ContentType   : text/html; charset=UTF-8
    LastModified  : 1/19/2015 12:14:57 PM
    Status        : 200
    .Example
    PS C:\> get-content D:\temp\uris.txt | test-uri -Detail | where { $_.status -ne 200 -OR $_.contentType -notmatch "application"}
    
    ResponseUri   : http://files.snapfiles.com/localdl936/CrystalDiskInfo7_2_0.zip
    ContentLength : 23070
    ContentType   : text/html
    LastModified  : 1/19/2015 11:34:44 AM
    Status        : 200
    
    ResponseURI   : http://download.bleepingcomputer.com/grinler/rkill
    ContentLength : 
    ContentType   : 
    LastModified  : 
    Status        : 404
    
    Test a list of URIs and filter for those that are not OK or where the type is not an application.
    .Notes
    Last Updated: January 19, 2015
    Version     : 1.0
    
    Learn more about PowerShell:
    http://jdhitsolutions.com/blog/essential-powershell-resources/
    
    ****************************************************************
    * DO NOT USE IN A PRODUCTION ENVIRONMENT UNTIL YOU HAVE TESTED *
    * THOROUGHLY IN A LAB ENVIRONMENT. USE AT YOUR OWN RISK.  IF   *
    * YOU DO NOT UNDERSTAND WHAT THIS SCRIPT DOES OR HOW IT WORKS, *
    * DO NOT USE IT OUTSIDE OF A SECURE, TEST SETTING.             *
    ****************************************************************
    .Link
    https://www.petri.com/testing-uris-urls-powershell
    #>
    
    [cmdletbinding(DefaultParameterSetName="Default")]
    Param(
    [Parameter(Position=0,Mandatory,HelpMessage="Enter the URI path starting with HTTP or HTTPS",
    ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidatePattern( "^(http|https)://" )]
    [Alias("url")]
    [string]$URI,
    [Parameter(ParameterSetName="Detail")]
    [Switch]$Detail,
    [ValidateScript({$_ -ge 0})]
    [int]$Timeout = 30
    )
    
    Begin {
        Write-Verbose -Message "Starting $($MyInvocation.Mycommand)" 
        Write-Verbose -message "Using parameter set $($PSCmdlet.ParameterSetName)" 
    } #close begin block
    
    Process {
    
        Write-Verbose -Message "Testing $uri"
        Try {
        #hash table of parameter values for Invoke-Webrequest
        $paramHash = @{
        UseBasicParsing = $True
        DisableKeepAlive = $True
        Uri = $uri
        Method = 'Head'
        ErrorAction = 'stop'
        TimeoutSec = $Timeout
        }
    
        $test = Invoke-WebRequest @paramHash
    
        if ($Detail) {
            $test.BaseResponse | 
            Select ResponseURI,ContentLength,ContentType,LastModified,
            @{Name="Status";Expression={$Test.StatusCode}}
        } #if $detail
        else {
        if ($test.statuscode -ne 200) {
                #it is unlikely this code will ever run but just in case
                Write-Verbose -Message "Failed to request $uri"
                write-Verbose -message ($test | out-string)
                $False
            }
            else {
                $True
            }
        } #else quiet
        
        }
        Catch {
        #there was an exception getting the URI
        write-verbose -message $_.exception
        if ($Detail) {
            #most likely the resource is 404
            $objProp = [ordered]@{
            ResponseURI = $uri
            ContentLength = $null
            ContentType = $null
            LastModified = $null
            Status = 404
            }
            #write a matching custom object to the pipeline
            New-Object -TypeName psobject -Property $objProp
    
            } #if $detail
        else {
            $False
        }
        } #close Catch block
    } #close Process block
    
    End {
        Write-Verbose -Message "Ending $($MyInvocation.Mycommand)"
    } #close end block
} #close Test-URI Function

function Install-OpenSSH{
    [CmdletBinding()]
    param(
        [ValidateScript({Test-URI $_})]
        [string]$OpenSSHUri = 'https://github.com/PowerShell/Win32-OpenSSH',
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_ -IsValid})]
        [string]$InstallPath = 'C:\Support\Install',
        [bool]$Confirm = $true #Forces re-install/overwrite. Cannot use [switch], status of [switch] cannot be changed during runtime
    )

    #Check to see if we are currently running "as Administrator"
    if ((Test-Administrator) -eq $false)
    {
        Write-Error -Message 'This function needs an elevated PowerShell session to work!'
        return
    }

    If (!(Test-path -Path $InstallPath)){New-Item -Path $InstallPath -ItemType Directory}

    $HTML = invoke-webrequest -Uri "$($OpenSSHUri)/releases/latest" -DisableKeepAlive
    $DownLoadTag = $HTML.ParsedHtml.getElementsByTagName('a') | Where href -like "*PowerShell/Win32-OpenSSH/releases/download*OpenSSH-Win64.zip"
    $DownloadHref = ($DownLoadTag.href) -replace 'about:/PowerShell/Win32-OpenSSH',''
    $OpenSSHFile = Split-Path $DownloadHref -Leaf
    $OpenSSHName = [System.IO.Path]::GetFileNameWithoutExtension($OpenSSHFile)

    #Get from environment, NOT from current session ($env:Path). The latter may result in unexpected behavior when this function is called twice
    $Path = ([Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)) -split ';'
    If (($Path -contains "C:\Program Files\$($OpenSSHName)") -and ($Confirm -eq $true)){
        if((yesno("OpenSHH seems installed, force overwrite?")) -eq 'Yes'){
            $Confirm = $false
        }
    }

    If (($Path -notcontains "C:\Program Files\$($OpenSSHName)") -or ($Confirm -eq $false)){
        invoke-webrequest -Uri "$($OpenSSHUri)/$($DownloadHref)" -OutFile "$($InstallPath)\$($OpenSSHFile)"

        Expand-Archive -Path "$($InstallPath)\$($OpenSSHFile)" -DestinationPath 'C:\Program Files' -Force

        #Add to Machine path if needed
        If ($Path -notcontains "C:\Program Files\$($OpenSSHName)"){
            #source: http://stackoverflow.com/questions/714877/setting-windows-powershell-path-variable
            [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\$($OpenSSHName)", [EnvironmentVariableTarget]::Machine)
        }
    }
}

function New-XMLTemplate{
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_ -IsValid})]
        [string]$Path = 'C:\Support\Scripts',
        [ValidateNotNullOrEmpty()]
        [string]$Name = 'pfSenseXMLTemplate.xml'
    )

    $XML = @'
<?xml version="1.0"?>
<pfsense>
	<version>15.5</version>
	<lastchange/>
	<system>
		<optimization>normal</optimization>
		<hostname>fw1</hostname>
		<domain>iton</domain>
		<dnsserver>213.136.12.52</dnsserver>
		<dnsserver>213.136.12.60</dnsserver>
		<group>
			<name>all</name>
			<description><![CDATA[All Users]]></description>
			<scope>system</scope>
			<gid>1998</gid>
			<member>0</member>
		</group>
		<group>
			<name>admins</name>
			<description><![CDATA[System Administrators]]></description>
			<scope>system</scope>
			<gid>1999</gid>
			<member>0</member>
			<priv>page-all</priv>
		</group>
		<user>
			<name>{adminUsername}</name>
			<descr><![CDATA[System Administrator]]></descr>
			<scope>system</scope>
			<groupname>admins</groupname>
			<bcrypt-hash>$2b$10$V7.s1lNl8XKf2TWVTQwLEuDihDjN5smrVAqYxrUI/smL9CiUPOO46</bcrypt-hash>
			<uid>0</uid>
			<priv>user-shell-access</priv>
		</user>
		<nextuid>2000</nextuid>
		<nextgid>2000</nextgid>
		<timeservers>0.pfsense.pool.ntp.org</timeservers>
		<webgui>
			<protocol>https</protocol>
			<loginautocomplete/>
			<ssl-certref>5874d45dcbf57</ssl-certref>
			<dashboardcolumns>2</dashboardcolumns>
			<port></port>
			<max_procs>2</max_procs>
		</webgui>
		<disablesegmentationoffloading/>
		<disablelargereceiveoffloading/>
		<powerd_ac_mode>hadp</powerd_ac_mode>
		<powerd_battery_mode>hadp</powerd_battery_mode>
		<powerd_normal_mode>hadp</powerd_normal_mode>
		<bogons>
			<interval>monthly</interval>
		</bogons>
		<timezone>Europe/Amsterdam</timezone>
		<maximumstates/>
		<aliasesresolveinterval/>
		<maximumtableentries/>
		<maximumfrags/>
		<enablenatreflectionpurenat>yes</enablenatreflectionpurenat>
		<enablebinatreflection>yes</enablebinatreflection>
		<enablenatreflectionhelper>yes</enablenatreflectionhelper>
		<reflectiontimeout/>
		<prefer_ipv4/>
		<serialspeed>115200</serialspeed>
		<primaryconsole>serial</primaryconsole>
		<enablesshd>enabled</enablesshd>
		<disableconsolemenu/>
	</system>
	<interfaces>
		<wan>
			<enable/>
			<if>hn0</if>
			<blockpriv/>
			<blockbogons/>
			<descr><![CDATA[WAN]]></descr>
			<ipaddr>{wanip}</ipaddr>
			<subnet>24</subnet>
			<gateway>GW_WAN</gateway>
			<spoofmac/>
		</wan>
		<lan>
			<enable/>
			<if>hn1</if>
			<ipaddr>{lanip}</ipaddr>
			<subnet>24</subnet>
			<ipaddrv6/>
			<subnetv6/>
			<media/>
			<mediaopt/>
			<track6-interface>wan</track6-interface>
			<track6-prefix-id>0</track6-prefix-id>
			<gateway/>
			<gatewayv6/>
		</lan>
	</interfaces>
	<staticroutes/>
	<dhcpd>
		<lan>
			<range>
				<from>{dhcpRangeFrom}</from>
				<to>{dhcpRangeTo}</to>
			</range>
			<failover_peerip/>
			<dhcpleaseinlocaltime/>
			<defaultleasetime/>
			<maxleasetime/>
			<netmask/>
			<gateway/>
			<domain/>
			<domainsearchlist/>
			<ddnsdomain/>
			<ddnsdomainprimary/>
			<ddnsdomainkeyname/>
			<ddnsdomainkey/>
			<mac_allow/>
			<mac_deny/>
			<tftp/>
			<ldap/>
			<nextserver/>
			<filename/>
			<filename32/>
			<filename64/>
			<rootpath/>
			<numberoptions/>
		</lan>
	</dhcpd>
	<dhcpdv6>
		<lan>
			<range>
				<from>::1000</from>
				<to>::2000</to>
			</range>
			<ramode>assist</ramode>
			<rapriority>medium</rapriority>
		</lan>
	</dhcpdv6>
	<snmpd>
		<syslocation/>
		<syscontact/>
		<rocommunity>public</rocommunity>
	</snmpd>
	<diag>
		<ipv6nat/>
	</diag>
	<syslog>
		<nologbogons/>
		<nologprivatenets/>
		<nologdefaultpass/>
	</syslog>
	<nat>
		<outbound>
			<mode>automatic</mode>
		</outbound>
		<separator/>
		<rule>
			<source>
				<any/>
			</source>
			<destination>
				<network>wanip</network>
				<port>80</port>
			</destination>
			<protocol>tcp</protocol>
			<target>{wapip}</target>
			<local-port>80</local-port>
			<interface>wan</interface>
			<descr/>
			<associated-rule-id>nat_5874f07711a291.40819308</associated-rule-id>
			<created>
				<time>1484058743</time>
				<username>{adminUsername}@{wapip}</username>
			</created>
			<updated>
				<time>1484126309</time>
				<username>{adminUsername}@{wapip}</username>
			</updated>
		</rule>
		<rule>
			<source>
				<any/>
			</source>
			<destination>
				<network>wanip</network>
				<port>443</port>
			</destination>
			<protocol>tcp</protocol>
			<target>{wapip}</target>
			<local-port>443</local-port>
			<interface>wan</interface>
			<descr/>
			<associated-rule-id/>
			<created>
				<time>1484124361</time>
				<username>{adminUsername}@{wapip}</username>
			</created>
			<updated>
				<time>1484126319</time>
				<username>{adminUsername}@{wapip}</username>
			</updated>
		</rule>
	</nat>
	<filter>
		<rule>
			<id/>
			<tracker>1484058743</tracker>
			<type>pass</type>
			<interface>wan</interface>
			<ipprotocol>inet</ipprotocol>
			<tag/>
			<tagged/>
			<max/>
			<max-src-nodes/>
			<max-src-conn/>
			<max-src-states/>
			<statetimeout/>
			<statetype>keep state</statetype>
			<os/>
			<protocol>tcp</protocol>
			<source>
				<any/>
			</source>
			<destination>
				<address>{wapip}</address>
				<port>80</port>
			</destination>
			<descr><![CDATA[NAT ]]></descr>
			<associated-rule-id>nat_5874f07711a291.40819308</associated-rule-id>
			<created>
				<time>1484058743</time>
				<username>NAT Port Forward</username>
			</created>
			<updated>
				<time>1484059710</time>
				<username>{adminUsername}@{wapip}</username>
			</updated>
		</rule>
		<rule>
			<id/>
			<tracker>1484125162</tracker>
			<type>pass</type>
			<interface>wan</interface>
			<ipprotocol>inet</ipprotocol>
			<tag/>
			<tagged/>
			<max/>
			<max-src-nodes/>
			<max-src-conn/>
			<max-src-states/>
			<statetimeout/>
			<statetype>keep state</statetype>
			<os/>
			<protocol>tcp</protocol>
			<source>
				<any/>
			</source>
			<destination>
				<address>{wapip}</address>
				<port>443</port>
			</destination>
			<descr><![CDATA[NAT ]]></descr>
			<created>
				<time>1484125162</time>
				<username>{adminUsername}@{wapip}</username>
			</created>
			<updated>
				<time>1484129951</time>
				<username>{adminUsername}@{wapip}</username>
			</updated>
		</rule>
		<rule>
			<id/>
			<tracker>1484130137</tracker>
			<type>block</type>
			<interface>wan</interface>
			<ipprotocol>inet46</ipprotocol>
			<tag/>
			<tagged/>
			<max/>
			<max-src-nodes/>
			<max-src-conn/>
			<max-src-states/>
			<statetimeout/>
			<statetype>keep state</statetype>
			<os/>
			<source>
				<any/>
			</source>
			<destination>
				<any/>
			</destination>
			<descr><![CDATA[Drop everything]]></descr>
			<created>
				<time>1484130137</time>
				<username>{adminUsername}@{wapip}</username>
			</created>
			<updated>
				<time>1484130547</time>
				<username>{adminUsername}@{wapip}</username>
			</updated>
		</rule>
		<rule>
			<id/>
			<tracker>0100000101</tracker>
			<type>pass</type>
			<interface>lan</interface>
			<ipprotocol>inet</ipprotocol>
			<tag/>
			<tagged/>
			<max/>
			<max-src-nodes/>
			<max-src-conn/>
			<max-src-states/>
			<statetimeout/>
			<statetype>keep state</statetype>
			<os/>
			<source>
				<any/>
			</source>
			<destination>
				<any/>
			</destination>
			<descr><![CDATA[Default allow LAN to any rule]]></descr>
			<updated>
				<time>1484127017</time>
				<username>{adminUsername}@{wapip}</username>
			</updated>
		</rule>
		<rule>
			<id/>
			<tracker>0100000102</tracker>
			<type>pass</type>
			<interface>lan</interface>
			<ipprotocol>inet6</ipprotocol>
			<tag/>
			<tagged/>
			<max/>
			<max-src-nodes/>
			<max-src-conn/>
			<max-src-states/>
			<statetimeout/>
			<statetype>keep state</statetype>
			<os/>
			<source>
				<any/>
			</source>
			<destination>
				<any/>
			</destination>
			<descr><![CDATA[Default allow LAN IPv6 to any rule]]></descr>
			<updated>
				<time>1484127027</time>
				<username>{adminUsername}@{wapip}</username>
			</updated>
		</rule>
		<separator>
			<wan/>
			<lan/>
		</separator>
	</filter>
	<shaper/>
	<ipsec/>
	<aliases/>
	<proxyarp/>
	<cron>
		<item>
			<minute>1,31</minute>
			<hour>0-5</hour>
			<mday>*</mday>
			<month>*</month>
			<wday>*</wday>
			<who>root</who>
			<command>/usr/bin/nice -n20 adjkerntz -a</command>
		</item>
		<item>
			<minute>1</minute>
			<hour>3</hour>
			<mday>1</mday>
			<month>*</month>
			<wday>*</wday>
			<who>root</who>
			<command>/usr/bin/nice -n20 /etc/rc.update_bogons.sh</command>
		</item>
		<item>
			<minute>*/60</minute>
			<hour>*</hour>
			<mday>*</mday>
			<month>*</month>
			<wday>*</wday>
			<who>root</who>
			<command>/usr/bin/nice -n20 /usr/local/sbin/expiretable -v -t 3600 sshlockout</command>
		</item>
		<item>
			<minute>*/60</minute>
			<hour>*</hour>
			<mday>*</mday>
			<month>*</month>
			<wday>*</wday>
			<who>root</who>
			<command>/usr/bin/nice -n20 /usr/local/sbin/expiretable -v -t 3600 webConfiguratorlockout</command>
		</item>
		<item>
			<minute>1</minute>
			<hour>1</hour>
			<mday>*</mday>
			<month>*</month>
			<wday>*</wday>
			<who>root</who>
			<command>/usr/bin/nice -n20 /etc/rc.dyndns.update</command>
		</item>
		<item>
			<minute>*/60</minute>
			<hour>*</hour>
			<mday>*</mday>
			<month>*</month>
			<wday>*</wday>
			<who>root</who>
			<command>/usr/bin/nice -n20 /usr/local/sbin/expiretable -v -t 3600 virusprot</command>
		</item>
		<item>
			<minute>30</minute>
			<hour>12</hour>
			<mday>*</mday>
			<month>*</month>
			<wday>*</wday>
			<who>root</who>
			<command>/usr/bin/nice -n20 /etc/rc.update_urltables</command>
		</item>
	</cron>
	<wol/>
	<rrd>
		<enable/>
		<category>left=system-processor&amp;right=&amp;resolution=300&amp;timePeriod=-1d&amp;startDate=&amp;endDate=&amp;startTime=0&amp;endTime=0&amp;graphtype=line&amp;invert=true</category>
	</rrd>
	<load_balancer>
		<monitor_type>
			<name>ICMP</name>
			<type>icmp</type>
			<descr><![CDATA[ICMP]]></descr>
			<options/>
		</monitor_type>
		<monitor_type>
			<name>TCP</name>
			<type>tcp</type>
			<descr><![CDATA[Generic TCP]]></descr>
			<options/>
		</monitor_type>
		<monitor_type>
			<name>HTTP</name>
			<type>http</type>
			<descr><![CDATA[Generic HTTP]]></descr>
			<options>
				<path>/</path>
				<host/>
				<code>200</code>
			</options>
		</monitor_type>
		<monitor_type>
			<name>HTTPS</name>
			<type>https</type>
			<descr><![CDATA[Generic HTTPS]]></descr>
			<options>
				<path>/</path>
				<host/>
				<code>200</code>
			</options>
		</monitor_type>
		<monitor_type>
			<name>SMTP</name>
			<type>send</type>
			<descr><![CDATA[Generic SMTP]]></descr>
			<options>
				<send/>
				<expect>220 *</expect>
			</options>
		</monitor_type>
	</load_balancer>
	<widgets>
		<sequence>system_information:col1:show,interfaces:col2:show,snort_alerts:col2:open</sequence>
	</widgets>
	<openvpn/>
	<dnshaper/>
	<unbound>
		<dnssec/>
		<active_interface>all</active_interface>
		<outgoing_interface>all</outgoing_interface>
		<custom_options/>
		<hideidentity/>
		<hideversion/>
		<dnssecstripped/>
		<port/>
		<system_domain_local_zone_type>transparent</system_domain_local_zone_type>
	</unbound>
	<revision>
		<time>1484137977</time>
		<description><![CDATA[admin@{wapip}: /system_advanced_admin.php made unknown change]]></description>
		<username>{adminUsername}@{wapip}</username>
	</revision>
	<cert>
		<refid>5874d45dcbf57</refid>
		<descr><![CDATA[webConfigurator default (5874d45dcbf57)]]></descr>
		<type>server</type>
		<crt>LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZiVENDQkZXZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBRENCdERFTE1Ba0dBMVVFQmhNQ1ZWTXgKRGpBTUJnTlZCQWdUQlZOMFlYUmxNUkV3RHdZRFZRUUhFd2hNYjJOaGJHbDBlVEU0TURZR0ExVUVDaE12Y0daVApaVzV6WlNCM1pXSkRiMjVtYVdkMWNtRjBiM0lnVTJWc1ppMVRhV2R1WldRZ1EyVnlkR2xtYVdOaGRHVXhLREFtCkJna3Foa2lHOXcwQkNRRVdHV0ZrYldsdVFIQm1VMlZ1YzJVdWJHOWpZV3hrYjIxaGFXNHhIakFjQmdOVkJBTVQKRlhCbVUyVnVjMlV0TlRnM05HUTBOV1JqWW1ZMU56QWVGdzB4TnpBeE1UQXhNak15TWpsYUZ3MHlNakEzTURNeApNak15TWpsYU1JRzBNUXN3Q1FZRFZRUUdFd0pWVXpFT01Bd0dBMVVFQ0JNRlUzUmhkR1V4RVRBUEJnTlZCQWNUCkNFeHZZMkZzYVhSNU1UZ3dOZ1lEVlFRS0V5OXdabE5sYm5ObElIZGxZa052Ym1acFozVnlZWFJ2Y2lCVFpXeG0KTFZOcFoyNWxaQ0JEWlhKMGFXWnBZMkYwWlRFb01DWUdDU3FHU0liM0RRRUpBUllaWVdSdGFXNUFjR1pUWlc1egpaUzVzYjJOaGJHUnZiV0ZwYmpFZU1Cd0dBMVVFQXhNVmNHWlRaVzV6WlMwMU9EYzBaRFExWkdOaVpqVTNNSUlCCklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFzMjRvQ0RxTzBXdnJ0NHBJWTRvakRaZ1YKbFVhTHVwWEFGM0FndDRmUzY4ZitmTkVaRFBDVnRTOEQzUnFiUTF2SzVodnQ1Z3dHM1VFcVN6dGZoNVFPUWlNUwpNVzNWcit5VStTWXU5Wmp5RERwV3dSdVNSeVpjUE8rRUc3a1BlZVAzRkFET0FWT2gyeHoxZmNRZzNvZFZCZTdoCjhvT0NLWFNGZUtiZ1FHajVzU010MmdXbjIxOGs0Zi82NzJzd3hpVHZjdmIrZ0FoYUhiRVNWQTdremd4RWpSVHYKdTgrUXJ1d2ZYUERPNmxuSHRqSTRUbEozZEE5dVRPVWxaYUFRQVhINWlaL3Z6MWxza0Z3Qm5ZcVNya1BSYktSRwo2Um5HNmt2VEN0OFJRUHBzK3lqVGhqY1RySGtSdEY2NjNVcDV6LzdTL3J0blhra0tYc0N0aDJQMWJjcmh5d0lECkFRQUJvNElCaGpDQ0FZSXdDUVlEVlIwVEJBSXdBREFSQmdsZ2hrZ0JodmhDQVFFRUJBTUNCa0F3TXdZSllJWkkKQVliNFFnRU5CQ1lXSkU5d1pXNVRVMHdnUjJWdVpYSmhkR1ZrSUZObGNuWmxjaUJEWlhKMGFXWnBZMkYwWlRBZApCZ05WSFE0RUZnUVUvMi9ZVFNFMVlGYkp0NGRSQlEvbm9uWnFFQzh3Z2VFR0ExVWRJd1NCMlRDQjFvQVUvMi9ZClRTRTFZRmJKdDRkUkJRL25vblpxRUMraGdicWtnYmN3Z2JReEN6QUpCZ05WQkFZVEFsVlRNUTR3REFZRFZRUUkKRXdWVGRHRjBaVEVSTUE4R0ExVUVCeE1JVEc5allXeHBkSGt4T0RBMkJnTlZCQW9UTDNCbVUyVnVjMlVnZDJWaQpRMjl1Wm1sbmRYSmhkRzl5SUZObGJHWXRVMmxuYm1Wa0lFTmxjblJwWm1sallYUmxNU2d3SmdZSktvWklodmNOCkFRa0JGaGxoWkcxcGJrQndabE5sYm5ObExteHZZMkZzWkc5dFlXbHVNUjR3SEFZRFZRUURFeFZ3WmxObGJuTmwKTFRVNE56UmtORFZrWTJKbU5UZUNBUUF3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQ0FJQwpNQXNHQTFVZER3UUVBd0lGb0RBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQXNkTmpqWVdaMm9nbVJKRGdRbWRBClI2Tkg0cWJicVpZMmt2aTNkY3d2eWRJaCtDbFNTVFlJUy9PMFVteTFVbElMUkpEUlFaYkZEMjNnZGVVQ1ZaZS8KY2NXSitlNzBwVEExQXhGR1BhcE1oQjVBMXNEVzlFc2IrR0k5Wk9MczA0dVl0N2tNTU9ZMXZ1aTNQb05HRUo1Mwp5dmttYVE5WnJKOWVSY3JBV01lU1pkQU95eE81QVlmK2VvOUlXM3JKOXVlUldhWDdMMG0vTGd1eHp4b0xEVng1CmhKb25SVWxSZFN0TzlPS0ljOFFrTkpZcW1sMEs1cG9IRDJ0RFE0YzA1MnlVUDRBa2JhL2dIeXJwTEtGck1zeCsKM1BYLzNXbEVRRlRQSUwwQWdDYTUzQjJqNkhKSHdXNVZtTlNieHJhaTZ6NFVhSjZ0blFucmhrTEg0Y0NucVhtTgpTZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K</crt>
		<prv>LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQ3piaWdJT283UmErdTMKaWtoamlpTU5tQldWUm91NmxjQVhjQ0MzaDlMcngvNTgwUmtNOEpXMUx3UGRHcHREVzhybUcrM21EQWJkUVNwTApPMStIbEE1Q0l4SXhiZFd2N0pUNUppNzFtUElNT2xiQkc1SkhKbHc4NzRRYnVROTU0L2NVQU00QlU2SGJIUFY5CnhDRGVoMVVGN3VIeWc0SXBkSVY0cHVCQWFQbXhJeTNhQmFmYlh5VGgvL3J2YXpER0pPOXk5djZBQ0ZvZHNSSlUKRHVUT0RFU05GTys3ejVDdTdCOWM4TTdxV2NlMk1qaE9VbmQwRDI1TTVTVmxvQkFCY2ZtSm4rL1BXV3lRWEFHZAppcEt1UTlGc3BFYnBHY2JxUzlNSzN4RkErbXo3S05PR054T3NlUkcwWHJyZFNublAvdEwrdTJkZVNRcGV3SzJIClkvVnR5dUhMQWdNQkFBRUNnZ0VBWmpON1o5eDYxcnhDNGlOSXdqRy9iNUhOMFY0Q1hyL0hUMUpWd0ZRRUJycSsKc0xlbExpS25FekY1WU9venY3VThKNytHelA3U3RoblZEazcrUmNwR0tOT3pIQ1owamFVUzRhc25Ha3NJcTRCYgpROWtCZzdkTTJJU1EyZjJaM0JMRi9FWE5FU0ppMGR4MzFDL3ZqUERHcy85eUFXRjR0VVlpZEN1UkZmNzFJamh6CkhHTkNvY1R1Qzh6UXlQdWVQTXRtbTRQdzhUWFE3ak9LM2U1VVdrejdRbUF4c3g3bzYweTE1V2ljUmNqN0hrUFEKNU9TYnU0amdDNlhsYlowMkg1dU9oYVh0U2lYc05vc0R2MW9tcVE1clROZHk1TXFNSWhUanVoaUJlRTcvMldkMgo4a2RGL20yZkNXbXVIV2VmUGxVSGNZVnJHZlhQczlZWmlZaEMrNzVMU1FLQmdRRHN0RklhZm1hRW54aWcwQkJyCnd3Nml0NEpFM2YwSHRWVm5STk1MMVBDRE9ZaElFSzFBaERXdXVnZGJ4aWgwRlRTcE8wTkZQcjEyVzEvdWVBQ0YKQXViTXRvdVNOOTZoT2czbnJlYnNKQWY3Rmhwc010U25VWXdDM2s1Vmt0YWQ0c3UrZ2JEQ2lNL04vUmsrd29LYQordjY0Y1N2S2NkYWh1aXFoWW5qeCtPUW1MUUtCZ1FEQ0RwdXZ1bVNlaHpQdi8wdzhjTE0wNVFabnVrTGlTei92CktaWmwyRE9rOTJIcWIycnp3VEx1U1dZTUI1RGZSTDZwNUJlK1lqSENlYkVuSVlHSXp0Q0pEL21YdGxVQzdLU3MKaDJSMkh4cjI5MkVqL01mQ3hTay9taHNLUjhTcExNT0pqSzVCZHM4NkZJeFdYeVI1d05ETW1GSnhXSDZNdEZIUQpzNzRxZUs5YTF3S0JnUUN0NUdNVTE1dFUvdFJHLzlPd2R5SC9aRFV0aHEvbXc4NjBDUm5LYldzcjNFNUVNd3cwCmcydzBxckhST0NocjcxQTZxekRtWkFzb01rU3RtamMzZ0VReVRFRUk4RVo3eDN5RG9Yd3VLdUk2RWFqanFBd1YKeDVER1lxN0ZxeFJEOVdPYzF3WVdSQS8xMG1TRGVMNGVRUnAwUVovY0gvbC80cGFDN1NiUkRQbi9HUUtCZ0NwcgpjeERvMTlIbmtDem9TOHZ5ZnRvVExtRkNVQmlUaG5oTFNQc2VWYnU3OEFXRk1ZWHpONlRyR29tS3BkcUlkbjFBCnhRZnpBeG1WN0dtM1kwOTZsZzlBRkxsYlBCNFZpTEhHTHVtN1J2T3hnK1NQLzBMT1FvUUt0ZHA3Y2J2aGN5VUEKUVo5QnoyN015eGllVjZUZHgwYlNEVU9GcXJRclBxODJlMTFoWUVPbEFvR0FaVVdyVU81SDV1bUFtNEswckdtMgpnNE00SnhFZFVtek9NYW5ZZ0VzVHYxbnU0VGVFV0hPU2JLN2dkZG9CblB0VzlFZ3g2RFlWRXYwakxSUFR3N0NHCkdMUE9yL3hPQktVUzc1QU1ldlpMTVBBWXh4YjJpUWY3S3lSN0ZDNkNCMGZiaDZrVE9aZWNubnZjTythcWN5OGoKeWd6UmxnZVhHZjIyWHI1aWFNTFpsaUU9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K</prv>
	</cert>
	<gateways>
		<gateway_item>
			<interface>wan</interface>
			<gateway>{wangateway}</gateway>
			<name>GW_WAN</name>
			<weight>1</weight>
			<ipprotocol>inet</ipprotocol>
			<interval/>
			<descr><![CDATA[Interface wan Gateway]]></descr>
			<defaultgw/>
		</gateway_item>
	</gateways>
	<ppps/>
	<installedpackages>
		<package>
			<name>snort</name>
			<pkginfolink>https://doc.pfsense.org/index.php/Setup_Snort_Package</pkginfolink>
			<website>http://www.snort.org</website>
			<descr><![CDATA[Snort is an open source network intrusion prevention and detection system (IDS/IPS). Combining the benefits of signature, protocol, and anomaly-based inspection.]]></descr>
			<version>3.2.9.2_15</version>
			<configurationfile>/snort.xml</configurationfile>
			<after_install_info>Please visit Services - Snort - Interfaces tab first and select your desired rules. Afterwards visit the Updates tab to download your configured rulesets.</after_install_info>
		</package>
		<package>
			<name>squid3</name>
			<internal_name>squid</internal_name>
			<descr><![CDATA[High performance web proxy cache (3.4 branch). It combines Squid as a proxy server with its capabilities of acting as a HTTP / HTTPS reverse proxy.&lt;br /&gt;
			It includes an Exchange-Web-Access (OWA) Assistant, SSL filtering and antivirus integration via C-ICAP.]]></descr>
			<pkginfolink>https://forum.pfsense.org/index.php?board=60.0</pkginfolink>
			<website>http://www.squid-cache.org/</website>
			<version>0.4.31_1</version>
			<configurationfile>squid.xml</configurationfile>
			<filter_rule_function>squid_generate_rules</filter_rule_function>
		</package>
		<snortglobal>
			<snort_config_ver>3.2.9.2_15</snort_config_ver>
		</snortglobal>
		<menu>
			<name>Snort</name>
			<tooltiptext>Set up snort specific settings</tooltiptext>
			<section>Services</section>
			<url>/snort/snort_interfaces.php</url>
		</menu>
		<menu>
			<name>Squid Proxy Server</name>
			<tooltiptext>Modify the proxy server settings</tooltiptext>
			<section>Services</section>
			<url>/pkg_edit.php?xml=squid.xml&amp;id=0</url>
		</menu>
		<menu>
			<name>Squid Reverse Proxy</name>
			<tooltiptext>Modify the reverse proxy server settings</tooltiptext>
			<section>Services</section>
			<url>/pkg_edit.php?xml=squid_reverse_general.xml&amp;id=0</url>
		</menu>
		<service>
			<name>snort</name>
			<rcfile>snort.sh</rcfile>
			<executable>snort</executable>
			<description><![CDATA[Snort IDS/IPS Daemon]]></description>
		</service>
		<service>
			<name>squid</name>
			<rcfile>squid.sh</rcfile>
			<executable>squid</executable>
			<description><![CDATA[Squid Proxy Server Service]]></description>
		</service>
		<service>
			<name>clamd</name>
			<rcfile>clamd.sh</rcfile>
			<executable>clamd</executable>
			<description><![CDATA[ClamAV Antivirus]]></description>
		</service>
		<service>
			<name>c-icap</name>
			<rcfile>c-icap.sh</rcfile>
			<executable>c-icap</executable>
			<description><![CDATA[ICAP Inteface for Squid and ClamAV integration]]></description>
		</service>
		<squidcache/>
		<squidremote/>
		<squidauth>
			<config>
				<auth_method>none</auth_method>
			</config>
		</squidauth>
	</installedpackages>
</pfsense>
'@
    If (!(Test-path -Path $Path)){New-Item -Path $Path -ItemType Directory}
    Out-File -FilePath "$($Path)\$($Name)" -InputObject $XML
}