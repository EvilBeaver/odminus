
[CmdletBinding()]
Param (
    [parameter(Mandatory = $True, ValueFromPipeline = $true , Position = 1)] [string] $Uri
)

function Get-WmiObjectEx {

    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $True, ValueFromPipeline = $true , Position = 1)] [string] $Class,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 2)] [string] $Namespace = 'root\cimv2',
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 3)] [string] $Timeout = '0:1:0'
    )

    Invoke-WmiQuery -Query "SELECT * FROM $Class" -Timeout $Timeout -Namespace $Namespace  
}

function Invoke-WmiQuery {

    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $True, ValueFromPipeline = $true , Position = 1)] [string] $Query,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 2)] [string] $Namespace = 'root\cimv2',
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 3)] [string] $Timeout = '0:1:0'
    )

    $wmiquery = New-Object System.Management.ManagementObjectSearcher $Namespace, $Query
    $wmiquery.psbase.Options.Timeout = $Timeout
    $wmiquery.Get()      
}

function Get-OSData {
	
    $OSData = New-Object PSObject
	
    try {
        $wmiObject = Get-WmiObjectEx Win32_OperatingSystem -Timeout $WmiTimeout
        $OSData | Add-Member NoteProperty -Name "BuildNumber"						-Value $wmiObject.BuildNumber
        $OSData | Add-Member NoteProperty -Name "Caption" 							-Value $wmiObject.Caption
        $OSData | Add-Member NoteProperty -Name "CountryCode" 						-Value $wmiObject.CountryCode
        $OSData | Add-Member NoteProperty -Name "CSName" 							-Value $wmiObject.CSName
        $OSData | Add-Member NoteProperty -Name "CurrentTimeZone" 					-Value $wmiObject.CurrentTimeZone
        $OSData | Add-Member NoteProperty -Name "Debug" 							-Value $wmiObject.Debug
        $OSData | Add-Member NoteProperty -Name "InstallDate" 						-Value $wmiObject.InstallDate
        $OSData | Add-Member NoteProperty -Name "LastBootUpTime" 					-Value $wmiObject.LastBootUpTime
        $OSData | Add-Member NoteProperty -Name "OSArchitecture" 					-Value $wmiObject.OSArchitecture
        $OSData | Add-Member NoteProperty -Name "OSLanguage" 						-Value $wmiObject.OSLanguage
        $OSData | Add-Member NoteProperty -Name "SerialNumber" 						-Value $wmiObject.SerialNumber
        $OSData | Add-Member NoteProperty -Name "TotalVirtualMemorySize" 			-Value $wmiObject.TotalVirtualMemorySize
        $OSData | Add-Member NoteProperty -Name "TotalVisibleMemorySize" 			-Value $wmiObject.TotalVisibleMemorySize
        $OSData | Add-Member NoteProperty -Name "Version" 							-Value $wmiObject.Version
    }
    catch {
        Write-Host; Write-Warning ("Error: (Get-OSData) get OS info: {0}" -f $_.Exception.Message)
    }
	
    $OSData
	
}

function Get-CPUData {
	
    $CPUData = @()
	
    try {
        $wmiObject = Get-WmiObjectEx Win32_Processor -Timeout $WmiTimeout

        foreach ($CPU in $wmiObject) {
			
            $CPUElement = New-Object PSObject

            $CPUElement | Add-Member NoteProperty -Name "AddressWidth" 					-Value $CPU.AddressWidth
            $CPUElement | Add-Member NoteProperty -Name "Caption" 						-Value $CPU.Caption
            $CPUElement | Add-Member NoteProperty -Name "CurrentClockSpeed" 			-Value $CPU.CurrentClockSpeed
            $CPUElement | Add-Member NoteProperty -Name "DataWidth" 					-Value $CPU.DataWidth
            $CPUElement | Add-Member NoteProperty -Name "DeviceID" 						-Value $CPU.DeviceID
            $CPUElement | Add-Member NoteProperty -Name "L2CacheSize" 					-Value $CPU.L2CacheSize
            $CPUElement | Add-Member NoteProperty -Name "L3CacheSize" 					-Value $CPU.L3CacheSize
            $CPUElement | Add-Member NoteProperty -Name "Manufacturer" 					-Value $CPU.Manufacturer
            $CPUElement | Add-Member NoteProperty -Name "MaxClockSpeed" 				-Value $CPU.MaxClockSpeed
            $CPUElement | Add-Member NoteProperty -Name "Name" 							-Value $CPU.Name
            $CPUElement | Add-Member NoteProperty -Name "NumberOfCores" 				-Value $CPU.NumberOfCores
            $CPUElement | Add-Member NoteProperty -Name "NumberOfEnabledCore" 			-Value $CPU.NumberOfEnabledCore
            $CPUElement | Add-Member NoteProperty -Name "NumberOfLogicalProcessors"		-Value $CPU.NumberOfLogicalProcessors
			
            $CPUData += $CPUElement

        }
    }
    catch {
        Write-Host; Write-Warning ("Error: (Get-ServerData) get server info: {0}" -f $_.Exception.Message)
    }
	
    $CPUData
	
}

function Get-ComputerSystem {
	
    $ComputerSystem = New-Object PSObject
	
    try {
        $wmiObject = Get-WmiObjectEx Win32_ComputerSystem -Timeout $WmiTimeout
        $ComputerSystem | Add-Member NoteProperty -Name "Model"                     -Value $wmiObject.Model
        $ComputerSystem | Add-Member NoteProperty -Name "Manufacturer"              -Value $wmiObject.Manufacturer
        $ComputerSystem | Add-Member NoteProperty -Name "NumberOfProcessors"        -Value $wmiObject.NumberOfProcessors
        $ComputerSystem | Add-Member NoteProperty -Name "TotalPhysicalMemory"       -Value $wmiObject.TotalPhysicalMemory
        $ComputerSystem | Add-Member NoteProperty -Name "Hostname"                  -Value $wmiObject.DnsHostName
        $ComputerSystem | Add-Member NoteProperty -Name "Domain"                    -Value $wmiObject.Domain

    }
    catch {
        Write-Host; Write-Warning ("Error: (Get-ComputerSystem) get computer system info: {0}" -f $_.Exception.Message)
    }
	
    $ComputerSystem
}

function Get-Permission1CConf {
	
    $Permission = New-Object PSObject
    $PathX86 = "C:\Program Files (x86)\1cv8\conf\"
    $PathX64 = "C:\Program Files\1cv8\conf\"
	
    $UseX86 = Test-Path $PathX86
    $UseX64 = Test-Path $PathX64
		
    $Permission | Add-Member NoteProperty -Name "x86PlatformUse"					-Value $UseX86
    $TestX86FilePath = $PathX86 + "testfile.conf"
    try {
        $Item = New-Item -Path $TestX86FilePath -ItemType "file" -ea stop
        Remove-Item $TestX86FilePath
        $Permission | Add-Member NoteProperty -Name "x86PlatformWritePermission"	-Value $True		
    }
    catch {
        $Permission | Add-Member NoteProperty -Name "x86PlatformWritePermission"	-Value $False
    }
	
	
    $Permission | Add-Member NoteProperty -Name "x64PlatformUse"					-Value $UseX64
    $TestX64FilePath = $PathX64 + "testfile.conf"
    try {
        $Item = New-Item -Path $TestX64FilePath -ItemType "file" -ea stop
        Remove-Item $TestX64FilePath
        $Permission | Add-Member NoteProperty -Name "x64PlatformWritePermission"	-Value $True
		
    }
    catch {
        $Permission | Add-Member NoteProperty -Name "x64PlatformWritePermission"	-Value $False
    }
	
    $Permission
}

function Get-PowerPlanData {
	
    $PowerPlanData = $null
	
    try {
        $ppresult = $true
        $wmiObject = Get-WmiObjectEx -Class win32_powerplan -Namespace root\cimv2\power -Timeout $WmiTimeout | ? {$_.isActive }
        $PowerPlanData = $wmiObject.ElementName
		
    } 
    catch {
        $ppresult = $false
        Write-Host; Write-Warning ("Ошибка (Get-PowerPlanData) при получении информации о режиме энергопотребления: {0}" -f $_.Exception.Message)        
    }

    if (-Not $ppresult) {    
        try {
            Write-Host; Write-Warning "Попытка использовать обходное решение для получения информации о режиме энергопотребления"

            powercfg -list | ? {$_ -match ".*\((.*)\) \*"} | Out-Null
            $PowerPlanData = $Matches[1]
            $ppresult = $true
        } 
        catch {$ppresult = $false}
    }

    if (-Not $ppresult) {
        Write-Host; Write-Warning ("Не удалось получить информацию о режиме энергопотребления: {0}" -f $_.Exception.Message)
    }
	
    $PowerPlanData
	
}

function Get-Pagefile {
	
    $PageFiles = @()
	
    try {
        $wmiObject = Get-WmiObjectEx Win32_PageFileUsage -Timeout $WmiTimeout
		
        foreach ($PageFileWMI in $wmiObject) {
            $PageFile = New-Object PSObject
            $PageFile | Add-Member NoteProperty -Name "Name" 					-Value $PageFileWMI.Name	
            $PageFile | Add-Member NoteProperty -Name "PeakUsage" 				-Value $PageFileWMI.PeakUsage
            $PageFile | Add-Member NoteProperty -Name "AllocatedBaseSize" 		-Value $PageFileWMI.AllocatedBaseSize
			
            $PageFiles += $PageFile

        }
    }
    catch { Write-Host; Write-Warning ("Ошибка (Get-Pagefile) при получении информации об конфигурации файлов подкачки: {0}" -f $_.Exception.Message) }
	
    $PageFiles
}

function Get-ServerData {
	
    $ServerData = New-Object PSObject -Property @{
        OSData         = Get-OSData
        CPUData        = Get-CPUData
        ComputerSystem = Get-ComputerSystem
        Write1CConf    = Get-Permission1CConf
        PowerPlan      = Get-PowerPlanData
        Pagefile       = Get-Pagefile
        Counters       = Get-Counters
    } 
	
    $ServerData
	
}

function Get-Counters {
	
    $ResultCounters = @()
	
    $DataCollectorList = logman | where {$_ -ne "" -and $_ -notlike "*---*" -and $_ -notlike "*Тип*Состояние*" -and $_ -notlike "*Type*Status*" -and $_ -notlike "Команда*" -and $_ -notlike "The command*" -and ($_ -like "*Счетчик*" -or $_ -like "*Counter*")}
	
    if ($DataCollectorList -eq $null) {
        return
    }
	
    $DataCollectorList = $DataCollectorList.Replace($DataCollectorList, $DataCollectorList + ";") 
    $DataCollectorList = $DataCollectorList.Replace("Счетчик", ",").Replace("Counter", ",")
    $DataCollectorList = $DataCollectorList.Replace(" ", "")
    $option = [System.StringSplitOptions]::RemoveEmptyEntries
    $DataCollectorList = $DataCollectorList.Split(";", $option)

    for ($i = 0; $i -ne $DataCollectorList.Length; $i += 1) {
        $ResultCounters += $DataCollectorList[$i].Remove($DataCollectorList[$i].IndexOf(","))
    }
    $ResultCounters
}

function Get-1C_Services {

    $Services1C = @()

    try {
        $svc1cApp = Invoke-WmiQuery 'SELECT * FROM win32_service WHERE PathName LIKE "%ragent.exe%"' -Timeout $WmiTimeout
		
        if (-Not $svc1cApp) {
            Return
        }
         
        foreach ($curSvc in $svc1cApp) {
            $svc1c = New-Object PSObject
            $svc1c | Add-Member -type NoteProperty -name 'Name'         -value $curSvc.Name
            $svc1c | Add-Member -type NoteProperty -name 'DisplayName'  -value $curSvc.DisplayName
            $svc1c | Add-Member -type NoteProperty -name 'State'  		-value $curSvc.State

            if ($curSvc.PathName -match "-regport[ ]+(\d+)") {
                $svc1c | Add-Member -type NoteProperty -name 'RegPort' -value $Matches[1]
            }
            
            if ($curSvc.PathName -match "-range[ ]+([:\d]+)") {
                $svc1c | Add-Member -type NoteProperty -name 'PortRange' -value $Matches[1]
            }
            
            if ($curSvc.PathName -match "\\(\d+\.\d+\.\d+\.\d+)\\") {
                $svc1c | Add-Member -type NoteProperty -name 'Version' -value $Matches[1]
            }

            if ($curSvc.PathName -match '-d[ ]+([ a-zA-Z0-9\(\)\.-_:\\\"]+)') {
                $svc1c | Add-Member -type NoteProperty -name 'Path' -value ($Matches[1] -replace '"', '')
            }

            if ($curSvc.PathName -match '-debug' -Or $curSvc.PathName -match '-http') {
                $svc1c | Add-Member -type NoteProperty -name 'Debug' -value $True
            }
            else {
                $svc1c | Add-Member -type NoteProperty -name 'Debug' -value $False
            }
			
            if ($svc1c.Version -match "8\.3") { 
                $svc1c | Add-Member -type NoteProperty -name 'Clusters' -value (Get-1С_Cluster -Path $svc1c.Path)
            }

            $Services1C += $svc1c    
        }
    }  
    catch { 
        Write-Host; Write-Warning ("Ошибка (Get-1C_Services): {0}" -f $_.Exception.Message) 
    }
	
    $Services1C
}

function Get-1С_Cluster {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 1)] [string] $Path
    )
	
    $ClusterArray = @()

    try {
        $confFileList = Get-ChildItem -Path $Path -Filter "1CV8Clst.lst" -Recurse

        if (-Not $confFileList) {
            Return
        }

        foreach ($curConfFile in $confFileList) {
            $confFile = [system.io.file]::ReadAllText($curConfFile.FullName) 
            $confFile = $confFile -Replace ('\r\n', '')
            #REGEX {ebba5eeb-9246-44dc-9557-e8c66cf673db,"Local cluster",1541,"Msc-stl-tst-03v",0,0,888999,888555,888888,888777,888444,{1,{"Msc-stl-tst-03v",1541}},0,99,1},
            $pattern = '{[\d\w\-]+,"(?<Name>.*)",(?<Port>\d+),"(?<HostName>.*)",\d+,\d+,(?<RestartInterval>\d+),(?<DisabledProcessesAfter>\d+),(?<AllowedMemory>\d+),(?<ExceedingInterval>\d+),(?<FailOverLevel>\d+),{\d+,{.*}},(?<PerformanceMode>\d+)'
            if ($confFile -match $pattern) {
                $cluster1cConf = New-Object PSObject -Property @{
                    Name                   = $Matches["Name"]
                    Port                   = $Matches["Port"]
                    HostName               = $Matches["HostName"]
                    RestartInterval        = $Matches["RestartInterval"]
                    DisabledProcessesAfter = $Matches["DisabledProcessesAfter"] 
                    AllowedMemory          = $Matches["AllowedMemory"] 
                    PerformanceMode        = $Matches["PerformanceMode"]
                    ExceedingInterval      = $Matches["ExceedingInterval"]
                    FailOverLevel          = $Matches["FailOverLevel"]
                    ConfFileName           = $curConfFile.FullName
                    WorkingServers         = Get-1C_Servers83 -Path $curConfFile.FullName
                    BaseList               = Get-1C_ClusterBase -Path $curConfFile.FullName
                }
            } 
            $ClusterArray += $cluster1cConf
        }                   
    }
    catch { 
        Write-Host; Write-Warning ("Ошибка (Get-1С_Cluster): {0}" -f $_.Exception.Message) 
    }  
	
    $ClusterArray
}

function Get-1C_Servers83 {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 1)] [string] $Path
    )
	
    $ServerList = @()

    try {
        $confFile = [system.io.file]::ReadAllText($Path)
        $confFile = $confFile -Replace ('\r\n', '')

        #{fa390406-bf41-40d9-9fbf-d07fe4af1f04,"Центральный сервер",1540,"R891CDB01",1,{1,{1560,1591}},"","Va4tyK3wJKhM1bvyBzCtkA==",0,0,8,128,1000,1,0,1,0,1,1541}
        $pattern = '{[\w\d-]+?,"(?<ServRole>[\w\d ]+?)",\d+,"(?<ServName>[\w\d\-]+?)",\d+,{\d+,{\d+,\d+}},".*?",".*?",(?<ServMaxMemory>\d+),(?<ServSafeMemory>-?\d+),(?<ServIBPerConn>\d+),(?<ServConnPerProcc>\d+),\d+,\d+,\d+,\d+,(?<ServProcMemory>\d+),\d+,\d+}'
		
        $AllMatches = [regex]::matches($confFile, $pattern)
        foreach ($FindingString in $AllMatches) {
			
            if ($FindingString -match $pattern) {
                $workSrv1C = New-Object PSObject -Property @{
                    ServRole         = $Matches["ServRole"]
                    ServName         = $Matches["ServName"]
                    ServMaxMemory    = $Matches["ServMaxMemory"]
                    ServSafeMemory   = $Matches["ServSafeMemory"]
                    ServProcMemory   = $Matches["ServProcMemory"]
                    ServIBPerConn    = $Matches["ServIBPerConn"]
                    ServConnPerProcc = $Matches["ServConnPerProcc"]
                }
					
                $ServerList += $workSrv1C
            }
        }
    }
    catch { 
        Write-Host; Write-Warning ("Ошибка (Get-1C_Servers83): {0}" -f $_.Exception.Message) 
    }  

    $ServerList
}

function Get-1C_ClusterBase {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 1)] [string] $Path
    )
	
    $BaseList = @()

    try {
        $confFile = [system.io.file]::ReadAllText($Path)
        $confFile = $confFile -Replace ('\r\n', '')

        #{fa390406-bf41-40d9-9fbf-d07fe4af1f04,"Центральный сервер",1540,"R891CDB01",1,{1,{1560,1591}},"","Va4tyK3wJKhM1bvyBzCtkA==",0,0,8,128,1000,1,0,1,0,1,1541}
        $pattern = '{[\w\d-]+?,"(?<BaseName>[\w\.]+)","[^}]*'
        $AllMatches = [regex]::matches($confFile, $pattern)

        foreach ($FindingString in $AllMatches) {
            $Base = @{}

            if ($FindingString -match '{[\w\d-]+?,"(?<BaseName>[\w\.]+)","(?<Descr>[\w\s\.]*)[^"]*') {
                $Base.Add("BaseName_1C", $Matches["BaseName"])
                $Base.Add("Descr", $Matches["Descr"])
            }
            else {
                Continue
            }

            if ($FindingString -match '[\;\"]+DB=(?<BaseName>[\w\.]+);') {
                $Base.Add("BaseName_SQL", $Matches["BaseName"])
            }
            else {
                $Base.Add("BaseName_SQL", "")   
            }
            
            if ($FindingString -match ';DBMS=(?<DBMS>[\w]+);') {
                $Base.Add("DBMS", $Matches["DBMS"])
            }
            else {
                $Base.Add("DBMS", "")   
            }

            if ($FindingString -match ';DBSrvr=(?<Srv>[\w\.\-\\]+);') {
                $Base.Add("Srv_SQL", $Matches["Srv"])
            }
            else {
                $Base.Add("Srv_SQL", "")   
            }

            if ($FindingString -match ';Srvr=(?<Srv>[\w\.\-\:]+)') {
                $Base.Add("Srv_1C", $Matches["Srv"])
            }
            else {
                $Base.Add("Srv_1C", "")   
            }

            if ($FindingString -match ';LicDstr=(?<Lic_Share>\w);') {
                if ($Matches["Lic_Share"] -eq "Y") { 
                    $Lic_Share = $true 
                }
                else {
                    $Lic_Share = $false
                }

                $Base.Add("Lic_Share", $Lic_Share)
            }
            else {
                $Base.Add("Lic_Share", $false)   
            }

            if ($FindingString -match ';SchJobDn=(?<Job_OFF>[\w]);') {
                if ($Matches["Job_OFF"] -eq "Y") { 
                    $Job_OFF = $true 
                }
                else {
                    $Job_OFF = $false
                }

                $Base.Add("Job_OFF", $Job_OFF)
            }
            else {
                $Base.Add("Job_OFF", $false)   
            }

            if ($FindingString -match ';SQLYOffs=(?<Offs>[\d]+);') {
                $Base.Add("SQLYOffs", $Matches["Offs"])
            }
            else {
                $Base.Add("SQLYOffs", 0)   
            }
					
            $BaseList += $Base
        }
    }
    catch { 
        Write-Host; Write-Warning ("Ошибка (Get-1C_Servers83): {0}" -f $_.Exception.Message) 
    }  

    $BaseList
}

$WmiTimeout = '0:1:0'
$PCName = (Get-WmiObject Win32_ComputerSystem).DNSHostName + "." + (Get-WmiObject Win32_ComputerSystem).Domain
$DataFile = $PCName + ".json"
$invetoryData = New-Object PSObject -Property @{
    Server     = Get-ServerData
    Services1C = Get-1C_Services
}

$Data = $invetoryData | ConvertTo-JSON -Depth 6
$Fields = @{
    "Content"=$Data
}

Invoke-WebRequest -Method POST -Body $Fields -Uri $Uri
