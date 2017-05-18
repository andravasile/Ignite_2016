
#region Write-TransLog

function Write-TransLog {
	
<#
.Synopsis
	General Log file output 
.Description
	Provide General Log File output that can be read with trace32.exe
.Parameter Message
	Provide a relevant message to the log  
.Parameter Component
	Can be used to point to a location with in a script
.Parameter TypeName
	Type Status Normal, Warning, and Error
.Parameter WriteEvent
	Switch Parameter that will write warning and errors to the Windows Event Log as well as file log (Event ID: 6596)
.Parameter DebugWriteEvent
	Switch Parameter that will write normal, warning, and errors to the Windows Event Log as well as file log (Event ID: 6596)
.Inputs 
	String
.Outputs
	Log File and optional Event Log
.Example
	Write events to Log File (C:\TransLogs)
	Write-TransLog -Message test -Component main -TypeName Error
	
	Write All Events to both the Log File and Event Log (Normal, Warning, and Errors)
	Write-TransLog -Message Test -Component Main -TypeName Warning -WriteEvent -DebugWriteEvent
	
	Write Warning and Error Events to both the Log File and Event Log (Warning, and Errors)
	Write-TransLog -Message Test -Component Main -TypeName Warning -WriteEvent
	
.Notes
	Written by : Tanner Slayton (21-04-2017) v1
#>
	
	[Cmdletbinding()]
	param (
		[Parameter(mandatory = $true,
				Valuefrompipeline = $true
		)]
		[string[]]$Message,
		[string]$Component,
		[Parameter(
				Mandatory = $true,
				ParameterSetName = 'ParamSet 1'
		)]
		[validateset("Normal", "Warning", "Error")]
		[string]$TypeName,
		[switch]$WriteEvent,
		[switch]$DebugWriteEvent
	)

    [string]$Invocation = $MyInvocation.ScriptName.ToString()
    [string]$ScriptName = Split-Path -Path $Invocation -Leaf
	[string]$LogFilePath = 'C:\TransLogs'
	[string]$LogFileName = $ScriptName.Replace('.ps1','.log')
 
    If((Test-Path -Path $LogFilePath) -eq $False)
    {
        New-Item -Path $LogFilePath -ItemType Directory -Force
    }
	
	If ($LogFileName -eq ".log") 
    { 
        Write-Warning "No Log Name is specified"
        $LogFileName = "PoSH-Log-$(Get-Date -Format MMddyyyy-HHMMss).log"
    }
	
	[string]$FullLogPath = Join-Path -Path $LogFilePath -ChildPath $LogFileName
	
    $LogType = Switch($TypeName) 
    {
	    'Normal' { 1 }
		'Warning' { 2 }
		'Error' { 3 }
		Default { 1 }
    }
	
	[string]$LogTime = (get-date -format HH\:mm\:ss) + ".000+000"
	[string]$LogDate = (get-date -format MM\-dd\-yyyy)
	[string]$Component = "$Component - Line:$($MyInvocation.ScriptLineNumber)"
	[string]$ScriptName = If (((($MyInvocation.ScriptName) -split '\\')[-1]) -ne '\$MyInvocation') { ((($MyInvocation.ScriptName) -split '\\')[-1]) }
	[string[]]$LogLine = "<![LOG[" + $Message + "]LOG]!><time=""" + $LogTime + """ date=""" + $LogDate + """ component=""" + $Component + """ context="""" type=""" + $LogType + """ thread=""" + $pid + """ file=""" + $ScriptName.Replace('.ps1','') + """>"

    Add-Content -Path $FullLogPath -Value $LogLine
    [string]$EventSource = 'SecEnable'	


    If ($WriteEvent) 
    {
        If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] “Administrator”) -eq $False)
        {
            [string]$Message = 'Write to Event Log was enabled, but script is not executing elevated, Event Log has been disabled'
            [string[]]$LogLine = "<![LOG[" + $Message + "]LOG]!><time=""" + $LogTime + """ date=""" + $LogDate + """ component=""" + $Component + """ context="""" type=""" + $LogType + """ thread=""" + $pid + """ file=""" + $ScriptName.Replace('.ps1','') + """>"
            Add-Content -Path $FullLogPath -Value $LogLine
        }
        Else
        {
		    switch ($TypeName)
            {
                'Normal'    {
                                If($DebugWriteEvent -eq $true)
                                {
                                    New-EventLog -LogName Application -Source $EventSource -ErrorAction SilentlyContinue
                                    $EvtLogMessage = "$Message `nLogPath: $FullLogPath"
                                    Write-EventLog -EventId 6596 -EntryType Information -LogName Application -Source $EventSource -Message $EvtLogMessage -Category 1
                                }
                            }
                'Warning'   {
                                New-EventLog -LogName 'Application' -Source $EventSource -ErrorAction SilentlyContinue
                                $EvtLogMessage = "$Message `nLogPath: $FullLogPath"
                                Write-EventLog -EventId 6596 -EntryType Warning -LogName Application -Source $EventSource -Message $EvtLogMessage -Category 2
                            }
                'Error'     {
                                New-EventLog -LogName 'Application' -Source $EventSource -ErrorAction SilentlyContinue
                                $EvtLogMessage = "$Message `nLogPath: $FullLogPath"
                                Write-EventLog -EventId 6596 -EntryType Error -LogName Application -Source $EventSource -Message $EvtLogMessage -Category 3
                            }
			    Default     {
                                If($DebugWriteEvent -eq $true)
                                {
                                    New-EventLog -LogName 'Application' -Source $EventSource -ErrorAction SilentlyContinue
                                    $EvtLogMessage = "$Message `nLogPath: $FullLogPath"
                                    Write-EventLog -EventId 6596 -EntryType Information -LogName Application -Source $EventSource -Message $EvtLogMessage -Category 1
                                }
			                }
		    }
        }
	}
}

#endregion