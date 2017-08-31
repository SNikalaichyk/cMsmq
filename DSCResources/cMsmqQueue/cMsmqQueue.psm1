#requires -Version 4.0

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )
    begin
    {
        $Service = Get-Service -Name MSMQ -ErrorAction Stop

        if ($Service.Status -ne 'Running')
        {
            throw 'Please ensure that the Message Queuing (MSMQ) service is running.'
        }

        Initialize-cMsmqType
    }
    process
    {
        $cMsmqQueue = Get-cMsmqQueue -Name $Name -ErrorAction SilentlyContinue

        if ($cMsmqQueue)
        {
            Write-Verbose -Message "Queue '$Name' was found."

            $EnsureResult = 'Present'
        }
        else
        {
            Write-Verbose -Message "Queue '$Name' could not be found."

            $EnsureResult = 'Absent'
        }

        $ReturnValue = @{
                Ensure        = $EnsureResult
                Name          = $Name
                Transactional = $cMsmqQueue.Transactional
                Authenticate  = $cMsmqQueue.Authenticate
                Journaling    = $cMsmqQueue.Journaling
                JournalQuota  = $cMsmqQueue.JournalQuota
                Label         = $cMsmqQueue.Label
                PrivacyLevel  = $cMsmqQueue.PrivacyLevel
                QueueQuota    = $cMsmqQueue.QueueQuota
            }

        return $ReturnValue
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Absent', 'Present')]
        [String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $Transactional = $false,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $Authenticate = $false,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $Journaling = $false,

        [Parameter(Mandatory = $false)]
        [UInt32]
        $JournalQuota = [UInt32]::MaxValue,

        [Parameter(Mandatory = $false)]
        [String]
        $Label = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('None', 'Optional', 'Body')]
        [String]
        $PrivacyLevel = 'Optional',

        [Parameter(Mandatory = $false)]
        [UInt32]
        $QueueQuota = [UInt32]::MaxValue
    )

    $PSBoundParameters.GetEnumerator() |
    ForEach-Object -Begin {
        $Width = $PSBoundParameters.Keys.Length | Sort-Object -Descending | Select-Object -First 1
    } -Process {
        "{0,-$($Width)} : '{1}'" -f $_.Key, ($_.Value -join ', ') |
        Write-Verbose
    }

    $TargetResource = Get-TargetResource -Name $Name

    if ($Ensure -eq 'Absent')
    {
        if ($TargetResource.Ensure -eq 'Absent')
        {
            $InDesiredState = $true
        }
        else
        {
            $InDesiredState = $false
        }
    }
    else
    {
        if ($TargetResource.Ensure -eq 'Absent')
        {
            $InDesiredState = $false
        }
        else
        {
            $InDesiredState = $true

            if ($PSBoundParameters.ContainsKey('Transactional'))
            {
                if ($TargetResource.Transactional -ne $Transactional)
                {
                    $InDesiredState = $false

                    if ($TargetResource.Transactional -eq $true)
                    {
                        $CurrentQueueTypeString = 'transactional'
                    }
                    else
                    {
                        $CurrentQueueTypeString = 'non-transactional'
                    }

                    if ($Transactional -eq $true)
                    {
                        $DesiredQueueTypeString = 'transactional'
                    }
                    else
                    {
                        $DesiredQueueTypeString = 'non-transactional'
                    }

                    $ErrorMessage = "Queue '{0}' is {1} and cannot be converted to {2}." -f $Name, $CurrentQueueTypeString, $DesiredQueueTypeString

                    throw $ErrorMessage
                }
            }

            $PSBoundParameters.GetEnumerator() |
            Where-Object {$_.Key -in @('Authenticate', 'Journaling', 'JournalQuota', 'Label', 'PrivacyLevel', 'QueueQuota')} |
            ForEach-Object {

                $PropertyName = $_.Key

                if ($TargetResource."$PropertyName" -cne $_.Value)
                {
                    $InDesiredState = $false

                    "Property '{0}': Current value '{1}'; Desired value: '{2}'." -f $PropertyName, $TargetResource."$PropertyName", $_.Value |
                    Write-Verbose
                }

            }
        }
    }

    if ($InDesiredState -eq $true)
    {
        Write-Verbose -Message "The target resource is already in the desired state. No action is required."
    }
    else
    {
        Write-Verbose -Message "The target resource is not in the desired state."
    }

    return $InDesiredState
}

function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Absent', 'Present')]
        [String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $Transactional = $false,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $Authenticate = $false,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $Journaling = $false,

        [Parameter(Mandatory = $false)]
        [UInt32]
        $JournalQuota = [UInt32]::MaxValue,

        [Parameter(Mandatory = $false)]
        [String]
        $Label = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('None', 'Optional', 'Body')]
        [String]
        $PrivacyLevel = 'Optional',

        [Parameter(Mandatory = $false)]
        [UInt32]
        $QueueQuota = [UInt32]::MaxValue
    )

    if (-not $PSCmdlet.ShouldProcess($Name))
    {
        return
    }

    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    if ($Ensure -eq 'Absent')
    {
        Write-Verbose -Message "Testing if the current user has the permission necessary to perform the operation."

        $CurrentUserPermission = Get-cMsmqQueuePermission -Name $Name -Principal $CurrentUser -ErrorAction SilentlyContinue
        $PermissionToTest = [System.Messaging.MessageQueueAccessRights]::DeleteQueue

        if (-not $CurrentUserPermission -or -not $CurrentUserPermission.HasFlag($PermissionToTest))
        {
            "User '{0}' does not have the '{1}' permission on queue '{2}'." -f $CurrentUser, $PermissionToTest, $Name |
            Write-Verbose

            Reset-cMsmqQueueSecurity -Name $Name -Confirm:$false -Verbose:$VerbosePreference
        }

        $PSBoundParameters.GetEnumerator() |
        Where-Object {$_.Key -in (Get-Command -Name Remove-cMsmqQueue).Parameters.Keys} |
        ForEach-Object -Begin {$RemoveParameters = @{}} -Process {$RemoveParameters.Add($_.Key, $_.Value)}

        Remove-cMsmqQueue @RemoveParameters -Confirm:$false
    }
    else
    {
        $TargetResource = Get-TargetResource -Name $Name

        if ($TargetResource.Ensure -eq 'Absent')
        {
            $PSBoundParameters.GetEnumerator() |
            Where-Object {$_.Key -in (Get-Command -Name New-cMsmqQueue).Parameters.Keys} |
            ForEach-Object -Begin {$NewParameters = @{}} -Process {$NewParameters.Add($_.Key, $_.Value)}

            New-cMsmqQueue @NewParameters
        }
        else
        {
            Write-Verbose -Message "Testing if the current user has the permission necessary to perform the operation."

            $CurrentUserPermission = Get-cMsmqQueuePermission -Name $Name -Principal $CurrentUser -ErrorAction SilentlyContinue
            $PermissionToTest = [System.Messaging.MessageQueueAccessRights]::SetQueueProperties

            if (-not $CurrentUserPermission -or -not $CurrentUserPermission.HasFlag($PermissionToTest))
            {
                "User '{0}' does not have the '{1}' permission on queue '{2}'." -f $CurrentUser, $PermissionToTest, $Name |
                Write-Verbose

                Reset-cMsmqQueueSecurity -Name $Name -Confirm:$false -Verbose:$VerbosePreference
            }

            $PSBoundParameters.GetEnumerator() |
            Where-Object {$_.Key -in (Get-Command -Name Set-cMsmqQueue).Parameters.Keys} |
            ForEach-Object -Begin {$SetParameters = @{}} -Process {$SetParameters.Add($_.Key, $_.Value)}

            Set-cMsmqQueue @SetParameters
        }
    }
}

Export-ModuleMember -Function *-TargetResource

#region Helper Functions

function Initialize-cMsmqType
{
    <#
    .SYNOPSIS
        Initializes custom and native MSMQ types.
    .DESCRIPTION
        The Initialize-cMsmqType function initializes custom and native MSMQ types.
    #>

    $DllFilePath = Split-Path -Path $PSScriptRoot -Parent |
        Split-Path -Parent |
        Join-Path -ChildPath 'cMsmq.dll'

    if ([AppDomain]::CurrentDomain.GetAssemblies().Location -notcontains $DllFilePath)
    {
        Add-Type -Path $DllFilePath -ErrorAction Stop
    }

    if ([AppDomain]::CurrentDomain.GetAssemblies().ManifestModule.Name -notcontains 'System.Messaging.dll')
    {
        Add-Type -AssemblyName System.Messaging -ErrorAction Stop
    }
}

Initialize-cMsmqType

function Get-cMsmqQueue
{
    <#
    .SYNOPSIS
        Gets the specified private MSMQ queue by its name.
    .DESCRIPTION
        The Get-cMsmqQueue function gets the specified private MSMQ queue by its name.
    .PARAMETER Name
        Specifies the name of the queue.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )
    begin
    {
        Initialize-cMsmqType
    }
    process
    {
        $QueuePath = '.\{0}' -f $Name

        if (-not [System.Messaging.MessageQueue]::Exists($QueuePath))
        {
            Write-Error -Message "Queue '$Name' could not be found at the specified path: '$QueuePath'."
            return
        }

        $Queue = New-Object -TypeName System.Messaging.MessageQueue -ArgumentList $QueuePath

        $OutputObject = [PSCustomObject]@{
                Name          = $Name
                Path          = $Queue.Path
                Transactional = $Queue.Transactional
                Authenticate  = $Queue.Authenticate
                Journaling    = $Queue.UseJournalQueue
                JournalQuota  = [UInt32]$Queue.MaximumJournalSize
                Label         = $Queue.Label
                PrivacyLevel  = [String]$Queue.EncryptionRequired
                QueueQuota    = [UInt32]$Queue.MaximumQueueSize
            }

        return $OutputObject
    }
}

function Get-cMsmqQueuePermission
{
    <#
    .SYNOPSIS
        Gets the access rights of the specified principal on the specified private MSMQ queue.
    .DESCRIPTION
        The Get-cMsmqQueuePermission function gets the access rights that have been granted
        to the specified security principal on the specified MSMQ queue.
    .PARAMETER Name
        Specifies the name of the queue.
    .PARAMETER Principal
        Specifies the identity of the principal.
    #>
    [CmdletBinding()]
    [OutputType([System.Messaging.MessageQueueAccessRights])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [String]
        $Principal
    )
    begin
    {
        Initialize-cMsmqType
    }
    process
    {
        try
        {
            Write-Verbose -Message "Getting permissions for principal '$Principal' on queue '$Name'."

            $AccessMask = [cMsmq.Security]::GetAccessMask($Name, $Principal)
            $OutputObject = [System.Messaging.MessageQueueAccessRights]$AccessMask.value__

            return $OutputObject
        }
        catch
        {
            Write-Error -Message $_.Exception.Message
            return
        }
    }
}

function New-cMsmqQueue
{
    <#
    .SYNOPSIS
        Creates a new private MSMQ queue.
    .DESCRIPTION
        The New-cMsmqQueue function creates a new private MSMQ queue.
    .PARAMETER Name
        Specifies the name of the queue.
    .PARAMETER Transactional
        Specifies whether the queue is a transactional queue.
    .PARAMETER Authenticate
        Sets a value that indicates whether the queue accepts only authenticated messages.
    .PARAMETER Journaling
        Sets a value that indicates whether received messages are copied to the journal queue.
    .PARAMETER JournalQuota
        Sets the maximum size of the journal queue in KB.
    .PARAMETER Label
        Sets the queue description.
    .PARAMETER PrivacyLevel
        Sets the privacy level associated with the queue.
    .PARAMETER QueueQuota
        Sets the maximum size of the queue in KB.
    #>
    [CmdletBinding(ConfirmImpact = 'Medium', SupportsShouldProcess = $true)]
    param
    (
        [Parameter( Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $Transactional = $false,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $Authenticate = $false,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $Journaling = $false,

        [Parameter(Mandatory = $false)]
        [UInt32]
        $JournalQuota = [UInt32]::MaxValue,

        [Parameter(Mandatory = $false)]
        [String]
        $Label = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('None', 'Optional', 'Body')]
        [String]
        $PrivacyLevel = 'Optional',

        [Parameter(Mandatory = $false)]
        [UInt32]
        $QueueQuota = [UInt32]::MaxValue
    )
    begin
    {
        Initialize-cMsmqType

        $PropertyNames = @{
                Authenticate = 'Authenticate'
                Journaling   = 'UseJournalQueue'
                JournalQuota = 'MaximumJournalSize'
                Label        = 'Label'
                PrivacyLevel = 'EncryptionRequired'
                QueueQuota   = 'MaximumQueueSize'
            }
    }
    process
    {
        if (-not $PSCmdlet.ShouldProcess($Name, 'Create Queue'))
        {
            return
        }

        $QueuePath = '.\{0}' -f $Name

        try
        {
            $Queue = [System.Messaging.MessageQueue]::Create($QueuePath, $Transactional)
        }
        catch
        {
            Write-Error -Message $_.Exception.Message
            return
        }

        $PSBoundParameters.GetEnumerator() |
        Where-Object {$_.Key -in $PropertyNames.Keys} |
        ForEach-Object {

            $PropertyName = $PropertyNames.Item($_.Key)

            if ($Queue."$PropertyName" -cne $_.Value)
            {
                "Setting property '{0}' to value '{1}'." -f $PropertyName, $_.Value |
                Write-Verbose

                $Queue."$PropertyName" = $_.Value
            }

        }
    }
}

function Remove-cMsmqQueue
{
    <#
    .SYNOPSIS
        Removes the specified MSMQ queue.
    .DESCRIPTION
        The Remove-cMsmqQueue function the specified MSMQ queue.
    .PARAMETER Name
        Specifies the name of the queue.
    #>
    [CmdletBinding(ConfirmImpact = 'High', SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )
    begin
    {
        Initialize-cMsmqType
    }
    process
    {
        if (-not $PSCmdlet.ShouldProcess($Name, 'Remove Queue'))
        {
            return
        }

        $QueuePath = '.\{0}' -f $Name

        try
        {
            [Void][System.Messaging.MessageQueue]::Delete($QueuePath)
        }
        catch
        {
            Write-Error -Message $_.Exception.Message
            return
        }
    }
}

function Reset-cMsmqQueueSecurity
{
    <#
    .SYNOPSIS
        Resets the security settings on the specified MSMQ queue.
    .DESCRIPTION
        The Reset-cMsmqQueueSecurity function performs the following actions:
        - Grants ownership of the queue to the SYSTEM account (DSC runs as SYSTEM);
        - Resets the permission list to the operating system's default values.
    .PARAMETER Name
        Specifies the name of the queue.
    #>
    [CmdletBinding(ConfirmImpact = 'High', SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )
    begin
    {
        Initialize-cMsmqType

        $DefaultSecurity = 'Security=010007801c0000002800000000000000140000000200080000000000' +
            '010100000000000512000000010500000000000515000000e611610036157811027bc60001020000'
    }
    process
    {
        if (-not $PSCmdlet.ShouldProcess($Name, 'Reset Queue Security'))
        {
            return
        }

        $QueuePath = '.\{0}' -f $Name

        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $QueueOwner = [cMsmq.Security]::GetOwner($Name)

        Write-Verbose -Message "Queue Owner : '$QueueOwner'"

        if ($CurrentUser -ne $QueueOwner)
        {
            Write-Verbose -Message "Taking ownership of queue '$Name'."

            $FilePath = Get-ChildItem -Path "$Env:SystemRoot\System32\msmq\storage\lqs" -Force |
                Select-String -Pattern "QueueName=$($Name)" -SimpleMatch |
                Select-Object -ExpandProperty Path

            if (-not $FilePath)
            {
                Write-Error -Message "Could not find a corresponding .INI file for queue '$Name'."
                return
            }

            (Get-Content -Path $FilePath) |
            ForEach-Object {$_ -replace '^Security=.+', $DefaultSecurity} |
            Set-Content -Path $FilePath
        }

        Write-Verbose -Message "Resetting permissions on queue '$Name'."

        $Queue = New-Object -TypeName System.Messaging.MessageQueue
        $Queue.Path = $QueuePath
        $Queue.ResetPermissions()
    }
}

function Set-cMsmqQueue
{
    <#
    .SYNOPSIS
        Sets properties on the specified MSMQ queue.
    .DESCRIPTION
        The Set-cMsmqQueue function sets properties on the specified MSMQ queue.
    .PARAMETER Name
        Specifies the name of the queue.
    .PARAMETER Authenticate
        Sets a value that indicates whether the queue accepts only authenticated messages.
    .PARAMETER Journaling
        Sets a value that indicates whether received messages are copied to the journal queue.
    .PARAMETER JournalQuota
        Sets the maximum size of the journal queue in KB.
    .PARAMETER Label
        Sets the queue description.
    .PARAMETER PrivacyLevel
        Sets the privacy level associated with the queue.
    .PARAMETER QueueQuota
        Sets the maximum size of the queue in KB.
    #>
    [CmdletBinding(ConfirmImpact = 'Medium', SupportsShouldProcess = $true)]
    param
    (
        [Parameter( Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $Authenticate = $false,

        [Parameter(Mandatory = $false)]
        [Boolean]
        $Journaling = $false,

        [Parameter(Mandatory = $false)]
        [UInt32]
        $JournalQuota = [UInt32]::MaxValue,

        [Parameter(Mandatory = $false)]
        [String]
        $Label = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('None', 'Optional', 'Body')]
        [String]
        $PrivacyLevel = 'Optional',

        [Parameter(Mandatory = $false)]
        [UInt32]
        $QueueQuota = [UInt32]::MaxValue
    )
    begin
    {
        Initialize-cMsmqType

        $PropertyNames = @{
                Authenticate = 'Authenticate'
                Journaling   = 'UseJournalQueue'
                JournalQuota = 'MaximumJournalSize'
                Label        = 'Label'
                PrivacyLevel = 'EncryptionRequired'
                QueueQuota   = 'MaximumQueueSize'
            }
    }
    process
    {
        if (-not $PSCmdlet.ShouldProcess($Name, 'Set Queue'))
        {
            return
        }

        $QueuePath = '.\{0}' -f $Name

        if (-not [System.Messaging.MessageQueue]::Exists($QueuePath))
        {
            Write-Error -Message "Queue '$Name' could not be found at the specified path: '$QueuePath'."
            return
        }

        $Queue = New-Object -TypeName System.Messaging.MessageQueue -ArgumentList $QueuePath

        $PSBoundParameters.GetEnumerator() |
        Where-Object {$_.Key -in $PropertyNames.Keys} |
        ForEach-Object {

            $PropertyName = $PropertyNames.Item($_.Key)

            if ($Queue."$PropertyName" -ne $_.Value)
            {
                "Setting property '{0}' to value '{1}'." -f $PropertyName, $_.Value |
                Write-Verbose

                $Queue."$PropertyName" = $_.Value
            }

        }
    }
}

#endregion
