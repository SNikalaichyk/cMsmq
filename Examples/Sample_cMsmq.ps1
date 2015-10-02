
configuration Sample_cMsmq
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName cMsmq

    # Ensure the Message Queueing is installed.
    WindowsFeature MSMQ
    {
        Ensure = 'Present'
        Name = 'MSMQ'
    }

    # Ensure the MSMQ service is running.
    Service MsmqService
    {
        Name = 'MSMQ'
        State = 'Running'
        DependsOn = '[WindowsFeature]MSMQ'
    }

    # Ensure the specified private queue exists.
    # All the parameters will be either left unchanged or, if the queue is to be created, set to their default values.
    cMsmqQueue Queue1
    {
        Ensure = 'Present'
        Name = 'Queue-1'
        DependsOn = '[Service]MsmqService'
    }

    # Ensure the specified transactional private queue exists.
    # If there is already a private queue with the same name but of different type, an error will be thrown.
    cMsmqQueue Queue2
    {
        Ensure = 'Present'
        Name = 'Queue-2'
        Transactional = $true
        Authenticate = $true
        Journaling = $true
        JournalQuota = 65536
        Label = 'Created by the cMsmqQueue DSC resource'
        PrivacyLevel = 'Body'
        QueueQuota = 262144
        DependsOn = '[Service]MsmqService'
    }

    # Ensure the specified private queue does not exist.
    # If provided, all the other non-mandatory properties will be ignored.
    cMsmqQueue Queue3
    {
        Ensure = 'Absent'
        Name = 'Queue-3'
        DependsOn = '[Service]MsmqService'
    }

    # Grant Full Control permission level for the specified principal.
    cMsmqQueuePermissionEntry QueuePermission1
    {
        Ensure = 'Present'
        Name = 'Queue-1'
        Principal = $Env:UserDomain, $Env:UserName -join '\'
        AccessRights = 'FullControl'
        DependsOn = '[cMsmqQueue]Queue1'
    }

    # Grant multiple access rights for the specified principal.
    cMsmqQueuePermissionEntry QueuePermission2
    {
        Ensure = 'Present'
        Name = 'Queue-2'
        Principal = 'BUILTIN\Administrators'
        AccessRights = 'ChangeQueuePermissions', 'DeleteQueue'
        DependsOn = '[cMsmqQueue]Queue2'
    }

    # Revoke all permissions for the specified principal.
    cMsmqQueuePermissionEntry QueuePermission3
    {
        Ensure = 'Absent'
        Name = 'Queue-2'
        Principal = 'BUILTIN\Users'
        DependsOn = '[cMsmqQueue]Queue2'
    }
}

Sample_cMsmq -OutputPath "$Env:SystemDrive\Sample_cMsmq"

Start-DscConfiguration -Path "$Env:SystemDrive\Sample_cMsmq" -Force -Verbose -Wait

Get-DscConfiguration

