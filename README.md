# cMsmq

The **cMsmq** module contains DSC resources for managing private MSMQ queues.

*Supports Windows Server 2008 R2 and later.*

You can also download this module from the [PowerShell Gallery](https://www.powershellgallery.com/packages/cMsmq/).

## Resources

### cMsmqQueue

* **Ensure**: Indicates whether the queue exists.
* **Name**: Indicates the name of the queue.
* **Transactional**: Indicates whether the queue is transactional.

  > **Note:** If there is already a queue with the same name but of different type, an error will be thrown.

* **Authenticate**: Indicates whether the queue accepts only authenticated messages.
* **Journaling**: Indicates whether received messages are copied to the journal queue.
* **JournalQuota**: Indicates the maximum size of the journal queue in KB.
* **Label**: Indicates the description of the queue.
* **PrivacyLevel**: Indicates the privacy level associated with the queue.
* **QueueQuota**: Indicates the maximum size of the queue in KB.

### cMsmqQueuePermissionEntry

* **Ensure**: Indicates whether the permission entry exists. The default value is `Present`. Set this property to `Absent` to ensure that any access rights the principal has are revoked.
* **Name**: Indicates the name of the queue.
* **Principal**: Indicates the identity of the principal. Valid name formats: Down-Level Logon Name; User Principal Name; sAMAccountName; Security Identifier.
* **AccessRights**: Indicates the access rights to be granted to the principal. Specify one or more values from the [System.Messaging.MessageQueueAccessRights](https://msdn.microsoft.com/en-us/library/system.messaging.messagequeueaccessrights%28v=vs.110%29.aspx) enumeration type. Multiple values can be specified by using a comma-separated string.

> **Note:**
> If the **Ensure** property is set to `Absent`, all the other non-mandatory properties are ignored. Applies to both the **cMsmqQueue** and the **cMsmqQueuePermissionEntry** resources.

## Versions

### 1.0.3 (November 24, 2015)

* Minor bug-fixing update.

### 1.0.2 (October 15, 2015)

* Minor update.

### 1.0.1 (October 2, 2015)

* Module manifest updated.

### 1.0.0 (October 1, 2015)

* Initial release with the following resources:
  - **cMsmqQueue**;
  - **cMsmqQueuePermissionEntry**.

## Examples

This configuration will install Microsoft Message Queuing (MSMQ), create several private queues, and assign permissions on them.

```powershell

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


```

