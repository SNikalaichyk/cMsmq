
#requires -Version 4.0 -Modules xDSCResourceDesigner

$ModuleName = 'cMsmq'
$ResourceName = 'cMsmqQueuePermissionEntry'

$DscResourceProperties =  @(
    (New-xDscResourceProperty -Type String -Attribute Write -Name Ensure -ValidateSet 'Absent', 'Present' -Description "Indicates whether the permission entry exists. The default value is Present. Set this property to Absent to ensure that any access rights the principal has are revoked.")
    (New-xDscResourceProperty -Type String -Attribute Key -Name Name -Description 'Indicates the name of the queue.'),
    (New-xDscResourceProperty -Type String -Attribute Key -Name Principal -Description 'Indicates the identity of the principal. Valid name formats: Down-Level Logon Name; User Principal Name; sAMAccountName; Security Identifier.'),
    (New-xDscResourceProperty -Type String[] -Attribute Write -Name AccessRights -Description 'Indicates the access rights to be granted to the principal. Specify one or more values from the System.Messaging.MessageQueueAccessRights enumeration type. Multiple values can be specified by using a comma-separated string.')
)

New-xDscResource -Name $ResourceName -ModuleName $ModuleName -Property $DscResourceProperties -Verbose

