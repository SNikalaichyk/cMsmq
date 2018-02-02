#requires -Version 4.0 -Modules xDSCResourceDesigner

$DscModuleName   = 'cMsmq'
$DscResourceName = 'cMsmqQueuePermissionEntry'

$DscResourceProperties =  @(
    (New-xDscResourceProperty -Type String -Attribute Write -Name Ensure -ValidateSet 'Absent', 'Present' -Description 'Indicates whether the permission entry exists.')
    (New-xDscResourceProperty -Type String -Attribute Key -Name Name -Description 'Indicates the name of the queue.'),
    (New-xDscResourceProperty -Type String -Attribute Write -Name QueueType -ValidateSet 'Private', 'Public' -Description 'Indicates if it is a private or a public queue.'),
    (New-xDscResourceProperty -Type String -Attribute Key -Name Principal -Description 'Indicates the identity of the principal.'),
    (New-xDscResourceProperty -Type String[] -Attribute Write -Name AccessRights -Description 'Indicates the access rights to be granted to the principal.')
)

New-xDscResource -Name $DscResourceName -ModuleName $DscModuleName -Property $DscResourceProperties -Verbose
