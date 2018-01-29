#requires -Version 4.0 -Modules xDSCResourceDesigner

$DscModuleName   = 'cMsmq'
$DscResourceName = 'cMsmqQueue'

$DscResourceProperties =  @(
    (New-xDscResourceProperty -Type String -Attribute Write -Name Ensure -ValidateSet 'Absent', 'Present' -Description 'Indicates whether the queue exists.')
    (New-xDscResourceProperty -Type String -Attribute Key -Name Name -Description 'Indicates the name of the queue.')
    (New-xDscResourceProperty -Type String -Attribute Write -Name QueueType -ValidateSet 'Private', 'Public' -Description 'Indicates if it is a private or a public queue.'),
    (New-xDscResourceProperty -Type Boolean -Attribute Write -Name Transactional -Description 'Indicates whether the queue is transactional.')
    (New-xDscResourceProperty -Type Boolean -Attribute Write -Name Authenticate -Description 'Indicates whether the queue accepts only authenticated messages.')
    (New-xDscResourceProperty -Type Boolean -Attribute Write -Name Journaling -Description 'Indicates whether received messages are copied to the journal queue.')
    (New-xDscResourceProperty -Type UInt32 -Attribute Write -Name JournalQuota -Description 'Indicates the maximum size of the journal queue in KB.')
    (New-xDscResourceProperty -Type String -Attribute Write -Name Label -Description 'Indicates the description of the queue.')
    (New-xDscResourceProperty -Type String -Attribute Write -Name PrivacyLevel -ValidateSet 'None', 'Optional', 'Body' -Description 'Indicates the privacy level associated with the queue.')
    (New-xDscResourceProperty -Type UInt32 -Attribute Write -Name QueueQuota -Description 'Indicates the maximum size of the queue in KB.')
)

New-xDscResource -Name $DscResourceName -ModuleName $DscModuleName -Property $DscResourceProperties -Verbose
