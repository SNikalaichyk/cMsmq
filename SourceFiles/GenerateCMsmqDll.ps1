<#
Compiles the cMsmq.cs source file into the cMsmq.dll library.
It implements the MQGetQueueSecurity function to retrieve information from the access control security descriptors of MSMQ queues.
#>

$TypeDefinition = Get-Content -Path "$PSScriptRoot\cMsmq.cs" | Out-String

Add-Type -TypeDefinition $TypeDefinition -Language CSharpVersion3 -OutputAssembly "$PSScriptRoot\cMsmq.dll" -OutputType Library

