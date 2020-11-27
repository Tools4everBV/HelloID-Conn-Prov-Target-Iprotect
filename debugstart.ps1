. ..\Debug\debugconfiguration.ps1
. .\testqueries.ps1 -debug $true


#simulate the input normally provided by the helloid as required in the same json format
$debugConfiguration = Get_DebugConfiguration -ConfigurationID "iprotect"
$configuration = $debugConfiguration  | ConvertTo-Json -Depth 10
$debugPerson = @{DisplayName = "testPersonDisplayName"}
$person = $debugPerson  | ConvertTo-Json -Depth 10

#build the ConnSetting that contains the complete conector settings

$ConnSettings = @{
    config = ConvertFrom-Json $configuration
    p = $person | ConvertFrom-Json
    # aRef = $accountReference | ConvertFrom-Json
    authenticationSuccess = $false;
    authorizationCookie = $null
    }
    
    Execute_Testqueries  -ConnectorSettings $ConnSettings    
