
$DebugTest= $true;
if ($DebugTest)
{
    $debugConfiguration = @{
        WebserviceUrl_users = "https://212.123.223.112:8443/Webcontrols/automated/import"
        webserviceUrl_xmlsql "https://212.123.223.112:8443/Webcontrols/"
        UserName = "Testuser"
        Password = "Testwachtwoord"
        ProxyAddress = "http://localhost:8888"
        ProxyUsername = ""
        Proxy_password = ""
    }
    $configuration = $debugConfiguration  | ConvertTo-Json -Depth 10

}



$ConnectorSettings = @{
    config = ConvertFrom-Json $configuration
    p = $person | ConvertFrom-Json}



    $result = [PSCustomObject]@{ 
        Success          = $success;
        AccountReference = $aRef
        AuditDetails     = $auditMessage;
        Account          = $account; 
    };
    
    #send result back
    Write-Output $result | ConvertTo-Json -Depth 10