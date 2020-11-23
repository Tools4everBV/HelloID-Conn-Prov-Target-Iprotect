. C:\Tools4everDevelopment\HelloId\iprotect\Debug\debugconfiguration.ps1
$DebugTest= $true;

if ($DebugTest)
{ 
    #simulate the input normally provided by the caller as required
 
    $debugConfiguration = Get_DebugConfiguration -ConfigurationID "iprotect"
    $configuration = $debugConfiguration  | ConvertTo-Json -Depth 10
    $debugPerson = @{DisplayName = "testPersonDisplayName"}
    $person = $debugPerson  | ConvertTo-Json -Depth 10
}
$success = $false;

$ConnectorSettings = @{
    config = ConvertFrom-Json $configuration
    p = $person | ConvertFrom-Json
    # aRef = $accountReference | ConvertFrom-Json
    authenticationSuccess = $false;
    authorizationCookie = ""
    }
    
    $auditMessage = "iprotect identity for person " + $p.DisplayName + " not updated successfully";
    
    $account = [PSCustomObject]@{
        EmployeeId = $p.externalId  # Employee Number
        UserId     = $aRef              # UserName Ultmio (User AD)
    }

    if ([Net.ServicePointManager]::SecurityProtocol -notmatch "Tls12") {
        [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
    }
    
    #  first retrieve the connection cookie

  

    $webservicePath = "xmlsql"
    $headers = @{
        'Content-Type' = "application/x-www-form-urlencoded"                
    }

    if ($ConnectorSettings.config.proxyAddress -ne "")
    {
        $splatWebRequestParameters = @{
            Uri = $ConnectorSettings.config.urlXMLSQL + $webservicePath
            Method = 'Post'
            Headers = $headers
            Proxy = $ConnectorSettings.config.proxyAddress
            UseBasicParsing = $true
            Body = "";  
        }             
    }
    else {
        $splatWebRequestParameters = @{
            Uri = $Connectorsettings.config.urlXMLSQL + $webservicePath
            Method = 'Post'
            Headers = $headers                
            UseBasicParsing = $true
            Body = "";
        }
    }  
    
    try{
        $Requestresult = Invoke-WebRequest @splatWebRequestParameters  
    }
    catch{
        throw $_
    }




    $result = [PSCustomObject]@{ 
        Success          = $success;
        AccountReference = $aRef
        AuditDetails     = $auditMessage;
        Account          = $account; 
    };
    
    #send result back
    Write-Output $result | ConvertTo-Json -Depth 10