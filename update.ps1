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
    authorizationCookie = $null
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

    $splatWebRequestParameters = @{
        Uri = $Connectorsettings.config.urlXMLSQL + $webservicePath
        Method = 'Post'
        Headers = $headers                
        UseBasicParsing = $true
        TimeoutSec = 60 
        MaximumRedirection = 0    
        Body = "";
    }
    

    try{
        $Requestresult = Invoke-WebRequest @splatWebRequestParameters  
    }
    catch{
        throw $_S
    }
    if($null -ne $Requestresult.Headers)
    {
        if ($null -ne $Requestresult.Headers["Set-Cookie"] )
        {
            $authorizationCookie = $Requestresult.Headers["Set-Cookie"]

            if ($authorizationCookie.IndexOf(";") -gt 0)
            {
                $CookieString = $authorizationCookie.Substring(0, $authorizationCookie.IndexOf(";"));
                $ConnectorSettings.authorizationCookie = $CookieString;
            }
        }
    }
    # setup connection
    if ($null -ne $ConnectorSettings.authorizationCookie)
    {
        if ( $ConnectorSettings.authorizationCookie.length -gt 0)
        {
            $webservicePath = 'j_security_check'
            $headers = @{
                'Content-Type' = "application/x-www-form-urlencoded" 
                'Cookie' = $ConnectorSettings.authorizationCookie                       
            }
            $body = "&j_username=$($debugConfiguration.UserName)&j_password=$($debugConfiguration.Password)" 
            
            $splatWebRequestParameters = @{
                Uri = $Connectorsettings.config.urlXMLSQL + $webservicePath
                Method = 'Post'
                Headers = $headers                
                UseBasicParsing = $true
                Body = $body;               
            }       
        
            try{
                $Requestresult = Invoke-WebRequest @splatWebRequestParameters  
            }
            catch{
                throw $_S
            }
        }
    }
     






    $result = [PSCustomObject]@{ 
        Success          = $success;
        AccountReference = $aRef
        AuditDetails     = $auditMessage;
        Account          = $account; 
    };
    
    #send result back
    Write-Output $result | ConvertTo-Json -Depth 10