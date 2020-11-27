Param ([bool]$debug = $false)

if ($debug -ne $true)
{
$ConnSettings = @{
    config = ConvertFrom-Json $configuration
    p = $person | ConvertFrom-Json
    # aRef = $accountReference | ConvertFrom-Json
    authenticationSuccess = $false;
    authorizationCookie = $null
    }
}
    
    function Execute_Testqueries
    {
        [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]    
        $ConnectorSettings
    )

    
        $success = $false;
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
            SessionVariable = 'curSession'
        }    

        try{
            $Requestresult = Invoke-WebRequest @splatWebRequestParameters  
        }
        catch{
            throw $_
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
        # authenticate connection
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
                    MaximumRedirection = 0    
                    Body = $body;     
                    WebSession = $curSession        
                }       
            
                try{
                    $Requestresult = Invoke-WebRequest @splatWebRequestParameters                
                }
                catch{
                    throw $_
                }
                if ($Requestresult.StatusCode -eq 302)
                {
                    $ConnectorSettings.authenticationSuccess = $true
                }
            }
        }

        # execute query
        if ($ConnectorSettings.authenticationSuccess)
        {
            $query = 'SELECT * FROM SYSTEMUSER'
            #$query = 'SELECT * FROM person'
            #$query = 'SELECT TABLEEMPLOYEE.EMPLOYEEID, TABLEEMPLOYEE.DEPARTMENTID, TABLEEMPLOYEE.FREEDATE1, TABLEEMPLOYEE.FREEDATE2, TABLEEMPLOYEE.HIREDATE, TABLEEMPLOYEE.LOGINNAME, TABLEEMPLOYEE.PERSONID, TABLEEMPLOYEE.ROLE, TABLEEMPLOYEE.SALARYNR, TABLEEMPLOYEE.SELECTID1, TABLEEMPLOYEE.SELECTID2, TABLEEMPLOYEE.SELECTID3, TABLEEMPLOYEE.SELECTID4, TABLEEMPLOYEE.SELECTID5, TABLEEMPLOYEE.SELECTID6, TABLEEMPLOYEE.SELECTID7, TABLEEMPLOYEE.SELECTID8, TABLEEMPLOYEE.TERMINATIONDATE, TABLEEMPLOYEE.USERGROUPID  FROM employee tableEmployee'
            $queryType = 'query'
            switch ($queryType)
            {
                'query' {  $body = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><query><sql>$query</sql></query>"}                
                'update' { $body = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><update><sql>$query</sql></update>"}                 
            }
            $webservicePath = "xmlsql"
            $headers = @{
                'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'          
                'Cookie' = $ConnectorSettings.authorizationCookie                       
            }
            $splatWebRequestParameters = @{
                Uri = $Connectorsettings.config.urlXMLSQL + $webservicePath
                Method = 'Post'
                Headers = $headers                
                UseBasicParsing = $true              
                ContentType = 'text/xml;charset=ISO-8859-1' 
                Body = $body; 
                WebSession = $curSession                
            }       
        
            try{
                $Requestresult = Invoke-WebRequest @splatWebRequestParameters      
            }
            catch{
                throw $_
            }
        }
        [xml] $IprotectDataxml = $Requestresult.Content  
        $resultNode = $IprotectDataxml.item("RESULT")          
        $nodePath = "ROWSET" 
        $rowsetNode = $resultNode.SelectSingleNode($nodePath)
        $nodePath = "ROW"
        $rowNodes = $rowsetNode.SelectNodes($nodePath)
        foreach($rowNode in $rowNodes)
        {
            $curObject = @{
                SYSTEMUSERID = $rowNode.item("SYSTEMUSERID").FirstChild.Value
            } 
        }
        #close the session

        $webservicePath = "xmlsql"
        $headers = @{
            'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'          
            'Cookie' = $ConnectorSettings.authorizationCookie                       
        }
        $body = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><LOGOUT></LOGOUT>";
        $splatWebRequestParameters = @{
            Uri = $Connectorsettings.config.urlXMLSQL + $webservicePath
            Method = 'Post'
            Headers = $headers                
            UseBasicParsing = $true              
            ContentType = 'text/xml;charset=ISO-8859-1' 
            Body = $body; 
            WebSession = $curSession                
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
    }

    if ($debug -ne $true)
    {
        Execute_Testqueries  -ConnectorSettings $ConnSettings
    }