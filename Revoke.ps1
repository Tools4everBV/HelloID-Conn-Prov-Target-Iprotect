#Script to revoke membership
$config = ConvertFrom-Json $configuration
$person = $person | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json 
$pRef = $permissionReference | ConvertFrom-json;   
$dR = $dryRun | ConvertFrom-json;   
$offline = $dR 
    
if ($dR -eq $true )
{
    $aRef = @{   EmployeeSalaryNR = $p.ExternalId
        PersonName = $p.Name.FamilyName 
    }          
}

$success = $false;        
$auditMessage = "iprotect identity for person " + $p.DisplayName + " not disabled successfully";
$accesskeyIdList = [System.Collections.ArrayList]::new();
        
if ([Net.ServicePointManager]::SecurityProtocol -notmatch "Tls12") {
    [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
}

#  query iprotect to get the list of accesskeys        
#  first retrieve the connection cookie, but also send the query 

$query = "SELECT
TABLEPERSON.PERSONID as person_id,
TABLEPERSON.NAME as person_name,
TABLEPERSON.FIRSTNAME as person_first_name,        
TABLEEMPLOYEE.SALARYNR as employee_salarynr,        
VIEWACCESSKEY.ACCESSKEYID as access_key_id, 
VIEWACCESSKEY.RCN as access_keyrcn,        
VIEWACCESSKEY.VALID as access_key_valid 
FROM employee TABLEEMPLOYEE
LEFT OUTER JOIN person TABLEPERSON ON TABLEPERSON.personID = TABLEEMPLOYEE.personID 
LEFT OUTER JOIN accesskeyview VIEWACCESSKEY ON viewAccesskey.personID =  TABLEPERSON.personID "						

$queryType = 'query'
switch ($queryType)
{
    'query' {  $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><query><sql>$query</sql></query>"}                
    'update' { $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><update><sql>$query</sql></update>"}                 
}

$webservicePath = "xmlsql"
$headers = @{
    'Content-Type' = "application/x-www-form-urlencoded"            
} 

$splatWebRequestParameters = @{
    Uri = $config.urlXMLSQL + $webservicePath
    Method = 'Post'
    Headers = $headers                
    UseBasicParsing = $true
    TimeoutSec = 60 
    MaximumRedirection = 0    
    Body = $queryBody;
    SessionVariable = 'curSession'
}         
if(-Not($offline -eq $true)) {

    try{
        $requestResult = Invoke-WebRequest @splatWebRequestParameters  -ErrorAction SilentlyContinue
    }
    catch{
        throw $_
    } 
}
else 
{
    $headers = @{ "Set-Cookie" = "dummycookie;blabla"}
    $requestResult = @{ Headers = $headers}
}

if($null -ne $requestResult.Headers) {
    if ($null -ne $requestResult.Headers["Set-Cookie"] ) {
        $authorizationCookie = $requestResult.Headers["Set-Cookie"]

        if ($authorizationCookie.IndexOf(";") -gt 0)
        {
            $cookieString = $authorizationCookie.Substring(0, $authorizationCookie.IndexOf(";"));           
        }
    }
}        
# authenticate connection

$webservicePath = 'j_security_check'
$headers = @{
    'Content-Type' = "application/x-www-form-urlencoded" 
}
if ($null -ne $cookieString) {
    if ( $cookieString.length -gt 0) {
        $headers = @{
        'Content-Type' = "application/x-www-form-urlencoded" 
        'Cookie' = $cookieString
        }                       
    }
}
$body = "&j_username=$($config.UserName)&j_password=$($config.Password)" 

$splatWebRequestParameters = @{
    Uri = $config.urlXMLSQL + $webservicePath
    Method = 'Post'
    Headers = $headers                
    UseBasicParsing = $true
    MaximumRedirection = 0    
    Body = $body;     
    WebSession = $curSession        
}       
if(-Not($offline -eq $true)) {
    try{
        $requestResult = Invoke-WebRequest @splatWebRequestParameters   -ErrorAction SilentlyContinue             
    }
    catch{
        throw $_
    }
}
else {
    $requestResult = @{StatusCode = 302}                    
}

if ($requestResult.StatusCode -eq 302){
    #authentication success
}
else {
    $success = $false            
    $auditMessage = "iprotect query for person " + $p.ExternalId + ". Authentication failed with error $($requestResult.StatusCode)";
    $result = [PSCustomObject]@{ 
        Success          = $success;
        AccountReference = $aref
        AuditDetails     = $auditMessage;
        Account          = $aref; 
    };            
    #send result back
    Write-Output $result | ConvertTo-Json -Depth 10
    return; 
}

# execute query and fetch results       
    
$webservicePath = "xmlsql"
$headers = @{
    'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'          
    'Cookie' = $cookieString                       
}
$splatWebRequestParameters = @{
    Uri = $config.urlXMLSQL + $webservicePath
    Method = 'Post'
    Headers = $headers                
    UseBasicParsing = $true  
    MaximumRedirection = 0                
    ContentType = 'text/xml;charset=ISO-8859-1' 
    Body = $queryBody; 
    WebSession = $curSession                
}  

if(-Not($offline -eq $true)){

    try{
        $queryRequestResult = Invoke-WebRequest @splatWebRequestParameters      
    }
    catch{
        throw $_
    }
    

    [xml] $IprotectDataxml = $queryRequestResult.Content  
    $resultNode = $IprotectDataxml.item("RESULT")          
    $nodePath = "ROWSET" 
    $rowsetNode = $resultNode.SelectSingleNode($nodePath)

    $nodePath = "ERROR"
    $ErrorNode =  $resultNode.SelectSingleNode($NodePath) 
    if ($null -ne $ErrorNode) {
        $success = $false
        $ErrorDescription = $ErrorNode.item("DESCRIPTION").FirstChild.Value
        $ErrorNumber =   $ErrorNode.item("NUMBER").FirstChild.Value
        $auditMessage = "iprotect query for person " + $p.ExternalId + " failed with error $ErrorNumber : $ErrorDescription";
        $result = [PSCustomObject]@{ 
            Success          = $success;
            AccountReference = $aref
            AuditDetails     = $auditMessage;
            Account          = $aref; 
            PermissionReference = $pRef
        };            
        #send result back
        Write-Output $result | ConvertTo-Json -Depth 10
        return; 
    }      
    
    if ($null -ne $rowsetNode) {
        $nodePath = "ROW"
        $rowNodes = $rowsetNode.SelectNodes($nodePath)
        foreach($rowNode in $rowNodes)
        {
            $curObject = @{
                PERSONID = $rowNode.item("PERSON_ID").FirstChild.Value
                PERSONNAME = $rowNode.item("PERSON_NAME").FirstChild.Value
                SALARYNR =  $rowNode.item("EMPLOYEE_SALARYNR").FirstChild.Value
                ACCESSKEYID =  $rowNode.item("ACCESS_KEY_ID").FirstChild.Value  
                RCN =  $rowNode.item("ACCESS_KEYRCN").FirstChild.Value  
                VALID =  $rowNode.item("ACCESS_KEY_VALID").FirstChild.Value
            }  
            if($curObject.SALARYNR -eq $aref.EmployeeSalaryNR)
            {                       
                $accesskeyIdList += $curObject.ACCESSKEYID 
            }                       
        }
    }
}
else {
    $dummyAccesskeyId = "9999999999"
    $accesskeyIdList += $dummyAccesskeyId            
}
#close the session

$webservicePath = "xmlsql"
$headers = @{
    'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'          
    'Cookie' = $cookieString                       
}
$body = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><LOGOUT></LOGOUT>";
$splatWebRequestParameters = @{
    Uri = $config.urlXMLSQL + $webservicePath
    Method = 'Post'
    Headers = $headers                
    UseBasicParsing = $true              
    ContentType = 'text/xml;charset=ISO-8859-1' 
    Body = $body; 
    WebSession = $curSession                
} 

try{
    $requestResult = Invoke-WebRequest @splatWebRequestParameters  -ErrorAction SilentlyContinue  
}
catch{
    throw $_
}
#  Now in $accesskeyIdList we have collected the  accesskeys that must be deleted from the group 
#  however in Iprotect there is no index on both accesskeyid and keygroupid, so we cannot combine them in a single where clause
#  so we need first to query for de keykeygroupId to delete 
#  1)  so collect keykeygroup where accesskeyid, and filter on keygroupid to find keykeygroupid
#  2) next delete keykeygroup


foreach ($accesskeyId in  $accesskeyIdList){

    # First collect the keykeygroups of the access key
    $queryRequestResult=$null
    $KeyKeyGroupID_todelete = $null;
    $query = "SELECT KEYKEYGROUPID, KEYGROUPID, ACCESSKEYID  FROM keykeygroup WHERE keykeygroup.accesskeyid = $Accesskeyid";
    
    $queryType = 'query'
    switch ($queryType)
    {
        'query' {  $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><query><sql>$query</sql></query>"}                
        'update' { $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><update><sql>$query</sql></update>"}                 
    }

    $splatWebRequestParameters = @{
        Uri = $config.urlXMLSQL + $webservicePath
        Method = 'Post'
        Headers = $headers                
        UseBasicParsing = $true
        TimeoutSec = 60 
        MaximumRedirection = 0    
        Body = $queryBody;
        SessionVariable = 'curSession'
    } 
    
    if(-Not($offline -eq $true)) {

        try{
            $requestResult = Invoke-WebRequest @splatWebRequestParameters  -ErrorAction SilentlyContinue  
        }
        catch{
            throw $_
        } 
    }
    else 
    {
        $headers = @{ "Set-Cookie" = "dummycookie;blabla"}
        $requestResult = @{ Headers = $headers}
    }

    if($null -ne $requestResult.Headers) {
        if ($null -ne $requestResult.Headers["Set-Cookie"] ) {
            $authorizationCookie = $requestResult.Headers["Set-Cookie"]

            if ($authorizationCookie.IndexOf(";") -gt 0)
            {
                $cookieString = $authorizationCookie.Substring(0, $authorizationCookie.IndexOf(";"));
               
            }
        }
    }        
    # authenticate connection
    $webservicePath = 'j_security_check'
    $headers = @{
        'Content-Type' = "application/x-www-form-urlencoded" 
    }
    if ($null -ne $cookieString) {
        if ( $cookieString.length -gt 0) {
            $headers = @{
            'Content-Type' = "application/x-www-form-urlencoded" 
            'Cookie' = $cookieString
            }                       
        }
    }

    $body = "&j_username=$($config.UserName)&j_password=$($config.Password)" 
    
    $splatWebRequestParameters = @{
        Uri = $config.urlXMLSQL + $webservicePath
        Method = 'Post'
        Headers = $headers                
        UseBasicParsing = $true
        MaximumRedirection = 0    
        Body = $body;     
        WebSession = $curSession        
    }       
    if(-Not($offline -eq $true)) {
        try{
            $requestResult = Invoke-WebRequest @splatWebRequestParameters    -ErrorAction SilentlyContinue              
        }
        catch{
            throw $_
        }
    }
    else {
        $requestResult = @{StatusCode = 302}                    
    }

    if ($requestResult.StatusCode -eq 302){
        #authentication success
    }
    else {
        $success = $false            
        $auditMessage = "iprotect query for person " + $p.ExternalId + ". Authentication failed with error $($requestResult.StatusCode)";
        $result = [PSCustomObject]@{ 
            Success          = $success;
            AccountReference = $aref
            AuditDetails     = $auditMessage;
            Account          = $aref; 
        };            
        #send result back
        Write-Output $result | ConvertTo-Json -Depth 10
        return; 
    }

    # execute query and fetch results       
        
    $webservicePath = "xmlsql"
    $headers = @{
        'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'          
        'Cookie' = $cookieString                       
    }
    $splatWebRequestParameters = @{
        Uri = $config.urlXMLSQL + $webservicePath
        Method = 'Post'
        Headers = $headers                
        UseBasicParsing = $true  
        MaximumRedirection = 0                
        ContentType = 'text/xml;charset=ISO-8859-1' 
        Body = $queryBody; 
        WebSession = $curSession                
    }             
    if(-Not($offline -eq $true)){

        try{
            $queryRequestResult = Invoke-WebRequest @splatWebRequestParameters      
        }
        catch{
            throw $_
        }     

        [xml] $IprotectDataxml = $queryRequestResult.Content  
        $resultNode = $IprotectDataxml.item("RESULT")  
        
        
        $nodePath = "ERROR"
        $ErrorNode =  $resultNode.SelectSingleNode($NodePath) 
        if ($null -ne $ErrorNode) {
            $success = $false
            $ErrorDescription = $ErrorNode.item("DESCRIPTION").FirstChild.Value
            $ErrorNumber =   $ErrorNode.item("NUMBER").FirstChild.Value
            $auditMessage = "iprotect permission update query for person " + $p.ExternalId + " failed with error $ErrorNumber : $ErrorDescription";
            $result = [PSCustomObject]@{ 
                Success          = $success;
                AccountReference = $aref
                AuditDetails     = $auditMessage;
                Account          = $aref; 
            };            
            #send result back
            Write-Output $result | ConvertTo-Json -Depth 10
            return;  

        }
        $nodePath = "ROWSET" 
        $rowsetNode = $resultNode.SelectSingleNode($nodePath)       
        if ($null -ne $rowsetNode) {
            $nodePath = "ROW"
            $rowNodes = $rowsetNode.SelectNodes($nodePath)
            foreach($rowNode in $rowNodes)
            {
                $curObject = @{
                    KEYKEYGROUPID = $rowNode.item("KEYKEYGROUPID").FirstChild.Value
                    KEYGROUPID = $rowNode.item("KEYGROUPID").FirstChild.Value                       
                    ACCESSKEYID =  $rowNode.item("ACCESSKEYID").FirstChild.Value                       
                }  
                if($curObject.KEYGROUPID -eq $pRef.Identification.KEYGROUPID)
                {                       
                    $KeyKeyGroupID_todelete = $curObject.KEYKEYGROUPID
                    break 
                }                       
            }
        } 
    }  

    #close the session

    $webservicePath = "xmlsql"
    $headers = @{
        'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'          
        'Cookie' = $cookieString                       
    }
    $body = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><LOGOUT></LOGOUT>";
    $splatWebRequestParameters = @{
        Uri = $config.urlXMLSQL + $webservicePath
        Method = 'Post'
        Headers = $headers                
        UseBasicParsing = $true              
        ContentType = 'text/xml;charset=ISO-8859-1' 
        Body = $body; 
        WebSession = $curSession                
    } 
    if(-Not($offline -eq $true)){
        try{
            $requestResult = Invoke-WebRequest @splatWebRequestParameters      
        }
        catch{
            throw $_
        }
    }

    #now in KeyKeyGroupID_todelete is the entry that should be deleted

    if ($null -ne $KeyKeyGroupID_todelete)
    {
        $query = "DELETE FROM keykeygroup WHERE keykeygroupid=$KeyKeyGroupID_todelete"						    
        $queryType = 'update'
        switch ($queryType)
        {
            'query' {  $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><query><sql>$query</sql></query>"}                
            'update' { $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><update><sql>$query</sql></update>"}                 
        }

        $splatWebRequestParameters = @{
            Uri = $config.urlXMLSQL + $webservicePath
            Method = 'Post'
            Headers = $headers                
            UseBasicParsing = $true
            TimeoutSec = 60 
            MaximumRedirection = 0    
            Body = $queryBody;
            SessionVariable = 'curSession'
        } 
        
        if(-Not($offline -eq $true)) {

            try{
                $requestResult = Invoke-WebRequest @splatWebRequestParameters  -ErrorAction SilentlyContinue 
            }
            catch{
                throw $_
            } 
        }
        else 
        {
            $headers = @{ "Set-Cookie" = "dummycookie;blabla"}
            $requestResult = @{ Headers = $headers}
        }

        if($null -ne $requestResult.Headers) {
            if ($null -ne $requestResult.Headers["Set-Cookie"] ) {
                $authorizationCookie = $requestResult.Headers["Set-Cookie"]

                if ($authorizationCookie.IndexOf(";") -gt 0)
                {
                    $cookieString = $authorizationCookie.Substring(0, $authorizationCookie.IndexOf(";"));
                   
                }
            }
        }        
        # authenticate connection
        $webservicePath = 'j_security_check'
        $headers = @{
            'Content-Type' = "application/x-www-form-urlencoded" 
        }
        if ($null -ne $cookieString) {
            if ( $cookieString.length -gt 0) {
                $headers = @{
                'Content-Type' = "application/x-www-form-urlencoded" 
                'Cookie' = $cookieString
                }                       
            }
        }
    
        $body = "&j_username=$($config.UserName)&j_password=$($config.Password)" 
        
        $splatWebRequestParameters = @{
            Uri = $config.urlXMLSQL + $webservicePath
            Method = 'Post'
            Headers = $headers                
            UseBasicParsing = $true
            MaximumRedirection = 0    
            Body = $body;     
            WebSession = $curSession        
        }       
        if(-Not($offline -eq $true)) {
            try{
                $requestResult = Invoke-WebRequest @splatWebRequestParameters    -ErrorAction SilentlyContinue             
            }
            catch{
                throw $_
            }
        }
        else {
            $requestResult = @{StatusCode = 302}                    
        }

        if ($requestResult.StatusCode -eq 302){
            #authentication success
        }
        else {
            $success = $false            
            $auditMessage = "iprotect query for person " + $p.ExternalId + ". Authentication failed with error $($requestResult.StatusCode)";
            $result = [PSCustomObject]@{ 
                Success          = $success;
                AccountReference = $aref
                AuditDetails     = $auditMessage;
                Account          = $aref; 
            };            
            #send result back
            Write-Output $result | ConvertTo-Json -Depth 10
            return; 
        }

        # execute query and fetch results
        
            
        $webservicePath = "xmlsql"
        $headers = @{
            'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'          
            'Cookie' = $cookieString                       
        }
        $splatWebRequestParameters = @{
            Uri = $config.urlXMLSQL + $webservicePath
            Method = 'Post'
            Headers = $headers                
            UseBasicParsing = $true  
            MaximumRedirection = 0                
            ContentType = 'text/xml;charset=ISO-8859-1' 
            Body = $queryBody; 
            WebSession = $curSession                
        }             
        if(-Not($dR -eq $true)){

            try{
                $queryRequestResult = Invoke-WebRequest @splatWebRequestParameters      
            }
            catch{
                throw $_
            }     

            [xml] $IprotectDataxml = $queryRequestResult.Content  
            $resultNode = $IprotectDataxml.item("RESULT")          
            
            $nodePath = "ERROR"
            $ErrorNode =  $resultNode.SelectSingleNode($NodePath) 
            if ($null -ne $ErrorNode) {
                $success = $false
                $ErrorDescription = $ErrorNode.item("DESCRIPTION").FirstChild.Value
                $ErrorNumber =   $ErrorNode.item("NUMBER").FirstChild.Value
                $auditMessage = "iprotect permission update query for person " + $p.ExternalId + " failed with error $ErrorNumber : $ErrorDescription";
                $result = [PSCustomObject]@{ 
                    Success          = $success;
                    AccountReference = $aref
                    AuditDetails     = $auditMessage;
                    Account          = $aref; 
                };            
                #send result back
                Write-Output $result | ConvertTo-Json -Depth 10
                return;  

            }  
        }             
        
        #close the session

        $webservicePath = "xmlsql"
        $headers = @{
            'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'          
            'Cookie' = $cookieString                       
        }
        $body = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><LOGOUT></LOGOUT>";
        $splatWebRequestParameters = @{
            Uri = $config.urlXMLSQL + $webservicePath
            Method = 'Post'
            Headers = $headers                
            UseBasicParsing = $true              
            ContentType = 'text/xml;charset=ISO-8859-1' 
            Body = $body; 
            WebSession = $curSession                
        } 
        if(-Not($offline -eq $true)){
            try{
                $requestResult = Invoke-WebRequest @splatWebRequestParameters      
            }
            catch{
                throw $_
            }
        }

    }
}

$success = $true
$auditMessage = "iprotect account revoke  $($pRef.DisplayName) for person " + $p.ExternalId + " succeeded";    
$result = [PSCustomObject]@{ 
    Success          = $success;
    AccountReference = $aref
    AuditDetails     = $auditMessage;   
    Account          = $aref; 
    PermissionReference = $pRef        
};

#send result back
Write-Output $result | ConvertTo-Json -Depth 10





