
$config = ConvertFrom-Json $configuration      
$dR = $dryRun |  ConvertFrom-Json  
$offline = $dR    

$success = $false;        
$auditMessage = "iprotect keygroups not collected successfully";
$permissionList = [System.Collections.ArrayList]::new();
        
if ([Net.ServicePointManager]::SecurityProtocol -notmatch "Tls12") {
    [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
}

#  query iprotect to get the list of accesskeys        
#  first retrieve the connection cookie, but also send the query 

$query = "SELECT KEYGROUPID, LOCALLINEID, HSID, NAME, CODE, NICKNAME, VISITORUSE, LOCALIDXID FROM keygroup"						

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
            $CookieString = $authorizationCookie.Substring(0, $authorizationCookie.IndexOf(";"));           
        }
    }
}        
# authenticate connection

$webservicePath = 'j_security_check'
$headers = @{
    'Content-Type' = "application/x-www-form-urlencoded" 
}
if ($null -ne $CookieString ) {
    if ( $CookieString.length -gt 0) {
        $headers = @{
        'Content-Type' = "application/x-www-form-urlencoded" 
        'Cookie' = $CookieString
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
    $auditMessage = "iprotect query authentication failed with error $($requestResult.StatusCode)";
    $result = [PSCustomObject]@{ 
        Success          = $success;       
        AuditDetails     = $auditMessage;       
    };            
    #send result back
    Write-Output $result | ConvertTo-Json -Depth 10
    return; 
}

# execute query and fetch results       
    
$webservicePath = "xmlsql"
$headers = @{
    'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'          
    'Cookie' = $CookieString                       
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
        $auditMessage = "iprotect query for collecting permissions failed with error $ErrorNumber : $ErrorDescription";
        $result = [PSCustomObject]@{
            ErrorNumber     = $ErrorNumber
            ErrorDescription =  $ErrorDescription
            Success          = $success;                   
            AuditDetails     = $auditMessage;                   
        };            
        #send result back
        throw ($result)        
    }  

    if ($null -ne $rowsetNode) {
        $nodePath = "ROW"
        $rowNodes = $rowsetNode.SelectNodes($nodePath)
        foreach($rowNode in $rowNodes) {
            $curObject = @{
                KEYGROUPID = $rowNode.item("KEYGROUPID").FirstChild.Value
                LOCALLINEID = $rowNode.item("LOCALLINEID").FirstChild.Value
                HSID =  $rowNode.item("HSID").FirstChild.Value
                CODE =  $rowNode.item("CODE").FirstChild.Value
                NAME =  $rowNode.item("NAME").FirstChild.Value      
                NICKNAME =  $rowNode.item("NICKNAME").FirstChild.Value    
                VISITORUSE =  $rowNode.item("VISITORUSE").FirstChild.Value    
                LOCALIDXID =  $rowNode.item("LOCALIDXID").FirstChild.Value             
            }

            $curPermission = @{
                DisplayName = $curObject.NAME;
                Identification = $curObject
                
            }                       
            $permissionList.add($curPermission) > $null
        }
    }
}
else {
    $curObject = @{
    KEYGROUPID = "dummyKEYGROUPID"
    LOCALLINEID = "dummyLOCALLINEID"
    HSID = "dummyHSID"
    CODE =  "dummyCODE"
    NAME =  "dummyNAME"  
    NICKNAME =  "dummyNICKNAME"  
    VISITORUSE = "dummyVISITORUSE" 
    LOCALIDXID =  "dummyLOCALIDXID"           
    }

    $curPermission = @{
        DisplayName = $curObject.NAME;
        Identification = $curObject
        
    }                       
    $permissionList.add($curPermission) > $null
 }
#close the session

$webservicePath = "xmlsql"
$headers = @{
    'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'          
    'Cookie' = $CookieString                       
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

write-output $permissionList | ConvertTo-Json -Depth 10;

