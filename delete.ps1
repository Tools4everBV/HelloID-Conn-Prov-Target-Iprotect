$aRef = $accountReference | ConvertFrom-Json   
$config = ConvertFrom-Json $configuration
$dR = $dryRun |  ConvertFrom-Json  
$p = $person | ConvertFrom-Json;

if ($dR -eq $true){
    $aRef = @{   EmployeeSalaryNR = $p.ExternalId
        PersonName = $p.Name.FamilyName 
    }          
}

$success = $false;
$auditMessage = "Iprotect identity for person " + $p.DisplayName + " not updated successfully";

$account = [PSCustomObject]@{           
    
    EmployeeSalaryNR = $aRef.EmployeeSalaryNR
    EmployeeHireDate = ""
    EmployeeTerminationDate = ""
    EmployeeBirthDate = ""
    EmployeeLanguage =""
    PersonName = $aRef.PersonName
    PersonFirstName =""
    PersonPrefix = ""
    PersonHomeAddress = ""
    PersonHomeCity = ""
    PersonHomeZip = ""
    DepartmentName = ""
}

if ([Net.ServicePointManager]::SecurityProtocol -notmatch "Tls12") {
    [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
}

[string] $arguments = "<ARGUMENTS>"
$arguments +=           "<LOGINNAME>$($config.Username)</LOGINNAME>"
$arguments +=           "<PASSWORD>$($config.Password)</PASSWORD>"
$arguments +=           "<FILETYPE>XML</FILETYPE>";
$arguments +=           "<FUNCTION-NAME>employee-data</FUNCTION-NAME>";
$arguments +=           "<FUNCTION-GROUP>Import</FUNCTION-GROUP>";
$arguments +=           "<COLUMNNAME-SYNTAX>Extended</COLUMNNAME-SYNTAX>";
$arguments +=           "<SELECT-USERDEFINED>Number</SELECT-USERDEFINED>";
$arguments +=         "</ARGUMENTS>";

$dataXML =      "<DATA>"
$dataXML +=         "<ROW>";
$dataXML +=             "<OPERATION>3</OPERATION>"
$dataXML +=             "<EMPLOYEE_SALARYNR><![CDATA[$($account.EmployeeSalaryNR)]]></EMPLOYEE_SALARYNR>" 
$dataXML +=             "<PERSON_NAME><![CDATA[$($account.PersonName)]]></PERSON_NAME>"   
$dataXML +=         "</ROW>";
$dataXML +=     "</DATA>";

$postXML = "<ROOT>$($arguments)$($dataXml)</ROOT>";
$headers = @{
    'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'                        
}

$splatWebRequestParameters = @{
    Uri = $config.UrlUser  
    Method = 'Post'
    Headers = $headers                
    UseBasicParsing = $true  
    MaximumRedirection = 0 
    TimeoutSec = 15                
    ContentType = 'text/xml;charset=ISO-8859-1' 
    Body = $postXML; 
    WebSession = $curSession                
}
if(-Not($DryRun -eq $true))
{
    try{
        $requestResult = Invoke-WebRequest @splatWebRequestParameters  
    
        if (($Requestresult.StatusCode -gt 199) -and ($Requestresult.StatusCode -lt 300 )){
            $success = $true;
            $auditMessage = "iprotect identity for person " + $p.ExternalId + " deleted successfully";     
        }
        else
        {
            $success = $false;
            $auditMessage = "iprotect identity for person " + $p.ExternalId + "delete failed with error $($requestresult.StatusCode) : $($requestresult.StatusDescription)";                 
        }

        [xml] $RequestContent = $Requestresult.Content;
        $RootNode = $RequestContent.item("ROOT") 
        if ($null -ne $RootNode){
            $NodePath = "ERROR"
            $ErrorNode =  $RootNode.SelectSingleNode($NodePath) 
            if ($null -ne $ErrorNode) {
                $success = $false;
                $ErrorDescription = $ErrorNode.item("DESCRIPTION").FirstChild.Value
                $ErrorNumber =   $ErrorNode.item("NUMBER").FirstChild.Value
                $auditMessage = "iprotect identity for person " + $p.externalId + "delete failed with error $ErrorNumber : $ErrorDescription";
            }
        } 
    }
    catch{
        throw $_
    }
}   

$result = [PSCustomObject]@{ 
    Success          = $success;
    AccountReference = $aRef;
    AuditDetails     = $auditMessage;
    Account          = $account; 
};

#send result back
Write-Output $result | ConvertTo-Json -Depth 10
