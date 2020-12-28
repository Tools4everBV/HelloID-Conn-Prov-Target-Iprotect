$config = ConvertFrom-Json $configuration
$dR = $dryRun |  ConvertFrom-Json  
$p = $person | ConvertFrom-Json;

$success = $false;
$auditMessage = "iprotect identity for person " + $p.DisplayName + " not updated successfully";

$account = [PSCustomObject]@{           
    
    EmployeeSalaryNR = $p.ExternalId
    # expected time format "yyyy/MM/dd HH:mm:ss"
    EmployeeHireDate = ""
    EmployeeTerminationDate = ""
    EmployeeBirthDate = ""
    EmployeeLanguage =""
    PersonName = $p.Name.FamilyName
    PersonFirstName =$p.Name.GivenName
    PersonPrefix = ""
    PersonHomeAddress = ""
    PersonHomeCity = ""
    PersonHomeZip = ""
    DepartmentName = ""
    AccesskeyRCN = $p.Custom.AccesskeyRCN
}

if ([Net.ServicePointManager]::SecurityProtocol -notmatch "Tls12") {
    [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
}

[string] $arguments = "<ARGUMENTS>"
$arguments +=           "<LOGINNAME>$($config.Username)</LOGINNAME>"
$arguments +=           "<PASSWORD>$($config.Password)</PASSWORD>"
$arguments +=           "<FILETYPE>XML</FILETYPE>"
$arguments +=           "<FUNCTION-NAME>employee-data</FUNCTION-NAME>"
$arguments +=           "<FUNCTION-GROUP>Import</FUNCTION-GROUP>"
$arguments +=           "<COLUMNNAME-SYNTAX>Extended</COLUMNNAME-SYNTAX>"
$arguments +=           "<SELECT-USERDEFINED>Number</SELECT-USERDEFINED>"
$arguments +=         "</ARGUMENTS>"

$dataXML =      "<DATA>"
$dataXML +=         "<ROW>"
    $dataXML +=         "<OPERATION>1</OPERATION>"
    $dataXML +=         "<EMPLOYEE_SALARYNR><![CDATA[$($account.EmployeeSalaryNR)]]></EMPLOYEE_SALARYNR>"
#  $dataXML +=         "<EMPLOYEE_HIREDATE><![CDATA[$($account.EmployeeHireDate)]]></EMPLOYEE_HIREDATE>"
#  $dataXML +=         "<EMPLOYEE_TERMINATIONDATE><![CDATA[$($account.EmployeeTerminationDate)]]></EMPLOYEE_TERMINATIONDATE>" 
#  $dataXML +=         "<EMPLOYEE_BIRTHDATE><![CDATA[$($account.EmployeeBirthDate)]]></EMPLOYEE_BIRTHDATE>"
#  $dataXML +=         "<EMPLOYEE_LANGUAGE><![CDATA[$($account.EmployeeLanguage)]]></EMPLOYEE_LANGUAGE>"
    $dataXML +=         "<PERSON_NAME><![CDATA[$($account.PersonName)]]></PERSON_NAME>"
    $dataXML +=         "<PERSON_FIRSTNAME><![CDATA[$($account.PersonFirstName)]]></PERSON_FIRSTNAME>"
#  $dataXML +=         "<PERSON_PREFIX><![CDATA[$($account.PersonPrefix)]]></PERSON_PREFIX>"
#  $dataXML +=         "<PERSON_HOMEADDRESS><![CDATA[$($account.PersonHomeAddress)]]></PERSON_HOMEADDRESS>"
#  $dataXML +=         "<PERSON_HOMECITY><![CDATA[$($account.PersonHomeCity)]]></PERSON_HOMECITY>"
#  $dataXML +=         "<PERSON_HOMEZIP><![CDATA[$($account.PersonHomeZip)]]></PERSON_HOMEZIP>" 
#  $dataXML +=         "<DEPARTMENT_NAME><![CDATA[$($account.DepartmentName)]]></DEPARTMENT_NAME>"
if ($null -ne $account.AccesskeyRCN){
    $dataXML +=         "<ACCESSKEY_RCN><![CDATA[$($account.AccesskeyRCN)]]></ACCESSKEY_RCN>"}
$dataXML +=         "</ROW>"
$dataXML +=     "</DATA>"

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
if(-Not($dR -eq $true)) {

    try{
        $requestResult = Invoke-WebRequest @splatWebRequestParameters  
            
        if (($Requestresult.StatusCode -gt 199) -and ($Requestresult.StatusCode -lt 300 )){
            $success = $true;
            $auditMessage = "iprotect identity for person " + $person.ExternalId + " created successfully";     
        }
        else
        {
            $success = $false;
            $auditMessage = "iprotect identity for person " + $person.ExternalId + "create failed with error $($Requestresult.StatusCode) : $($Rquestresult.StatusDescription)";                 
        }

        [xml] $requestContent = $requestResult.Content;
        $rootNode = $RequestContent.item("ROOT") 
        if ($null -ne $rootNode)
        {
            $nodePath = "ERROR"            
            $errorNode =  $rootNode.SelectSingleNode($nodePath) 
            if ($null -ne $ErrorNode) {
                $success = $false;
                $errorDescription = $ErrorNode.item("DESCRIPTION").FirstChild.Value
                $errorNumber =   $ErrorNode.item("NUMBER").FirstChild.Value
                $auditMessage = "iprotect identity for person " + $p.externalId + "create failed with error $errorNumber : $errorDescription";
            }           
        }   
    }
    catch{
        throw $_
    }
}

$result = [PSCustomObject]@{ 
    Success          = $success;
    AccountReference = @{   EmployeeSalaryNR = $account.EmployeeSalaryNR
                            PersonName = $account.PersonName}
    AuditDetails     = $auditMessage;
    Account          = $account; 
};

#send result back
Write-Output $result | ConvertTo-Json -Depth 10

