#################################################
# HelloID-Conn-Prov-Target-IProtect-Create
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
function Resolve-IProtectError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
            # Make sure to inspect the error result object and add only the error message as a FriendlyMessage.
            # $httpErrorObj.FriendlyMessage = $errorDetailsObject.message
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails # Temporarily assignment
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-JSessionID {
    [CmdletBinding()]
    param ()

    $splatParams = @{
        Uri                = "$($actionContext.Configuration.BaseUrl)/xmlsql"
        Method             = 'Post'
        Headers            = @{
            'Content-Type' = 'application/x-www-form-urlencoded'
        }
        UseBasicParsing    = $true
        TimeoutSec         = 60
        MaximumRedirection = 0
        SessionVariable    = 'WebSession'
    }
    try {
        Write-Information 'Getting Get-JSessionID'
        $requestResult = Invoke-WebRequest @splatParams -ErrorAction SilentlyContinue
        if ($null -ne $requestResult.Headers) {
            if ($null -ne $requestResult.Headers['Set-Cookie'] ) {
                $authorizationCookie = $requestResult.Headers['Set-Cookie']

                if ($authorizationCookie.IndexOf(';') -gt 0) {
                    $jSessionId = $authorizationCookie.Substring(0, $authorizationCookie.IndexOf(';'))
                }
            }
        }
        Write-Output $WebSession, $jSessionId
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Confirm-AuthenticationResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $JSessionID,

        [Parameter(Mandatory)]
        $WebSession
    )
    Write-Information 'Authenticate with the IProtect'
    $encodedPassword = [System.Web.HttpUtility]::UrlEncode($actionContext.Configuration.Password)
    $splatParams = @{
        Uri                = "$($actionContext.Configuration.BaseUrl)/j_security_check"
        Method             = 'POST'
        Headers            = @{
            'Content-Type' = 'application/x-www-form-urlencoded'
            'Cookie'       = $JSessionID
        }
        UseBasicParsing    = $true
        MaximumRedirection = 0
        Body               = "&j_username=$($actionContext.Configuration.UserName)&j_password=$encodedPassword"
        WebSession         = $WebSession
    }
    try {
        $authenticationResult = Invoke-WebRequest @splatParams -ErrorAction SilentlyContinue
        if ($authenticationResult.Headers.Location -like '*Webcontrols/login_error.html') {
            throw 'Authentication failed with error [Invalid username and/or password or not licensed]'
        }
        if (-Not ($authenticationResult.StatusCode -eq 302)) {
            throw "Authentication failed with error [$($authenticationResult.StatusCode)]"
        }
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Invoke-IProtectQuery {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $JSessionID,

        [Parameter()]
        $WebSession,

        [Parameter()]
        [string]
        $Query,

        [Parameter()]
        [string]
        $QueryType
    )
    if ($null -eq $JSessionID ) {
        throw 'JSessionID parameter is required to execute the query'
    }
    if ($null -eq $WebSession) {
        throw 'WebSession parameter is required to execute the query'
    }
    if ($null -eq $Query) {
        throw 'Query parameter is required to execute the query'
    }
    if ($null -eq $QueryType) {
        throw 'QueryType is required to execute the query'
    }
    switch ($QueryType) {
        'query' { $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><query><sql>$($query)</sql></query>" }
        'update' { $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><update><sql>$($query)</sql></update>" }
    }

    $splatParams = @{
        Uri                = "$($actionContext.Configuration.BaseUrl)/xmlsql"
        Method             = 'POST'
        Headers            = @{
            'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'
            'Cookie' = $JSessionID
        }
        UseBasicParsing    = $true
        MaximumRedirection = 0
        ContentType        = 'text/xml;charset=UTF-8'
        Body               = $queryBody
        WebSession         = $WebSession
    }

    try {
        $queryResult = Invoke-WebRequest @splatParams -Verbose:$false
        switch ($queryType) {
            'query' {
                if ($queryResult.Content -ne $null) {
                    if ($queryResult.Content -is [byte[]]) {
                        $contentString = [System.Text.Encoding]::UTF8.GetString($queryResult.Content)
                    }
                    else {
                        $contentString = $queryResult.Content
                    }
                    [xml]$xmlResult = $contentString
                    $resultNode = $xmlResult.RESULT
                    $errorNode = $resultNode.SelectSingleNode('ERROR')
                    if ($null -ne $errorNode) {
                        $errorDescription = $errorNode.DESCRIPTION
                        if ($null -ne $errorDescription) {
                            throw $errorDescription
                        }
                        else {
                            throw "An error occurred but no description was found."
                        }
                    }
                    $rowSetNode = $resultNode.SelectSingleNode('ROWSET')
                    if ($null -ne $rowSetNode) {
                        $rowNodes = $rowSetNode.SelectNodes('ROW')
                        if ($rowNodes.Count -gt 0) {
                            foreach ($row in $rowNodes) {
                                $rowData = @{}
                                foreach ($childNode in $row.ChildNodes) {
                                    $rowData[$childNode.Name] = $childNode.InnerText
                                }
                                $rowDataObject = [PSCustomObject]$rowData
                                Write-Output $rowDataObject
                            }
                        }
                        else {
                            Write-Output $null
                        }
                    }
                }
            }
            'update' {
                [xml] $xmlResult = $queryResult
                $resultNode = $xmlResult.item('RESULT')
                $errorNode = $resultNode.SelectSingleNode('ERROR')
                if ($null -ne $errorNode) {
                    throw $errorNode.DESCRIPTION
                }
                Write-Output $resultNode
            }
        }
    }
    catch {
        Write-Warning "Query: $query"
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Invoke-Logout {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $JSessionID,
        
        [Parameter()]
        $WebSession
    )

    $headers = @{
        'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'
        'Cookie' = $JSessionID
    }
    $body = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><LOGOUT></LOGOUT>"
    $splatWebRequestParameters = @{
        Uri             = $actionContext.Configuration.BaseUrl + "/xmlsql"
        Method          = 'Post'
        Headers         = $headers
        UseBasicParsing = $true
        ContentType     = 'text/xml;charset=ISO-8859-1'
        Body            = $body
        WebSession      = $WebSession
    }
    try {
        $null = Invoke-WebRequest @splatWebRequestParameters -Verbose:$false -ErrorAction SilentlyContinue
    }
    catch {
        # Logout failure is not critical, so only log"
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Message = "Warning, IProtect logout failed error: $($_)"
                IsError = $false
            })
    }
}

function Get-IProtectDepartment {
    param (
        [Parameter()]
        [string]
        $JSessionID,

        [Parameter()]
        $WebSession,

        [ValidateNotNullOrEmpty()]
        [Object]
        [ref]$Account,

        [Parameter()]
        $WhenDepartmentNotFound
    )

    # Check if DepartmentId is empty
    if ([string]::IsNullOrEmpty($Account.DepartmentId)) {
        if ($WhenDepartmentNotFound -eq 'Error') {
            # Error, no department in lookup value = throw error
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "The lookup value for Department is empty and the connector is configured to stop when this happens."
                    IsError = $true
                })
        }
        else {
            # Clear, no department in lookup value = clear value
            Write-Information "Clearing department. (whenDepartmentNotFound = Clear)"
            $Account.DepartmentId = $null
        }
        return
    }

    # Replace special characters in department name to avoid query issues
    $departmentName = $Account.DepartmentId
    $departmentName = $departmentName -replace "'", "`\`'"
    $departmentName = $departmentName -replace "&", "&amp;"

    # Lookup Value is filled in, lookup value in IProtect
    $queryGetDepartments = "
        SELECT
            TABLEDEPARTMENT.DEPARTMENTID as DEPARTMENTID,
            TABLEDEPARTMENT.NAME as DEPARTMENTNAME
        FROM department TABLEDEPARTMENT
        WHERE TABLEDEPARTMENT.NAME = '$departmentName'"

    $splatGetDepartments = @{
        JSessionID = $jSessionID
        WebSession = $webSession
        Query      = $queryGetDepartments
        QueryType  = 'query'
    }

    $department = Invoke-IProtectQuery @splatGetDepartments
    
    # When department is not found in IProtect
    if ([string]::IsNullOrEmpty($department.DEPARTMENTID)) {
        if ($WhenDepartmentNotFound -eq 'Error') {
            # Error, department not found = throw error
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Department [$($Account.DepartmentId)] not found in IProtect and the connector is configured to stop when this happens."
                    IsError = $true
                })
        }
        else {
            # Clear, department not found = clear value
            Write-Information "Department [$($Account.DepartmentId)] not found in IProtect, clearing value. (whenDepartmentNotFound = Clear)"
            $Account.DepartmentId = $null
        }
    }
    else {
        # Department is found in IProtect, set in IProtect
        $Account.DepartmentId = $department.DEPARTMENTID
    }
}

function Get-IProtectAutorizationGroup {
    param (
        [Parameter()]
        [string]
        $JSessionID,

        [Parameter()]
        $WebSession,

        [ValidateNotNullOrEmpty()]
        [Object]
        [ref]$Account,

        [Parameter()]
        $WhenAuthorizationGroupNotFound
    )

    # Check if HsId is empty
    if ([string]::IsNullOrEmpty($Account.HsId)) {
        if ($WhenAuthorizationGroupNotFound -eq 'Error') {
            # Error, no authorization group in lookup value = throw error
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "The lookup value for Authorization Group (HsId) is empty and the connector is configured to stop when this happens."
                    IsError = $true
                })
        }
        else {
            # Clear, no authorization group in lookup value = clear value
            Write-Information "Clearing authorization group. (whenAuthorizationGroupNotFound = Clear)"
            $Account.HsId = $null
        }
        return
    }
   
    # Lookup Value is filled in, lookup value in IProtect
    $queryGetHsGroup = "
        SELECT
            TABLEHSGROUP.HSGROUPID as HSGROUPID,
            TABLEHSGROUP.NAME as HSGROUPNAME
        FROM hsgroup TABLEHSGROUP
        WHERE TABLEHSGROUP.NAME = '$($Account.HsId)'"

    $splatGetHsGroup = @{
        JSessionID = $jSessionID
        WebSession = $webSession
        Query      = $queryGetHsGroup
        QueryType  = 'query'
    }

    $hsgroup = Invoke-IProtectQuery @splatGetHsGroup
    
    # When autorization group is not found in IProtect
    if ([string]::IsNullOrEmpty($hsgroup.HSGROUPID)) {
        if ($WhenAuthorizationGroupNotFound -eq 'Error') {
            # Error, authorization group not found = throw error
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "HsGroup [$($Account.HsId)] not found in IProtect and the connector is configured to stop when this happens."
                    IsError = $true
                })
        }
        else {
            # Clear, authorization group not found = clear value
            Write-Information "HsGroup [$($Account.HsId)] not found in IProtect, clearing value. (whenAuthorizationGroupNotFound = Clear)"
            $Account.HsId = $null
        }
    }
    else {
        # Autorization group is found in IProtect, set in IProtect
        $Account.HsId = $hsgroup.HSGROUPID
    }
}

function Get-IProtectFreeSelectField {
    param (
        [Parameter()]
        [string]
        $JSessionID,

        [Parameter()]
        $WebSession,

        [ValidateNotNullOrEmpty()]
        [Object]
        [ref]$Account,

        [Parameter()]
        [string]
        $Field,

        [Parameter()]
        $WhenFreeSelectFieldNotFound
    )

    # Check if field value is empty
    if ([string]::IsNullOrEmpty($Account.$Field)) {
        if ($WhenFreeSelectFieldNotFound -eq 'Error') {
            # Error, no value in lookup field = throw error
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "The lookup value for $Field is empty and the connector is configured to stop when this happens."
                    IsError = $true
                })
        }
        else {
            # Clear, no value in lookup field = clear value
            Write-Information "Clearing $Field. (whenFreeSelectFieldNotFound = Clear)"
            $Account.$Field = $null
        }
        return
    }
   
    # Lookup Value is filled in, lookup value in IProtect    
    $queryGetCustomFields = "
        SELECT
            TABLECUSTOMTEXT.CUSTOMTEXTNR as CUSTOMTEXTNR,
            TABLECUSTOMTEXT.LAN1TEXT as LAN1TEXT,
            TABLECUSTOMTEXT.COLUMNNAME as COLUMNNAME
        FROM customtext TABLECUSTOMTEXT"

    $splatGetCustomFields = @{
        JSessionID = $jSessionID
        WebSession = $webSession
        Query      = $queryGetCustomFields
        QueryType  = 'query'
    }

    $customFields = Invoke-IProtectQuery @splatGetCustomFields

    $customField = $customFields | Where-object { $_.COLUMNNAME -eq ($Field.ToUpper()) -and $_.LAN1TEXT -eq $Account.$Field -and -not[String]::IsNullOrEmpty($_.CUSTOMTEXTNR) }

    # When custom field is not found in IProtect
    if ([string]::IsNullOrEmpty($customField.CUSTOMTEXTNR)) {
        if ($WhenFreeSelectFieldNotFound -eq 'Error') {
            # Error, freeselect field not found = throw error
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "$Field [$($Account.$Field)] not found in IProtect and the connector is configured to stop when this happens."
                    IsError = $true
                })
        }
        else {
            # Clear, freeselect field not found = clear value
            Write-Information "$Field [$($Account.$Field)] not found in IProtect, clearing value. (whenFreeSelectFieldNotFound = Clear)"
            $Account.$Field = $null
        }
    }
    else {
        # FreeSelect field is found in IProtect, set in IProtect
        $Account.$Field = $customField.CUSTOMTEXTNR
    }
}
#endregion

try {
    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'

    $webSession, $jSessionID = Get-JSessionID
    $null = Confirm-AuthenticationResult -JSessionID $jSessionID -WebSession $webSession

    # Validate correlation configuration
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationField = $actionContext.CorrelationConfiguration.AccountField
        $correlationValue = $actionContext.CorrelationConfiguration.PersonFieldValue

        if ([string]::IsNullOrEmpty($($correlationField))) {
            throw 'Correlation is enabled but not configured correctly'
        }
        if ([string]::IsNullOrEmpty($($correlationValue))) {
            throw 'Correlation is enabled but [accountFieldValue] is empty. Please make sure it is correctly mapped'
        }

        # Build dynamic FREETEXT and FREESELECT fields for query
        $freeFieldsSelect = [System.Collections.Generic.List[string]]::new()
        foreach ($property in $actionContext.Data.Person.PSObject.Properties) {
            if ($property.Name -match '^(FREETEXT|FREESELECT)\d+$') {
                $freeFieldsSelect.Add("TABLEPERSON.$($property.Name) AS $($property.Name)")
            }
        }
        $freeFieldsQuery = if ($freeFieldsSelect.Count -gt 0) { ($freeFieldsSelect -join ",`n        ") + "," } else { "" }

        $queryGetEmployee = "
        SELECT
        TABLEEMPLOYEE.PERSONID AS person_personId,
        TABLEPERSON.NAME AS person_Name,
        TABLEPERSON.FirstName AS person_FirstName,
        TABLEPERSON.Prefix AS person_Prefix,
        $freeFieldsQuery
        TABLEEMPLOYEE.BirthDate AS employee_BirthDate,
        TABLEEMPLOYEE.Language AS employee_Language,
        TABLEEMPLOYEE.EMPLOYEEID AS employee_employeeId,
        TABLEEMPLOYEE.SALARYNR AS employee_salaryNr,
        TABLEEMPLOYEE.HireDate AS employee_HireDate,
        TABLEEMPLOYEE.TerminationDate AS employee_TerminationDate
        FROM employee TABLEEMPLOYEE
            LEFT OUTER JOIN person TABLEPERSON ON TABLEPERSON.personID = TABLEEMPLOYEE.personID
        WHERE
            TABLEEMPLOYEE.SALARYNR = '$($correlationValue)'"

        Write-Information "Finding Employee with $correlationField [$($correlationValue)]"

        $splatGetEmployee = @{
            JSessionID = $jSessionID
            WebSession = $webSession
            Query      = $queryGetEmployee
            QueryType  = 'query'
        }

        $correlateEmployeeAccount = Invoke-IProtectQuery @splatGetEmployee

        $personObject = [PSCustomObject]@{}
        $employeeObject = [PSCustomObject]@{}
        if ($correlateEmployeeAccount ) {
            foreach ($property in $correlateEmployeeAccount.PSObject.Properties.Name) {
                if ($property.StartsWith('PERSON')) {
                    $PersonObject | Add-Member @{ $property.Replace('PERSON_', '') = $correlateEmployeeAccount.$property }
                }
                elseif ($property.StartsWith('EMPLOYEE')) {
                    $employeeObject | Add-Member  @{ $property.Replace('EMPLOYEE_', '') = $correlateEmployeeAccount.$property }
                }
            }
        }

        if (($correlateEmployeeAccount | Measure-Object).Count -eq 0) {
            Write-Information "No employee found. Check if only a person exsists"

            $queryGetPerson = "
            SELECT
            TABLEPERSON.PERSONID AS person_personId,
            TABLEPERSON.NAME AS person_Name,
            TABLEPERSON.FirstName AS person_FirstName,
            TABLEPERSON.Prefix AS person_Prefix,
            $freeFieldsQuery
            TABLEEMPLOYEE.BirthDate AS employee_BirthDate,
            TABLEEMPLOYEE.Language AS employee_Language,
            TABLEEMPLOYEE.EMPLOYEEID AS employee_employeeId,
            TABLEEMPLOYEE.SALARYNR AS employee_salaryNr,
            TABLEEMPLOYEE.HireDate AS employee_HireDate,
            TABLEEMPLOYEE.TerminationDate AS employee_TerminationDate
            FROM person TABLEPERSON
                LEFT OUTER JOIN employee TABLEEMPLOYEE ON TABLEEMPLOYEE.personID = TABLEPERSON.personID
            WHERE
                TABLEPERSON.NAME = '$($actionContext.Data.Person.Name)'
                AND TABLEPERSON.FIRSTNAME = '$($actionContext.Data.Person.FirstName)'
            "

            $splatGetUser = @{
                JSessionID = $jSessionID
                WebSession = $webSession
                Query      = $queryGetPerson
                QueryType  = 'query'
            }
            $personObject = Invoke-IProtectQuery @splatGetUser
            $correlatedPersonAccount = $personObject | Where-Object { $_.EMPLOYEE_EMPLOYEEID -eq "" }            
        }
    }

    if ($actionContext.Data.Person.PSObject.Properties.Name -Contains 'DepartmentId') {
        $splatGetDepartment = @{
            JSessionID             = $jSessionID
            WebSession             = $webSession
            Account                = [ref]$actionContext.Data.Person
            WhenDepartmentNotFound = $actionContext.Configuration.whenDepartmentNotFound
        }
        Get-IProtectDepartment @splatGetDepartment
    }

    if ($actionContext.Data.Person.PSObject.Properties.Name -Contains 'HsId') {
        $splatGetHsGroup = @{
            JSessionID                     = $jSessionID
            WebSession                     = $webSession
            Account                        = [ref]$actionContext.Data.Person
            WhenAuthorizationGroupNotFound = $actionContext.Configuration.whenAuthorizationGroupNotFound
        }
        Get-IProtectAutorizationGroup  @splatGetHsGroup
    }

    # Dynamically process all FREESELECT fields in Person
    foreach ($property in $actionContext.Data.Person.PSObject.Properties) {
        if ($property.Name -match '^FREESELECT\d+$') {
            $splatGetFreeSelect = @{
                JSessionID                  = $jSessionID
                WebSession                  = $webSession
                Account                     = [ref]$actionContext.Data.Person
                Field                       = $property.Name
                WhenFreeSelectFieldNotFound = $actionContext.Configuration.whenFreeSelectFieldNotFound
            }
            Get-IProtectFreeSelectField @splatGetFreeSelect
        }
    }

    if ($actionContext.Data.Employee.PSObject.Properties.Name -Contains 'HsId') {
        $splatGetHsGroup = @{
            JSessionID                     = $jSessionID
            WebSession                     = $webSession
            Account                        = [ref]$actionContext.Data.Employee
            WhenAuthorizationGroupNotFound = $actionContext.Configuration.whenAuthorizationGroupNotFound
        }
        Get-IProtectAutorizationGroup  @splatGetHsGroup
    }

    # Check if any lookups failed before proceeding
    if ($outputContext.AuditLogs.IsError -contains $true) {
        throw "Error(s) occurred while looking up required values"
    }

    $actionList = [System.Collections.Generic.list[string]]::new()
    $employeeCount = ($correlateEmployeeAccount | Measure-Object).Count
    $personCount = ($correlatedPersonAccount | Measure-Object).Count
    if ($employeeCount -eq 1) {
        $actionList.Add('CorrelateAccount')
    }
    elseif ($employeeCount -gt 1) {
        $actionList.Add('MultipleEmployeeFound')
    }
    elseif ($personCount -eq 1) {
        $actionList.Add('CreateEmployee')
        $outputContext.AccountReference = $correlatedPersonAccount.PERSON_PERSONID
    }
    elseif ($personCount -gt 1) {
        $actionList.Add('MultiplePersonFound')
    }
    else {
        $actionList.Add('CreatePerson')
        $actionList.Add('CreateEmployee')
    }

    Write-Information "Actions [$($actionList -join ', ')]"

    # Process
    foreach ($action in $actionList) {
        switch ($action) {
            'CreatePerson' {
                # Make sure to test with special characters and if needed; add utf8 encoding.
                $queryProperties = @()
                foreach ($prop in $actionContext.Data.Person.PSObject.Properties) {
                    # Check if value is null or empty - if so, use null instead of empty string
                    if ([string]::IsNullOrEmpty($prop.value)) {
                        $queryProperties += 'NULL'
                        continue
                    }

                    # Escape special characters for string values
                    $escapedValue = $prop.value -replace "'", "`\`'"
                    $escapedValue = $escapedValue -replace "&", "&amp;"
                    
                    # Determine if field requires quotes (text fields) or not (ID/numeric fields)
                    $fieldValue = switch -Regex ($prop.Name) {
                        '^(FIRSTNAME|NAME|PREFIX)$' { "'$escapedValue'" ; break }
                        '^FREETEXT\d+$' { "'$escapedValue'" ; break }
                        '^(DEPARTMENTID|HSID)$' { "$($prop.value)" ; break }
                        '^FREESELECT\d+$' { "$($prop.value)" ; break }
                        default { "'$escapedValue'" ; break }
                    }
                    $queryProperties += $fieldValue
                }

                $columnsCreatePerson = $(($actionContext.Data.Person | Select-Object * -ExcludeProperty personId).PSObject.Properties.Name -join ', ')

                $queryCreatePerson = "
                INSERT INTO Person ($($columnsCreatePerson))
                VALUES ($($queryProperties -join ', '))"

                # Build dynamic retrieve query with all fields from Person object
                $retrieveFieldsList = [System.Collections.Generic.List[string]]::new()
                $retrieveFieldsList.Add('TABLEPERSON.PERSONID AS personId')
                $retrieveFieldsList.Add('TABLEPERSON.NAME AS Name')
                $retrieveFieldsList.Add('TABLEPERSON.FirstName AS FirstName')
                $retrieveFieldsList.Add('TABLEPERSON.Prefix AS Prefix')
                
                foreach ($property in $actionContext.Data.Person.PSObject.Properties) {
                    if ($property.Name -match '^(DEPARTMENTID|HSID|FREETEXT\d+|FREESELECT\d+)$') {
                        $retrieveFieldsList.Add("TABLEPERSON.$($property.Name) AS $($property.Name)")
                    }
                }
                
                $retrieveFieldsList.Add('TABLEEMPLOYEE.EMPLOYEEID AS employee_employeeId')
                $retrieveFieldsList.Add('TABLEEMPLOYEE.SALARYNR AS employee_salaryNr')
                
                $queryRetrievePerson = "
                    SELECT
                    $($retrieveFieldsList -join ",`n                    ")
                    FROM person TABLEPERSON
                        LEFT OUTER JOIN employee TABLEEMPLOYEE ON TABLEEMPLOYEE.personID = TABLEPERSON.personID
                    WHERE
                        TABLEPERSON.NAME = '$($actionContext.Data.Person.Name)'
                        AND TABLEPERSON.FIRSTNAME = '$($actionContext.Data.Person.FirstName)'
                    "

                if (-not($actionContext.DryRun -eq $true)) {
                    Write-Information "Creating and correlating IProtect Person account with NAME =  $($actionContext.Data.Person.Name) , FIRSTNAME = $($actionContext.Data.Person.Name)"

                    $splatCreateUser = @{
                        JSessionID = $jSessionID
                        WebSession = $webSession
                        Query      = $queryCreatePerson
                        QueryType  = 'update'
                    }
                    
                    $null = Invoke-IProtectQuery @splatCreateUser

                    Write-Information 'Retrieve PersonID from just created person'

                    $splatGetCreatedUser = @{
                        JSessionID = $jSessionID
                        WebSession = $webSession
                        Query      = $queryRetrievePerson
                        QueryType  = 'query'
                    }
                    $createdPersonObject = Invoke-IProtectQuery @splatGetCreatedUser
                    $createdPersonAccount = $createdPersonObject | Where-Object { $_.EMPLOYEE_EMPLOYEEID -eq "" } 
                    $createdPersonCount = ($createdPersonAccount | Measure-Object).Count

                    if ($null -eq $createdPersonAccount) {
                        throw 'Unable to get PersonID of the just created person'
                    }
                    elseif ($createdPersonCount.Count -gt 1) {
                        throw "Multiple Persons found with [$($actionContext.Data.Person.Name)' AND FIRSTNAME = '$($actionContext.Data.Person.FirstName)], Please correct this so the Persons are unique."
                    }
                    $outputContext.Data.Person = $createdPersonAccount
                    $outputContext.AccountReference = $createdPersonAccount.PERSONID
                }
                else {
                    Write-Information '[DryRun] Create and correlate IProtect Person account, will be executed during enforcement'
                    Write-Information "Query to Create Person '$($queryCreatePerson)'"
                }
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Create Person account was successful. AccountReference is: [$($outputContext.AccountReference)]"
                        IsError = $false
                    })
                break
            }

            'CreateEmployee' {
                Write-Information 'Creating Employee account'
                # Create Employee
                $queryProperties = @()
                foreach ($prop in $actionContext.Data.Employee.PSObject.Properties) {
                    
                    $queryProperties += switch ($prop.Name ) {
                        'BIRTHDATE' { "$( if (-not ([string]::IsNullOrEmpty($prop.value))) { "#$($prop.value)#" } else{ 'NULL' } )" ; break }
                        'LANGUAGE' { "$($prop.value)" ; break }
                        'SALARYNR' { "'$($prop.value)'" ; break }
                        'HIREDATE' { "$( if (-not ([string]::IsNullOrEmpty($prop.value))) { "#$($prop.value)#" } else{ 'NULL' } )" ; break }
                        'TERMINATIONDATE' { "$( if (-not ([string]::IsNullOrEmpty($prop.value))) { "#$($prop.value)#" } else{ 'NULL' } )" ; break }
                        'HSID' { "$($prop.value)" ; break }
                    }
                }

                $columnsCreateEmployee = $(($actionContext.Data.Employee | Select-Object * -ExcludeProperty employeeId).PSObject.Properties.Name -join ', ')
                $queryCreateEmployee = "
                INSERT INTO Employee (PERSONID, $columnsCreateEmployee)
                VALUES ($($outputContext.AccountReference), $($queryProperties -join ', '))"
                
                $queryRetrieveEmployee = "
                SELECT
                    EMPLOYEEID,
                    SALARYNR
                FROM employee WHERE SALARYNR = '$($actionContext.Data.Employee.SalaryNR)'"

                if (-not($actionContext.DryRun -eq $true)) {
                    Write-Information "Creating and correlating IProtect employee account with [$($correlationField) - $($correlationValue)]"

                    $splatCreateEmployee = @{
                        JSessionID = $jSessionID
                        WebSession = $webSession
                        Query      = $queryCreateEmployee
                        QueryType  = 'update'
                    }

                    $null = Invoke-IProtectQuery @splatCreateEmployee

                    $splatGetCreatedEmployee = @{
                        JSessionID = $jSessionID
                        WebSession = $webSession
                        Query      = $queryRetrieveEmployee
                        QueryType  = 'Query'
                    }

                    # Get Created account
                    $createdEmployeeAccount = Invoke-IProtectQuery @splatGetCreatedEmployee
                }
                else {
                    Write-Information '[DryRun] Create and correlate IProtect Employee account, will be executed during enforcement'
                    Write-Information "Query to Create Employee '$($queryCreateEmployee)'"
                }

                $outputContext.Data.employee = $createdEmployeeAccount
                if ($null -eq $createdPersonAccount ) {
                    # Only the Person Account is correlated
                    $outputContext.AccountCorrelated = $true
                    $outputContext.Data.Person = $personObject
                }
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Create Employee account was successful. AccountReference is: [$($outputContext.AccountReference)]"
                        IsError = $false
                    })
                break
            }

            'CorrelateAccount' {
                Write-Information 'Correlating IProtect account'
                $outputContext.Data.Employee = $employeeObject
                $outputContext.Data.Person = $personObject
                $outputContext.AccountReference = $personObject.PERSONID
                $outputContext.AccountCorrelated = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = 'CorrelateAccount'
                        Message = "Correlated account: [$($outputContext.AccountReference)] on field: [$($correlationField)] with value: [$($correlationValue)]"
                        IsError = $false
                    })
                break
            }

            'MultipleEmployeeFound' {
                Write-Information 'Multiple Employees found!'
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Multiple Employees found on field: [$($correlationField)] with value: [$($correlationValue)]. Please correct this so the employees are unique."
                        IsError = $true
                    })
                break
            }

            'MultiplePersonFound' {
                Write-Information 'Multiple Persons found!'
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Multiple Persons found without a linked Employee on fields [NAME = $($actionContext.Data.Person.Name)] AND [FIRSTNAME = $($actionContext.Data.Person.FirstName)]. Please correct this so the Persons are unique."
                        IsError = $true
                    })
                break
            }               
        }
    }

    # Set success only if no errors occurred
    if (-not ($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}
catch {
    $outputContext.success = $false
    $ex = $PSItem

    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-IProtectError -ErrorObject $ex
        $auditMessage = "Could not create or correlate IProtect account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Could not create or correlate IProtect account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    
    # Only log when there are no lookup errors, as these generate their own audit message
    if (-not ($ex.Exception.Message -eq "Error(s) occurred while looking up required values")) {
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Message = $auditMessage
                IsError = $true
            })
    }
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if ($outputContext.AuditLogs.IsError -notContains $true) {
        $outputContext.Success = $true
    }
    
    if ($null -ne $WebSession) {
        $splatLogout = @{
            JSessionID = $jSessionID
            WebSession = $webSession
        }
        $null = Invoke-logout @splatLogout
    }
}