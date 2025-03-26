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

        $queryGetEmployee = "
        SELECT
        TABLEEMPLOYEE.PERSONID AS person_personId,
        TABLEPERSON.NAME AS person_Name,
        TABLEPERSON.FirstName AS person_FirstName,
        TABLEPERSON.Prefix AS person_Prefix,
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
                    $queryProperties += switch ($prop.Name ) {
                        'FIRSTNAME' { "'$($prop.value)'" ; break }
                        'NAME' { "'$($prop.value)'" ; break }
                        'PREFIX' { "'$($prop.value)'" ; break }
                    }
                }

                $columnsCreatePerson = $(($actionContext.Data.Person | Select-Object * -ExcludeProperty personId).PSObject.Properties.Name -join ', ')

                $queryCreatePerson = "
                INSERT INTO Person ($($columnsCreatePerson))
                VALUES ($($queryProperties -join ', '))"

                $queryRetrievePerson = "
                    SELECT
                    TABLEPERSON.PERSONID AS person_personId,
                    TABLEPERSON.NAME AS person_Name,
                    TABLEPERSON.FirstName AS person_FirstName,
                    TABLEPERSON.Prefix AS person_Prefix,
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

                if (-not($actionContext.DryRun -eq $true)) {
                    Write-Information "Creating and correlating IProtect Person account with NAME =  $($actionContext.Data.Name) , FIRSTNAME = $($actionContext.Data.Name)"

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

    if ( -not ($outputContext.AuditLogs.IsError -contains $true)) {
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
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
finally {
    if ($null -ne $WebSession) {
        $splatLogout = @{
            JSessionID = $jSessionID
            WebSession = $webSession
        }
        $null = Invoke-logout @splatLogout
    }
}