#################################################
# HelloID-Conn-Prov-Target-IProtect-Update
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
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }
    $webSession, $jSessionID = Get-JSessionID
    $null = Confirm-AuthenticationResult -JSessionID $jSessionID -WebSession $webSession

    Write-Information 'Verifying if a IProtect account exists'
    $queryGetPerson = "
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
    FROM Person AS TABLEPERSON
    LEFT OUTER JOIN employee AS TABLEEMPLOYEE
        ON TABLEEMPLOYEE.personID = TABLEPERSON.personID
    WHERE
        TABLEPERSON.personID = $($actionContext.References.Account)"


    $splatGetPerson = @{
        JSessionID = $jSessionID
        WebSession = $webSession
        Query      = $queryGetPerson
        QueryType  = 'query'
    }

    $correlatedAccount = Invoke-IProtectQuery @splatGetPerson

    $actionList = [System.Collections.Generic.list[object]]::new()
    if ($null -ne $correlatedAccount) {
        $personObject = [PSCustomObject]@{}
        $employeeObject = [PSCustomObject]@{}

        foreach ($property in $correlatedAccount.PSObject.Properties.Name) {
            if ($property.StartsWith('PERSON')) {
                $personObject | Add-Member @{ $property.Replace('PERSON_', '') = $correlatedAccount.$property }
            }
            elseif ($property.StartsWith('EMPLOYEE')) {
                $employeeObject | Add-Member  @{ $property.Replace('EMPLOYEE_', '') = $correlatedAccount.$property }
            }
        }

        $actionContext.Data.Employee.PSObject.Properties | ForEach-Object {
            if ($null -eq $_.Value) { 
                $_.Value = "" 
            }
        }

        $actionContext.Data.Person.PSObject.Properties | ForEach-Object {
            if ($null -eq $_.Value) { 
                $_.Value = "" 
            }
        }

        If ('' -ne $employeeObject.HIREDATE ) {
            $employeeObject.HIREDATE = ($employeeObject.HIREDATE | Get-Date).ToString("yyyy-MM-dd")
        }

        If ('' -ne $employeeObject.BIRTHDATE ) {
            $employeeObject.BIRTHDATE = ($employeeObject.BIRTHDATE | Get-Date).ToString("yyyy-MM-dd")
        }

        If ('' -ne $employeeObject.TERMINATIONDATE) {
            $employeeObject.TERMINATIONDATE = ($employeeObject.TERMINATIONDATE | Get-Date).ToString("yyyy-MM-dd")
        }

        $outputContext.PreviousData = @{
            person   = $personObject
            employee = $employeeObject
        }
        $actionContext.Data.Person.PersonId = $personObject.PersonId
        $actionContext.Data.Employee.employeeId = $employeeObject.employeeId
        $outputContext.Data = $actionContext.Data

        Write-Information 'Compare Person Properties'
        $splatCompareProperties = @{
            ReferenceObject  = @($personObject.PSObject.Properties)
            DifferenceObject = @($actionContext.Data.Person.PSObject.Properties)
        }

        $propertiesPersonChanged = Compare-Object @splatCompareProperties -PassThru | Where-Object { $_.SideIndicator -eq '=>' }

        Write-Information 'Compare Employee Properties'
        $splatCompareProperties = @{
            ReferenceObject  = @($employeeObject.PSObject.Properties)
            DifferenceObject = @($actionContext.Data.Employee.PSObject.Properties)
        }
        $propertiesEmployeeChanged = Compare-Object @splatCompareProperties -PassThru | Where-Object { $_.SideIndicator -eq '=>' }


        if ($propertiesPersonChanged) {
            $actionList.Add('UpdatePersonAccount')
        }
        if ($propertiesEmployeeChanged) {
            $actionList.Add('UpdateEmployeeAccount')
        }
        if ( $actionList.Count -eq 0) {
            $actionList.Add('NoChanges')
        }
    }
    else {
        $actionList.Add('NotFound')
    }

    Write-Information "Actions [$($actionList -join ', ')]"

    # Process
    foreach ($action in $actionList) {
        switch ($action) {
            'UpdatePersonAccount' {
                Write-Information "Person Account property(s) required to update: $($propertiesPersonChanged.Name -join ', ')"

                $updateQueryProperties = @()
                foreach ($prop in $propertiesPersonChanged) {
                    $updateQueryProperties += switch ($prop.Name ) {
                        'FirstName' { "FirstName = '$($prop.value)'" ; break }
                        'Name' { "Name = '$($prop.value)'" ; break }
                        'Prefix' { "Prefix = '$($prop.value)'" ; break }
                    }
                }

                $updateQueryPerson = "
                    UPDATE
                    PERSON
                    SET
                        $($updateQueryProperties -join ",`n" )
                    Where
                    PersonId = $($personObject.PersonId)"

                # Make sure to test with special characters and if needed; add utf8 encoding.
                if (-not($actionContext.DryRun -eq $true)) {
                    Write-Information "Updating IProtect Person account with accountReference: [$($actionContext.References.Account)]"
                    
                    $splatUpdateUser = @{
                        JSessionID = $jSessionID
                        WebSession = $webSession
                        Query      = $updateQueryPerson
                        QueryType  = 'update'
                    }

                    $null = Invoke-IProtectQuery @splatUpdateUser
                }
                else {
                    Write-Information "[DryRun] Update IProtect account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
                }

                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Update Person account was successful, Account property(s) updated: [$($propertiesPersonChanged.name -join ',')]"
                        IsError = $false
                    })
                break
            }
            'UpdateEmployeeAccount' {
                Write-Information "Employee Account property(s) required to update: $($propertiesEmployeeChanged.Name -join ', ')"
                $updateQueryProperties = @()
                foreach ($prop in $propertiesEmployeeChanged) {
                    $updateQueryProperties += switch ($prop.Name ) {
                        'BIRTHDATE' { "BirthDate = $( if (-not ([string]::IsNullOrEmpty($prop.value))) { "#$($prop.value)#" } else{ 'NULL' } )" ; break }
                        'LANGUAGE' { "Language = $($prop.value)" ; break }
                        'SALARYNR' { "SalaryNR = '$($prop.value)'" ; break }
                        'HIREDATE' { "HireDate = $( if (-not ([string]::IsNullOrEmpty($prop.value))) { "#$($prop.value)#" } else{ 'NULL' } )" ; break }
                        'TERMINATIONDATE' { "TerminationDate = $( if (-not ([string]::IsNullOrEmpty($prop.value))) { "#$($prop.value)#" } else{ 'NULL' } )" ; break }
                    }
                }

                $updateQueryEmployee = "
                    UPDATE
                        EMPLOYEE
                    SET
                        $($updateQueryProperties -join ",`n" )
                    Where
                        EmployeeId = $($employeeObject.employeeId)"

                # Make sure to test with special characters and if needed; add utf8 encoding.
                if (-not($actionContext.DryRun -eq $true)) {
                    Write-Information "Updating IProtect Employee account with accountReference: [$($actionContext.References.Account)]"

                    $splatUpdateEmployee = @{
                        JSessionID = $jSessionID
                        WebSession = $webSession
                        Query      = $updateQueryEmployee
                        QueryType  = 'update'
                    }

                    $null = Invoke-IProtectQuery @splatUpdateEmployee
                }
                else {
                    Write-Information "[DryRun] Update IProtect account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
                }

                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Update Employee account was successful, Account property(s) updated: [$($propertiesEmployeeChanged.name -join ',')]"
                        IsError = $false
                    })
                break
            }

            'NoChanges' {
                Write-Information "No changes to IProtect Person and Employee account with accountReference: [$($actionContext.References.Account)]"
                $outputContext.Success = $true
                # Make sure there are no difference between Data and previousData
                $outputContext.Data = $actionContext.Data
                $outputContext.PreviousData = $actionContext.Data
                break
            }

            'NotFound' {
                Write-Information "IProtect account: [$($actionContext.References.Account)] could not be found, possibly indicating that it could be deleted"
                $outputContext.Success = $false
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "IProtect account with accountReference: [$($actionContext.References.Account)] could not be found, possibly indicating that it could be deleted"
                        IsError = $true
                    })
                break
            }
        }
    }
}
catch {
    $outputContext.Success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-IProtectError -ErrorObject $ex
        $auditMessage = "Could not update IProtect account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Could not update IProtect account. Error: $($ex.Exception.Message)"
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