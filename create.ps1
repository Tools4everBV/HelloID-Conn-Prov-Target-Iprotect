#################################################
# HelloID-Conn-Prov-Target-iProtect-Create
# PowerShell V2
# Note: Due to the necessity of provisioning the person, the employee as well as the keycard and license plate, the correlation option in HelloID is not supported, as it only supports a single correlation field.
#################################################
# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($actionContext.Configuration.isDebug) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region Person
# Define Account mapping object
$personAccount = [PSCustomObject]$actionContext.Data.Person

# Define properties to enclose in specific characters
# String values have to be enclosed in single quotes
$personPropertiesToEncloseInSingleQuotes = @(
    "NAME"
    , "FIRSTNAME"
    , "PREFIX"
)
# Date values have to be enclosed in hashtags
$personPropertiesToEncloseInHashtags = @()

# Define properties to query
$personPropertiesToQuery = @("PERSONID") + $personAccount.PSObject.Properties.Name | Select-Object -Unique

# Define properties to export
$personPropertiesToExport = @("PERSONID") + $personAccount.PSObject.Properties.Name | Select-Object -Unique
#endRegion Person

#region Employee
# Define Account mapping object
$employeeAccount = [PSCustomObject]$actionContext.Data.Employee

# Define properties to enclose in specific characters
# String values have to be enclosed in single quotes
$employeePropertiesToEncloseInSingleQuotes = @(
    "SALARYNR"
)
# Date values have to be enclosed in hashtags
$employeePropertiesToEncloseInHashtags = @(
    "HireDate"
    , "TerminationDate"
    , "BirthDate"
)

# Define properties to query
$employeePropertiesToQuery = @("EMPLOYEEID") + $employeeAccount.PSObject.Properties.Name | Select-Object -Unique

# Define properties to export
$employeePropertiesToExport = @("EMPLOYEEID") + $employeeAccount.PSObject.Properties.Name | Select-Object -Unique
#endRegion Employee

#region KeyCard
# Define Account mapping object
$keyCardAccount = [PSCustomObject]$actionContext.Data.KeyCard

# Define properties to enclose in specific characters
# String values have to be enclosed in single quotes
$keyCardPropertiesToEncloseInSingleQuotes = @(
    "RCN"
)
# Date values have to be enclosed in hashtags
$keyCardPropertiesToEncloseInHashtags = @()

# Define properties to query
$keyCardPropertiesToQuery = @("ACCESSKEYID") + $keyCardAccount.PSObject.Properties.Name | Select-Object -Unique

# Define properties to export
$keyCardPropertiesToExport = @("ACCESSKEYID") + $keyCardAccount.PSObject.Properties.Name | Select-Object -Unique
#endRegion KeyCard

#region LicensePlate
# Define Account mapping object
$licensePlateAccount = [PSCustomObject]$actionContext.Data.LicensePlate

# Define properties to enclose in specific characters
# String values have to be enclosed in single quotes
$licensePlatePropertiesToEncloseInSingleQuotes = @(
    "RCN"
)
# Date values have to be enclosed in hashtags
$licensePlatePropertiesToEncloseInHashtags = @()

# Define properties to query
$licensePlatePropertiesToQuery = @("ACCESSKEYID") + $licensePlateAccount.PSObject.Properties.Name | Select-Object -Unique

# Define properties to export
$licensePlatePropertiesToExport = @("ACCESSKEYID") + $licensePlateAccount.PSObject.Properties.Name | Select-Object -Unique
#endRegion LicensePlate

# Create empty hashtable for AccountReference as this is appended with each action
$outputContext.AccountReference = @{}

#region functions
function Get-JSessionID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $BaseUrl,

        [Parameter(Mandatory = $false)]
        [string]
        $ProxyAddress
    )

    $splatParams = @{
        Uri                = "$BaseUrl/xmlsql"
        Method             = "Post"
        Headers            = @{
            "Content-Type" = "application/x-www-form-urlencoded"
        }
        UseBasicParsing    = $true
        TimeoutSec         = 60
        MaximumRedirection = 0
        SessionVariable    = "script:WebSession"
    }

    if (-not[String]::IsNullOrEmpty($ProxyAddress)) {
        $splatParams["Proxy"] = $ProxyAddress
    }

    try {
        $requestResult = Invoke-WebRequest @splatParams -ErrorAction SilentlyContinue -Verbose:$false
        if ($null -ne $requestResult.Headers) {
            if ($null -ne $requestResult.Headers["Set-Cookie"] ) {
                $authorizationCookie = $requestResult.Headers["Set-Cookie"]

                if ($authorizationCookie.IndexOf(";") -gt 0) {
                    $jsessionId = $authorizationCookie.Substring(0, $authorizationCookie.IndexOf(";"))
                }
            }
        }
        Write-Output $jsessionId
    }
    catch {
        throw $_
    }
}

function Get-AuthenticationResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $BaseUrl,

        [Parameter(Mandatory)]
        [string]
        $JSessionID,

        [Parameter(Mandatory)]
        [string]
        $UserName,

        [Parameter(Mandatory)]
        [string]
        $Password
    )

    $splatParams = @{
        Uri                = "$BaseUrl/j_security_check"
        Method             = "POST"
        Headers            = @{
            "Content-Type" = "application/x-www-form-urlencoded"
            "Cookie"       = $JSessionID
        }
        UseBasicParsing    = $true
        MaximumRedirection = 0
        Body               = "&j_username=$($UserName)&j_password=$($Password)"
        WebSession         = $script:WebSession
    }
    try {
        Invoke-WebRequest @splatParams -ErrorAction SilentlyContinue -Verbose:$false
    }
    catch {
        throw $_
    }
}

function Invoke-IProtectQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $BaseUrl,

        [Parameter(Mandatory)]
        [string]
        $JSessionID,

        [Parameter(Mandatory)]
        [string]
        $QueryType,

        [Parameter(Mandatory = $false)]
        [string]
        $Query,

        [Parameter(Mandatory = $false)]
        [string]
        $ProxyServer
    )

    switch ($QueryType) {
        "query" { $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><query><sql>$query</sql></query>" }
        "update" { $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><update><sql>$query</sql></update>" }
        "logout" { $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><LOGOUT></LOGOUT>" }
    }
    $splatParams = @{
        Uri                = "$BaseUrl/xmlsql"
        Method             = "POST"
        Headers            = @{
            "Accept" = "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2"
            "Cookie" = $JSessionID
        }
        UseBasicParsing    = $true
        MaximumRedirection = 0
        ContentType        = "text/xml;charset=ISO-8859-1"
        Body               = $queryBody
        WebSession         = $script:WebSession
    }

    if (-not[String]::IsNullOrEmpty($ProxyServer)) {
        $splatParams["Proxy"] = $ProxyServer
    }

    try {
        $queryResult = Invoke-WebRequest @splatParams -Verbose:$false
        Write-Verbose "queryResult: $($queryResult | Out-String)"
        switch ($queryType) {
            "query" {
                [xml] $xmlResult = $queryResult.Content
                $resultNode = $xmlResult.item("RESULT")
                $nodePath = "ROWSET"
                $rowsetNode = $resultNode.SelectSingleNode($nodePath)

                $nodePath = "ERROR"
                $errorNode = $resultNode.SelectSingleNode($nodePath)

                if ($null -ne $errorNode) {
                    throw $ErrorNode.DESCRIPTION
                }

                if ($null -ne $rowsetNode) {
                    $nodePath = "ROW"
                    $rowNodes = $rowsetNode.SelectNodes($nodePath)
                    if ((-not ($null -eq $rowNodes) -and ($rowNodes.Count -gt 0))) {
                        Write-Output $rowNodes
                    }
                    else {
                        Write-Output $null
                    }
                }
            }
            "update" {
                [xml] $xmlResult = $queryResult.Content
                $resultNode = $xmlResult.item("RESULT")
                $errorNode = $resultNode.SelectSingleNode("ERROR")
                if ($null -ne $errorNode) {
                    throw $ErrorNode.DESCRIPTION
                }
                Write-Output $resultNode
            }
        }
    }
    catch {
        throw $_
    }
}
#endregion functions

try {
    #region Get JSessionID
    try {
        Write-Verbose "Getting JSessionID"
    
        $jSessionIDSplatParams = @{
            BaseUrl      = $actionContext.Configuration.BaseUrl
            ProxyAddress = $actionContext.Configuration.ProxyAddress
        }
    
        $jSessionID = Get-JSessionID @jSessionIDSplatParams
    
        Write-Verbose "Got JSessionID. Result: $($jSessionID | ConvertTo-Json)"
    }
    catch {
        $ex = $PSItem

        $auditMessage = "Error getting JSessionID. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = $auditMessage
                IsError = $true
            })
    
        # Throw terminal error
        throw $auditMessage
    }
    #endregion Get JSessionID
    
    #region Authenticate to iProtect
    try {
        Write-Verbose "Authenticating to iProtect"
    
        $authenicationResultplatParams = @{
            BaseUrl    = $actionContext.Configuration.BaseUrl
            JSessionID = $jSessionID
            Username   = $actionContext.Configuration.UserName
            Password   = $actionContext.Configuration.Password
        }
    
        $authenicationResult = Get-AuthenticationResult @authenicationResultplatParams
    
        if (-Not ($authenicationResult.StatusCode -eq 302)) {
            throw "Authentication failed with error [$($authenicationResult.StatusCode)]"
        }
        else {
            Write-Verbose "Authenticated to iProtect. Result: $($authenicationResult | ConvertTo-Json)"
        }
    
        Write-Verbose "Got JSessionID"
    }
    catch {
        $ex = $PSItem

        $auditMessage = "Error authenticating to iProtect. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = $auditMessage
                IsError = $true
            })
    
        # Throw terminal error
        throw $auditMessage
    }
    #endregion Authenticate to iProtect

    #region Person
    #region Verify if person must be either [created ] or just [correlated]
    try {
        $queryCorrelatePerson = "
            SELECT
                $($personPropertiesToQuery -Join ',')
            FROM
                PERSON
            WHERE
                NAME = '$($personAccount.Name)'
                AND FIRSTNAME = '$($personAccount.FirstName)'
            "

        $correlatePersonSplatParams = @{
            BaseUrl    = $actionContext.Configuration.BaseUrl
            JSessionID = $jSessionID
            Query      = $queryCorrelatePerson
            QueryType  = "query"
        }

        Write-Verbose "Querying person where [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)]. SplatParams: $($correlatePersonSplatParams | ConvertTo-Json)"

        $correlatedPerson = $null
        $correlatedPerson = Invoke-IProtectQuery @correlatePersonSplatParams
            
        Write-Verbose "Queried person where [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)]. Result: $($correlatedPerson | Out-String)"
    }
    catch {
        $ex = $PSItem

        $auditMessage = "Error querying person where [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)]. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = $auditMessage
                IsError = $true
            })

        # Log query
        Write-Warning "Query: $queryCorrelatePerson"
        
        # Throw terminal error
        throw $auditMessage
    }
    #endregion Verify if person must be either [created ] or just [correlated]

    if (($correlatedPerson | Measure-Object).count -eq 0) {
        $actionPerson = "Create"
    }
    elseif (($correlatedPerson | Measure-Object).count -eq 1) {
        $actionPerson = "Correlate"
    }
    elseif (($correlatedPerson | Measure-Object).count -gt 1) {
        $actionPerson = "MultipleFound"
    }

    # Process
    switch ($actionPerson) {
        "Create" {
            #region Create person
            try {
                $objectCreatePerson = @{}

                # Add the mapped fields to object to create person
                foreach ($personAccountProperty in $personAccount.PsObject.Properties | Where-Object { $null -ne $_.Value }) {
                    # Enclose specific fields with single quotes
                    if ($personAccountProperty.Name -in $personPropertiesToEncloseInSingleQuotes) {
                        [void]$objectCreatePerson.Add("$($personAccountProperty.Name)", "'$($personAccountProperty.Value)'")
                    }
                    # Enclose specific fields with hashtags
                    elseif ($personAccountProperty.Name -in $personPropertiesToEncloseInHashtags) {
                        [void]$objectCreatePerson.Add("$($personAccountProperty.Name)", "#$($personAccountProperty.Value)#")
                    }
                    else {
                        [void]$objectCreatePerson.Add("$($personAccountProperty.Name)", "$($personAccountProperty.Value)")
                    }
                }

                # Seperate Property Names with comma ,
                $queryCreatePersonProperties = $(($objectCreatePerson.Keys -join ","))
                # Seperate Property Values with comma ,
                $queryCreatePersonValues = $(($objectCreatePerson.Values -join ","))

                $queryCreatePerson = "
                INSERT INTO Person
                    ($($queryCreatePersonProperties))
                VALUES
                    ($($queryCreatePersonValues))
                "

                $createPersonSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryCreatePerson
                    QueryType  = "update"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Creating person with [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)]. SplatParams: $($createPersonSplatParams | ConvertTo-Json)"   

                    $createdPerson = Invoke-IProtectQuery @createPersonSplatParams

                    # Auditlog is created after query of created person to include accountreference
                    Write-Verbose "Created person with [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)]"
                }
                else {
                    Write-Warning "DryRun: Would create person with [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)]. SplatParams: $($createPersonSplatParams | ConvertTo-Json)"
                }
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error creating person with [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)]. Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryCreatePerson"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion Create person

            if (-Not($actionContext.DryRun -eq $true)) {
                #region Get created person by salarynr
                try {
                    $queryGetPerson = "
                    SELECT
                        $($personPropertiesToQuery -Join ',')
                    FROM
                        PERSON
                    WHERE
                        NAME = '$($personAccount.Name)'
                        AND FIRSTNAME = '$($personAccount.FirstName)'
                    "

                    $getPersonSplatParams = @{
                        BaseUrl    = $actionContext.Configuration.BaseUrl
                        JSessionID = $jSessionID
                        Query      = $queryGetPerson
                        QueryType  = "query"
                    }

                    Write-Verbose "Querying created person where [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)]. SplatParams: $($getPersonSplatParams | ConvertTo-Json)"

                    $correlatedPerson = $null
                    $correlatedPerson = Invoke-IProtectQuery @getPersonSplatParams

                    if ($null -eq $correlatedPerson) {
                        throw "No result returned"
                    }
        
                    Write-Verbose "Queried created person where [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)]. Result: $($correlatedPerson | Out-String)"
                }
                catch {
                    $ex = $PSItem

                    $auditMessage = "Error querying created person where [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)]. Error: $($ex.Exception.Message)"
                    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $true
                        })

                    # Log query
                    Write-Warning "Query: $queryGetPerson"

                    # Throw terminal error
                    throw $auditMessage
                }
                #endregion Get created person by salarynr

                #region Set AccountReference and AccountData and create auditlog
                [void]$outputContext.AccountReference.add("Person", @{
                        "PERSONID" = "$($correlatedPerson.PERSONID)"
                    })

                foreach ($correlatedPersonProperty in $correlatedPerson.PSObject.Properties | Where-Object { $_.Name -in $personPropertiesToExport }) {
                    $outputContext.Data.Person | Add-Member -MemberType NoteProperty -Name $correlatedPersonProperty.Name -Value $correlatedPersonProperty.Value -Force
                }
    
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Created person with [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)] with AccountReference: $($outputContext.AccountReference.Person | ConvertTo-Json)"
                        IsError = $false
                    })
                #endregion Set AccountReference and AccountData and create auditlog
            }

            break
        }

        "Correlate" {
            [void]$outputContext.AccountReference.add("Person", @{
                    "PERSONID" = "$($correlatedPerson.PERSONID)"
                })

            foreach ($correlatedPersonProperty in $correlatedPerson.PSObject.Properties | Where-Object { $_.Name -in $personPropertiesToExport }) {
                $outputContext.Data.Person | Add-Member -MemberType NoteProperty -Name $correlatedPersonProperty.Name -Value $correlatedPersonProperty.Value -Force
            }

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = "CorrelateAccount" # Optionally specify a different action for this audit log
                    Message = "Correlated to person with AccountReference: $($outputContext.AccountReference.Person | ConvertTo-Json) on [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)]"
                    IsError = $false
                })

            $outputContext.AccountCorrelated = $true

            break
        }

        "MultipleFound" {
            $auditMessage = "Multiple persons found where [NAME = $($personAccount.Name)] AND [FIRSTNAME = $($personAccount.FirstName)]. Please correct this so the persons are unique."

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $true
                })
        
            # Throw terminal error
            throw $auditMessage

            break
        }
    }
    #endregion Person

    #region Employee
    # Set PersonID with PersonID of created or correlated person
    $employeeAccount.PERSONID = $correlatedPerson.PERSONID

    #region Verify if employee must be either [created ] or just [correlated]
    try {
        $queryCorrelateEmployee = "
            SELECT
                $($employeePropertiesToQuery -Join ',')
            FROM
                EMPLOYEE
            WHERE
                SALARYNR = '$($employeeAccount.SALARYNR)'
            "

        $correlateEmployeeSplatParams = @{
            BaseUrl    = $actionContext.Configuration.BaseUrl
            JSessionID = $jSessionID
            Query      = $queryCorrelateEmployee
            QueryType  = "query"
        }

        Write-Verbose "Querying employee where [SALARYNR] = [$($employeeAccount.SALARYNR)]. SplatParams: $($correlateEmployeeSplatParams | ConvertTo-Json)"

        $correlatedEmployee = $null
        $correlatedEmployee = Invoke-IProtectQuery @correlateEmployeeSplatParams
            
        Write-Verbose "Queried employee where [SALARYNR] = [$($employeeAccount.SALARYNR)]. Result: $($correlatedEmployee | Out-String)"
    }
    catch {
        $ex = $PSItem

        $auditMessage = "Error querying employee where [SALARYNR] = [$($employeeAccount.SALARYNR)]. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = $auditMessage
                IsError = $true
            })

        # Log query
        Write-Warning "Query: $queryCorrelateEmployee"
        
        # Throw terminal error
        throw $auditMessage
    }
    #endregion Verify if employee must be either [created ] or just [correlated]

    if (($correlatedEmployee | Measure-Object).count -eq 0) {
        $actionEmployee = "Create"
    }
    elseif (($correlatedEmployee | Measure-Object).count -eq 1) {
        $actionEmployee = "Correlate"
    }
    elseif (($correlatedEmployee | Measure-Object).count -gt 1) {
        $actionEmployee = "MultipleFound"
    }

    # Process
    switch ($actionEmployee) {
        "Create" {
            #region Create employee
            try {
                $objectCreateEmployee = @{}

                # Add the mapped fields to object to create employee
                foreach ($employeeAccountProperty in $employeeAccount.PsObject.Properties | Where-Object { $null -ne $_.Value }) {
                    # Enclose specific fields with single quotes
                    if ($employeeAccountProperty.Name -in $employeePropertiesToEncloseInSingleQuotes) {
                        [void]$objectCreateEmployee.Add("$($employeeAccountProperty.Name)", "'$($employeeAccountProperty.Value)'")
                    }
                    # Enclose specific fields with hashtags
                    elseif ($employeeAccountProperty.Name -in $employeePropertiesToEncloseInHashtags) {
                        [void]$objectCreateEmployee.Add("$($employeeAccountProperty.Name)", "#$($employeeAccountProperty.Value)#")
                    }
                    else {
                        [void]$objectCreateEmployee.Add("$($employeeAccountProperty.Name)", "$($employeeAccountProperty.Value)")
                    }
                }

                # Seperate Property Names with comma ,
                $queryCreateEmployeeProperties = $(($objectCreateEmployee.Keys -join ","))
                # Seperate Property Values with comma ,
                $queryCreateEmployeeValues = $(($objectCreateEmployee.Values -join ","))

                $queryCreateEmployee = "
                INSERT INTO Employee
                    ($($queryCreateEmployeeProperties))
                VALUES
                    ($($queryCreateEmployeeValues))
                "

                $createEmployeeSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryCreateEmployee
                    QueryType  = "update"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Creating employee with [SALARYNR = $($employeeAccount.SalaryNr)] AND [PERSONID = $($correlatedPerson.PERSONID)]. SplatParams: $($createEmployeeSplatParams | ConvertTo-Json)"   

                    $createdEmployee = Invoke-IProtectQuery @createEmployeeSplatParams

                    # Auditlog is created after query of created employee to include accountreference
                    Write-Verbose "Created employee with [SALARYNR = $($employeeAccount.SalaryNr)] AND [PERSONID = $($correlatedPerson.PERSONID)]"
                }
                else {
                    Write-Warning "DryRun: Would create employee with [SALARYNR = $($employeeAccount.SalaryNr)] AND [PERSONID = $($correlatedPerson.PERSONID)]. SplatParams: $($createEmployeeSplatParams | ConvertTo-Json)"
                }
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error creating employee with [SALARYNR = $($employeeAccount.SalaryNr)] AND [PERSONID = $($correlatedPerson.PERSONID)]. Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryCreateEmployee"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion Create employee

            if (-Not($actionContext.DryRun -eq $true)) {
                #region Get created employee by salarynr
                try {
                    $queryGetEmployee = "
                    SELECT
                        $($employeePropertiesToQuery -Join ',')
                    FROM
                        EMPLOYEE
                    WHERE
                        SALARYNR = '$($employeeAccount.SALARYNR)'
                    "

                    $getEmployeeSplatParams = @{
                        BaseUrl    = $actionContext.Configuration.BaseUrl
                        JSessionID = $jSessionID
                        Query      = $queryGetEmployee
                        QueryType  = "query"
                    }

                    Write-Verbose "Querying created employee where [SALARYNR = $($employeeAccount.SalaryNr)]. SplatParams: $($getEmployeeSplatParams | ConvertTo-Json)"

                    $correlatedEmployee = $null
                    $correlatedEmployee = Invoke-IProtectQuery @getEmployeeSplatParams

                    if ($null -eq $correlatedEmployee) {
                        throw "No result returned"
                    }
        
                    Write-Verbose "Queried created employee where [SALARYNR = $($employeeAccount.SalaryNr)]. Result: $($correlatedEmployee | Out-String)"
                }
                catch {
                    $ex = $PSItem

                    $auditMessage = "Error querying created employee where [SALARYNR = $($employeeAccount.SalaryNr)]. Error: $($ex.Exception.Message)"
                    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $true
                        })

                    # Log query
                    Write-Warning "Query: $queryGetEmployee"

                    # Throw terminal error
                    throw $auditMessage
                }
                #endregion Get created employee by salarynr

                #region Set AccountReference and AccountData and create auditlog
                [void]$outputContext.AccountReference.add("Employee", @{
                        "EMPLOYEEID" = "$($correlatedEmployee.EMPLOYEEID)"
                    })

                foreach ($correlatedEmployeeProperty in $correlatedEmployee.PSObject.Properties | Where-Object { $_.Name -in $employeePropertiesToExport }) {
                    $outputContext.Data.Employee | Add-Member -MemberType NoteProperty -Name $correlatedEmployeeProperty.Name -Value $correlatedEmployeeProperty.Value -Force
                }
    
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Created employee with [SALARYNR = $($employeeAccount.SalaryNr)] AND [PERSONID = $($employeeAccount.PERSONID)] with AccountReference: $($outputContext.AccountReference.Employee | ConvertTo-Json)"
                        IsError = $false
                    })
                #endregion Set AccountReference and AccountData and create auditlog
            }

            break
        }

        "Correlate" {
            [void]$outputContext.AccountReference.add("Employee", @{
                    "EMPLOYEEID" = "$($correlatedEmployee.EMPLOYEEID)"
                })

            foreach ($correlatedEmployeeProperty in $correlatedEmployee.PSObject.Properties | Where-Object { $_.Name -in $employeePropertiesToExport }) {
                $outputContext.Data.Employee | Add-Member -MemberType NoteProperty -Name $correlatedEmployeeProperty.Name -Value $correlatedEmployeeProperty.Value -Force
            }

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = "CorrelateAccount" # Optionally specify a different action for this audit log
                    Message = "Correlated to employee with AccountReference: $($outputContext.AccountReference.Employee | ConvertTo-Json) on [SALARYNR = $($employeeAccount.SALARYNR)]"
                    IsError = $false
                })

            $outputContext.AccountCorrelated = $true

            break
        }

        "MultipleFound" {
            $auditMessage = "Multiple employees found where [SALARYNR] = [$($employeeAccount.SALARYNR)]. Please correct this so the employees are unique."

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $true
                })
        
            # Throw terminal error
            throw $auditMessage

            break
        }
    }
    #endregion Employee

    #region KeyCard
    if (-not [string]::IsNullOrEmpty($keyCardAccount.RCN)) {
        # Set PersonID with PersonID of created or correlated person
        $keyCardAccount.PERSONID = $correlatedPerson.PERSONID

        #region Verify if keycard must be either [created ] or just [correlated]
        try {
            $queryCorrelateKeyCard = "
            SELECT
                $($keyCardPropertiesToQuery -Join ',')
            FROM
                ACCESSKEY
            WHERE
                CARDCLASSID = $($keyCardAccount.CARDCLASSID)
                AND RCN = '$($keyCardAccount.RCN)'
            "

            $correlateKeyCardSplatParams = @{
                BaseUrl    = $actionContext.Configuration.BaseUrl
                JSessionID = $jSessionID
                Query      = $queryCorrelateKeyCard
                QueryType  = "query"
            }

            Write-Verbose "Querying keycard where [CARDCLASSID] = [$($keyCardAccount.CARDCLASSID)] AND [RCN] = [$($keyCardAccount.RCN)]. SplatParams: $($correlateKeyCardSplatParams | ConvertTo-Json)"

            $correlatedKeyCard = $null
            $correlatedKeyCard = Invoke-IProtectQuery @correlateKeyCardSplatParams
            
            Write-Verbose "Queried keycard where [CARDCLASSID] = [$($keyCardAccount.CARDCLASSID)] AND [RCN] = [$($keyCardAccount.RCN)]. Result: $($correlatedKeyCard | Out-String)"
        }
        catch {
            $ex = $PSItem

            $auditMessage = "Error querying keycard where [CARDCLASSID] = [$($keyCardAccount.CARDCLASSID)] AND [RCN] = [$($keyCardAccount.RCN)]. Error: $($ex.Exception.Message)"
            Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $true
                })

            # Log query
            Write-Warning "Query: $queryCorrelateKeyCard"
        
            # Throw terminal error
            throw $auditMessage
        }
        #endregion Verify if keycard must be either [created ] or just [correlated]

        if (($correlatedKeyCard | Measure-Object).count -eq 0) {
            $actionKeyCard = "Create"
        }
        elseif (($correlatedKeyCard | Measure-Object).count -eq 1) {
            if ((-not([string]::IsNullorEmpty($correlatedKeyCard.PERSONID))) -and (-not($correlatedKeyCard.PERSONID -eq $keyCardAccount.PERSONID))) {
                $actionKeyCard = "AlreadyAssigned"
            }
            elseif ((-not([string]::IsNullorEmpty($correlatedKeyCard.PERSONID))) -and ($correlatedKeyCard.PERSONID -eq $keyCardAccount.PERSONID)) {
                $actionKeyCard = "Correlate"
            }
            else {
                $actionKeyCard = "Assign"
            }
        }
        elseif (($correlatedKeyCard | Measure-Object).count -gt 1) {
            $actionKeyCard = "MultipleFound"
        }

        # Process
        switch ($actionKeyCard) {
            "Create" {
                #region Create keycard
                try {
                    $objectCreateKeyCard = @{}

                    # Add the mapped fields to object to create keycard
                    foreach ($keyCardAccountProperty in $keyCardAccount.PsObject.Properties | Where-Object { $null -ne $_.Value }) {
                        # Enclose specific fields with single quotes
                        if ($keyCardAccountProperty.Name -in $keyCardPropertiesToEncloseInSingleQuotes) {
                            [void]$objectCreateKeyCard.Add("$($keyCardAccountProperty.Name)", "'$($keyCardAccountProperty.Value)'")
                        }
                        # Enclose specific fields with hashtags
                        elseif ($keyCardAccountProperty.Name -in $keyCardPropertiesToEncloseInHashtags) {
                            [void]$objectCreateKeyCard.Add("$($keyCardAccountProperty.Name)", "#$($keyCardAccountProperty.Value)#")
                        }
                        else {
                            [void]$objectCreateKeyCard.Add("$($keyCardAccountProperty.Name)", "$($keyCardAccountProperty.Value)")
                        }
                    }

                    # Seperate Property Names with comma ,
                    $queryCreateKeyCardProperties = $(($objectCreateKeyCard.Keys -join ","))
                    # Seperate Property Values with comma ,
                    $queryCreateKeyCardValues = $(($objectCreateKeyCard.Values -join ","))

                    $queryCreateKeyCard = "
                    INSERT INTO ACCESSKEY
                        ($($queryCreateKeyCardProperties))
                    VALUES
                        ($($queryCreateKeyCardValues))
                    "

                    $createKeyCardSplatParams = @{
                        BaseUrl    = $actionContext.Configuration.BaseUrl
                        JSessionID = $jSessionID
                        Query      = $queryCreateKeyCard
                        QueryType  = "update"
                    }

                    if (-Not($actionContext.DryRun -eq $true)) {
                        Write-Verbose "Creating keycard with [CARDCLASSID = $($keyCardAccount.CARDCLASSID)] AND [RCN = $($keyCardAccount.RCN)]. SplatParams: $($createKeyCardSplatParams | ConvertTo-Json)"   

                        $createdKeyCard = Invoke-IProtectQuery @createKeyCardSplatParams

                        # Auditlog is created after query of created keycard to include accountreference
                        Write-Verbose "Created keycard with [CARDCLASSID = $($keyCardAccount.CARDCLASSID)] AND [RCN = $($keyCardAccount.RCN)]"
                    }
                    else {
                        Write-Warning "DryRun: Would create keycard with [CARDCLASSID = $($keyCardAccount.CARDCLASSID)] AND [RCN = $($keyCardAccount.RCN)]. SplatParams: $($createKeyCardSplatParams | ConvertTo-Json)"
                    }
                }
                catch {
                    $ex = $PSItem

                    $auditMessage = "Error creating keycard with [CARDCLASSID = $($keyCardAccount.CARDCLASSID)] AND [RCN = $($keyCardAccount.RCN)]. Error: $($ex.Exception.Message)"
                    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $true
                        })

                    # Log query
                    Write-Warning "Query: $queryCreateKeyCard"

                    # Throw terminal error
                    throw $auditMessage
                }
                #endregion Create keycard

                if (-Not($actionContext.DryRun -eq $true)) {
                    #region Get created keycard by salarynr
                    try {
                        $queryGetKeyCard = "
                        SELECT
                            $($keyCardPropertiesToQuery -Join ',')
                        FROM
                            ACCESSKEY
                        WHERE
                            CARDCLASSID = $($keyCardAccount.CARDCLASSID)
                            AND RCN = '$($keyCardAccount.RCN)'
                        "

                        $getKeyCardSplatParams = @{
                            BaseUrl    = $actionContext.Configuration.BaseUrl
                            JSessionID = $jSessionID
                            Query      = $queryGetKeyCard
                            QueryType  = "query"
                        }

                        Write-Verbose "Querying created keycard where [CARDCLASSID] = [$($keyCardAccount.CARDCLASSID)] AND [RCN] = [$($keyCardAccount.RCN)]. SplatParams: $($getKeyCardSplatParams | ConvertTo-Json)"

                        $correlatedKeyCard = $null
                        $correlatedKeyCard = Invoke-IProtectQuery @getKeyCardSplatParams

                        if ($null -eq $correlatedKeyCard) {
                            throw "No result returned"
                        }
        
                        Write-Verbose "Queried created keycard where [CARDCLASSID] = [$($keyCardAccount.CARDCLASSID)] AND [RCN] = [$($keyCardAccount.RCN)]. Result: $($correlatedKeyCard | Out-String)"
                    }
                    catch {
                        $ex = $PSItem

                        $auditMessage = "Error querying created keycard where [CARDCLASSID] = [$($keyCardAccount.CARDCLASSID)] AND [RCN] = [$($keyCardAccount.RCN)]. Error: $($ex.Exception.Message)"
                        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = $auditMessage
                                IsError = $true
                            })

                        # Log query
                        Write-Warning "Query: $queryGetKeyCard"

                        # Throw terminal error
                        throw $auditMessage
                    }
                    #endregion Get created keycard by salarynr

                    #region Set AccountReference and AccountData and create auditlog
                    [void]$outputContext.AccountReference.add("KeyCard", @{
                            "ACCESSKEYID" = "$($correlatedKeyCard.ACCESSKEYID)"
                        })

                    foreach ($correlatedKeyCardProperty in $correlatedKeyCard.PSObject.Properties | Where-Object { $_.Name -in $keyCardPropertiesToExport }) {
                        $outputContext.Data.KeyCard | Add-Member -MemberType NoteProperty -Name $correlatedKeyCardProperty.Name -Value $correlatedKeyCardProperty.Value -Force
                    }
    
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Created keycard with [CARDCLASSID = $($keyCardAccount.CARDCLASSID)] AND [RCN = $($keyCardAccount.RCN)] with AccountReference: $($outputContext.AccountReference.KeyCard | ConvertTo-Json)"
                            IsError = $false
                        })
                    #endregion Set AccountReference and AccountData and create auditlog
                }

                break
            }

            "Assign" {
                #region Assign keycard
                try {
                    $objectAssignKeyCard = @{}

                    $keyCardPropertiesToUseOnAssign = @(
                        "RCN"
                        , "PERSONID"
                    )

                    # Add the mapped fields to object to assign keycard
                    foreach ($keyCardAccountProperty in $keyCardAccount.PsObject.Properties | Where-Object { $_.Name -in $keyCardPropertiesToUseOnAssign -and $null -ne $_.Value }) {
                        # Enclose specific fields with single quotes
                        if ($keyCardAccountProperty.Name -in $keyCardPropertiesToEncloseInSingleQuotes) {
                            [void]$objectAssignKeyCard.Add("$($keyCardAccountProperty.Name)", "'$($keyCardAccountProperty.Value)'")
                        }
                        # Enclose specific fields with hashtags
                        elseif ($keyCardAccountProperty.Name -in $keyCardPropertiesToEncloseInHashtags) {
                            [void]$objectAssignKeyCard.Add("$($keyCardAccountProperty.Name)", "#$($keyCardAccountProperty.Value)#")
                        }
                        else {
                            [void]$objectAssignKeyCard.Add("$($keyCardAccountProperty.Name)", "$($keyCardAccountProperty.Value)")
                        }
                    }

                    # Seperate Properties with comma , and enclose values with single quotes ''
                    $queryAssignKeyCardPropertiesAndValues = ($objectAssignKeyCard.Keys | ForEach-Object {
                            "$($_) = $($objectAssignKeyCard.$_)"
                        }) -join " , "

                    $queryAssignKeyCard = "
                    UPDATE
                        ACCESSKEY
                    SET
                        $queryAssignKeyCardPropertiesAndValues
                    WHERE
                        ACCESSKEYID = $($correlatedKeyCard.ACCESSKEYID)
                    "

                    $assignKeyCardSplatParams = @{
                        BaseUrl    = $actionContext.Configuration.BaseUrl
                        JSessionID = $jSessionID
                        Query      = $queryAssignKeyCard
                        QueryType  = "update"
                    }

                    if (-Not($actionContext.DryRun -eq $true)) {
                        Write-Verbose "Assigning keycard with [ACCESSKEYID = $($correlatedKeyCard.ACCESSKEYID)]. SplatParams: $($assignKeyCardSplatParams | ConvertTo-Json)"   

                        $assignedKeyCard = Invoke-IProtectQuery @assignKeyCardSplatParams

                        # Auditlog is created after query of assigned keycard to include accountreference
                        Write-Verbose "Assigned keycard with [ACCESSKEYID = $($correlatedKeyCard.ACCESSKEYID)]"
                    }
                    else {
                        Write-Warning "DryRun: Would assign keycard with [ACCESSKEYID = $($correlatedKeyCard.ACCESSKEYID)]. SplatParams: $($assignKeyCardSplatParams | ConvertTo-Json)"
                    }
                }
                catch {
                    $ex = $PSItem

                    $auditMessage = "Error assigning keycard with [ACCESSKEYID = $($correlatedKeyCard.ACCESSKEYID)]. Error: $($ex.Exception.Message)"
                    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $true
                        })

                    # Log query
                    Write-Warning "Query: $queryAssignKeyCard"

                    # Throw terminal error
                    throw $auditMessage
                }
                #endregion Assign keycard

                #region Set AccountReference and AccountData and create auditlog
                [void]$outputContext.AccountReference.add("KeyCard", @{
                        "ACCESSKEYID" = "$($correlatedKeyCard.ACCESSKEYID)"
                    })

                foreach ($correlatedKeyCardProperty in $correlatedKeyCard.PSObject.Properties | Where-Object { $_.Name -in $keyCardPropertiesToExport }) {
                    $outputContext.Data.KeyCard | Add-Member -MemberType NoteProperty -Name $correlatedKeyCardProperty.Name -Value $correlatedKeyCardProperty.Value -Force
                }

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Assigned keycard with [ACCESSKEYID = $($correlatedKeyCard.ACCESSKEYID)] with AccountReference: $($outputContext.AccountReference.KeyCard | ConvertTo-Json)"
                        IsError = $false
                    })
                #endregion Set AccountReference and AccountData and create auditlog
                break
            }

            "Correlate" {
                [void]$outputContext.AccountReference.add("KeyCard", @{
                        "ACCESSKEYID" = "$($correlatedKeyCard.ACCESSKEYID)"
                    })

                foreach ($correlatedKeyCardProperty in $correlatedKeyCard.PSObject.Properties | Where-Object { $_.Name -in $keyCardPropertiesToExport }) {
                    $outputContext.Data.KeyCard | Add-Member -MemberType NoteProperty -Name $correlatedKeyCardProperty.Name -Value $correlatedKeyCardProperty.Value -Force
                }

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "CorrelateAccount" # Optionally specify a different action for this audit log
                        Message = "Correlated to keycard with AccountReference: $($outputContext.AccountReference.KeyCard | ConvertTo-Json) on [CARDCLASSID] = [$($keyCardAccount.CARDCLASSID)] AND [RCN] = [$($keyCardAccount.RCN)]"
                        IsError = $false
                    })

                $outputContext.AccountCorrelated = $true

                break
            }

            "AlreadyAssigned" {
                $auditMessage = "Keycard where [CARDCLASSID] = [$($keyCardAccount.CARDCLASSID)] AND [RCN] = [$($keyCardAccount.RCN)] is already assigned to person [$($correlatedKeyCard.PERSONID)]"
    
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })
            
                # Throw terminal error
                throw $auditMessage
    
                break
            }

            "MultipleFound" {
                $auditMessage = "Multiple keycards found where [CARDCLASSID] = [$($keyCardAccount.CARDCLASSID)] AND [RCN] = [$($keyCardAccount.RCN)]. Please correct this so the keycards are unique."

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })
        
                # Throw terminal error
                throw $auditMessage

                break
            }
        }
    }
    #endregion KeyCard

    #region LicensePlate
    if (-not [string]::IsNullOrEmpty($licensePlateAccount.RCN)) {
        # Set PersonID with PersonID of created or correlated person
        $licensePlateAccount.PERSONID = $correlatedPerson.PERSONID

        #region Verify if licenseplate must be either [created ] or just [correlated]
        try {
            $queryCorrelateLicensePlate = "
            SELECT
                $($licensePlatePropertiesToQuery -Join ',')
            FROM
                ACCESSKEY
            WHERE
                CARDCLASSID = $($licensePlateAccount.CARDCLASSID)
                AND RCN = '$($licensePlateAccount.RCN)'
            "

            $correlateLicensePlateSplatParams = @{
                BaseUrl    = $actionContext.Configuration.BaseUrl
                JSessionID = $jSessionID
                Query      = $queryCorrelateLicensePlate
                QueryType  = "query"
            }

            Write-Verbose "Querying licenseplate where [CARDCLASSID] = [$($licensePlateAccount.CARDCLASSID)] AND [RCN] = [$($licensePlateAccount.RCN)]. SplatParams: $($correlateLicensePlateSplatParams | ConvertTo-Json)"

            $correlatedLicensePlate = $null
            $correlatedLicensePlate = Invoke-IProtectQuery @correlateLicensePlateSplatParams
            
            Write-Verbose "Queried licenseplate where [CARDCLASSID] = [$($licensePlateAccount.CARDCLASSID)] AND [RCN] = [$($licensePlateAccount.RCN)]. Result: $($correlatedLicensePlate | Out-String)"
        }
        catch {
            $ex = $PSItem

            $auditMessage = "Error querying licenseplate where [CARDCLASSID] = [$($licensePlateAccount.CARDCLASSID)] AND [RCN] = [$($licensePlateAccount.RCN)]. Error: $($ex.Exception.Message)"
            Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $true
                })

            # Log query
            Write-Warning "Query: $queryCorrelateLicensePlate"
        
            # Throw terminal error
            throw $auditMessage
        }
        #endregion Verify if licenseplate must be either [created ] or just [correlated]

        if (($correlatedLicensePlate | Measure-Object).count -eq 0) {
            $actionLicensePlate = "Create"
        }
        elseif (($correlatedLicensePlate | Measure-Object).count -eq 1) {
            if ((-not([string]::IsNullorEmpty($correlatedLicensePlate.PERSONID))) -and (-not($correlatedLicensePlate.PERSONID -eq $licensePlateAccount.PERSONID))) {
                $actionLicensePlate = "AlreadyAssigned"
            }
            elseif ((-not([string]::IsNullorEmpty($correlatedLicensePlate.PERSONID))) -and ($correlatedLicensePlate.PERSONID -eq $licensePlateAccount.PERSONID)) {
                $actionLicensePlate = "Correlate"
            }
            else {
                $actionLicensePlate = "Assign"
            }
        }
        elseif (($correlatedLicensePlate | Measure-Object).count -gt 1) {
            $actionLicensePlate = "MultipleFound"
        }

        # Process
        switch ($actionLicensePlate) {
            "Create" {
                #region Create licenseplate
                try {
                    $objectCreateLicensePlate = @{}

                    # Add the mapped fields to object to create licenseplate
                    foreach ($licensePlateAccountProperty in $licensePlateAccount.PsObject.Properties | Where-Object { $null -ne $_.Value }) {
                        # Enclose specific fields with single quotes
                        if ($licensePlateAccountProperty.Name -in $licensePlatePropertiesToEncloseInSingleQuotes) {
                            [void]$objectCreateLicensePlate.Add("$($licensePlateAccountProperty.Name)", "'$($licensePlateAccountProperty.Value)'")
                        }
                        # Enclose specific fields with hashtags
                        elseif ($licensePlateAccountProperty.Name -in $licensePlatePropertiesToEncloseInHashtags) {
                            [void]$objectCreateLicensePlate.Add("$($licensePlateAccountProperty.Name)", "#$($licensePlateAccountProperty.Value)#")
                        }
                        else {
                            [void]$objectCreateLicensePlate.Add("$($licensePlateAccountProperty.Name)", "$($licensePlateAccountProperty.Value)")
                        }
                    }

                    # Seperate Property Names with comma ,
                    $queryCreateLicensePlateProperties = $(($objectCreateLicensePlate.Keys -join ","))
                    # Seperate Property Values with comma ,
                    $queryCreateLicensePlateValues = $(($objectCreateLicensePlate.Values -join ","))

                    $queryCreateLicensePlate = "
                    INSERT INTO ACCESSKEY
                        ($($queryCreateLicensePlateProperties))
                    VALUES
                        ($($queryCreateLicensePlateValues))
                    "

                    $createLicensePlateSplatParams = @{
                        BaseUrl    = $actionContext.Configuration.BaseUrl
                        JSessionID = $jSessionID
                        Query      = $queryCreateLicensePlate
                        QueryType  = "update"
                    }

                    if (-Not($actionContext.DryRun -eq $true)) {
                        Write-Verbose "Creating licenseplate with [CARDCLASSID = $($licensePlateAccount.CARDCLASSID)] AND [RCN = $($licensePlateAccount.RCN)]. SplatParams: $($createLicensePlateSplatParams | ConvertTo-Json)"   

                        $createdLicensePlate = Invoke-IProtectQuery @createLicensePlateSplatParams

                        # Auditlog is created after query of created licenseplate to include accountreference
                        Write-Verbose "Created licenseplate with [CARDCLASSID = $($licensePlateAccount.CARDCLASSID)] AND [RCN = $($licensePlateAccount.RCN)]"
                    }
                    else {
                        Write-Warning "DryRun: Would create licenseplate with [CARDCLASSID = $($licensePlateAccount.CARDCLASSID)] AND [RCN = $($licensePlateAccount.RCN)]. SplatParams: $($createLicensePlateSplatParams | ConvertTo-Json)"
                    }
                }
                catch {
                    $ex = $PSItem

                    $auditMessage = "Error creating licenseplate with [CARDCLASSID = $($licensePlateAccount.CARDCLASSID)] AND [RCN = $($licensePlateAccount.RCN)]. Error: $($ex.Exception.Message)"
                    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $true
                        })

                    # Log query
                    Write-Warning "Query: $queryCreateLicensePlate"

                    # Throw terminal error
                    throw $auditMessage
                }
                #endregion Create licenseplate

                if (-Not($actionContext.DryRun -eq $true)) {
                    #region Get created licenseplate by salarynr
                    try {
                        $queryGetLicensePlate = "
                        SELECT
                            $($licensePlatePropertiesToQuery -Join ',')
                        FROM
                            ACCESSKEY
                        WHERE
                            CARDCLASSID = $($licensePlateAccount.CARDCLASSID)
                            AND RCN = '$($licensePlateAccount.RCN)'
                        "

                        $getLicensePlateSplatParams = @{
                            BaseUrl    = $actionContext.Configuration.BaseUrl
                            JSessionID = $jSessionID
                            Query      = $queryGetLicensePlate
                            QueryType  = "query"
                        }

                        Write-Verbose "Querying created licenseplate where [CARDCLASSID] = [$($licensePlateAccount.CARDCLASSID)] AND [RCN] = [$($licensePlateAccount.RCN)]. SplatParams: $($getLicensePlateSplatParams | ConvertTo-Json)"

                        $correlatedLicensePlate = $null
                        $correlatedLicensePlate = Invoke-IProtectQuery @getLicensePlateSplatParams

                        if ($null -eq $correlatedLicensePlate) {
                            throw "No result returned"
                        }
        
                        Write-Verbose "Queried created licenseplate where [CARDCLASSID] = [$($licensePlateAccount.CARDCLASSID)] AND [RCN] = [$($licensePlateAccount.RCN)]. Result: $($correlatedLicensePlate | Out-String)"
                    }
                    catch {
                        $ex = $PSItem

                        $auditMessage = "Error querying created licenseplate where [CARDCLASSID] = [$($licensePlateAccount.CARDCLASSID)] AND [RCN] = [$($licensePlateAccount.RCN)]. Error: $($ex.Exception.Message)"
                        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = $auditMessage
                                IsError = $true
                            })

                        # Log query
                        Write-Warning "Query: $queryGetLicensePlate"

                        # Throw terminal error
                        throw $auditMessage
                    }
                    #endregion Get created licenseplate by salarynr

                    #region Set AccountReference and AccountData and create auditlog
                    [void]$outputContext.AccountReference.add("LicensePlate", @{
                            "ACCESSKEYID" = "$($correlatedLicensePlate.ACCESSKEYID)"
                        })

                    foreach ($correlatedLicensePlateProperty in $correlatedLicensePlate.PSObject.Properties | Where-Object { $_.Name -in $licensePlatePropertiesToExport }) {
                        $outputContext.Data.LicensePlate | Add-Member -MemberType NoteProperty -Name $correlatedLicensePlateProperty.Name -Value $correlatedLicensePlateProperty.Value -Force
                    }
    
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Created licenseplate with [CARDCLASSID = $($licensePlateAccount.CARDCLASSID)] AND [RCN = $($licensePlateAccount.RCN)] with AccountReference: $($outputContext.AccountReference.LicensePlate | ConvertTo-Json)"
                            IsError = $false
                        })
                    #endregion Set AccountReference and AccountData and create auditlog
                }

                break
            }

            "Assign" {
                #region Assign licenseplate
                try {
                    $objectAssignLicensePlate = @{}

                    $licensePlatePropertiesToUseOnAssign = @(
                        "RCN"
                        , "PERSONID"
                    )

                    # Add the mapped fields to object to assign licenseplate
                    foreach ($licensePlateAccountProperty in $licensePlateAccount.PsObject.Properties | Where-Object { $_.Name -in $licensePlatePropertiesToUseOnAssign -and $null -ne $_.Value }) {
                        # Enclose specific fields with single quotes
                        if ($licensePlateAccountProperty.Name -in $licensePlatePropertiesToEncloseInSingleQuotes) {
                            [void]$objectAssignLicensePlate.Add("$($licensePlateAccountProperty.Name)", "'$($licensePlateAccountProperty.Value)'")
                        }
                        # Enclose specific fields with hashtags
                        elseif ($licensePlateAccountProperty.Name -in $licensePlatePropertiesToEncloseInHashtags) {
                            [void]$objectAssignLicensePlate.Add("$($licensePlateAccountProperty.Name)", "#$($licensePlateAccountProperty.Value)#")
                        }
                        else {
                            [void]$objectAssignLicensePlate.Add("$($licensePlateAccountProperty.Name)", "$($licensePlateAccountProperty.Value)")
                        }
                    }

                    # Seperate Properties with comma , and enclose values with single quotes ''
                    $queryAssignLicensePlatePropertiesAndValues = ($objectAssignLicensePlate.Keys | ForEach-Object {
                            "$($_) = $($objectAssignLicensePlate.$_)"
                        }) -join " , "

                    $queryAssignLicensePlate = "
                    UPDATE
                        ACCESSKEY
                    SET
                        $queryAssignLicensePlatePropertiesAndValues
                    WHERE
                        ACCESSKEYID = $($correlatedLicensePlate.ACCESSKEYID)
                    "

                    $assignLicensePlateSplatParams = @{
                        BaseUrl    = $actionContext.Configuration.BaseUrl
                        JSessionID = $jSessionID
                        Query      = $queryAssignLicensePlate
                        QueryType  = "update"
                    }

                    if (-Not($actionContext.DryRun -eq $true)) {
                        Write-Verbose "Assigning licenseplate with [ACCESSKEYID = $($correlatedLicensePlate.ACCESSKEYID)]. SplatParams: $($assignLicensePlateSplatParams | ConvertTo-Json)"   

                        $assignedLicensePlate = Invoke-IProtectQuery @assignLicensePlateSplatParams

                        # Auditlog is created after query of assigned licenseplate to include accountreference
                        Write-Verbose "Assigned licenseplate with [ACCESSKEYID = $($correlatedLicensePlate.ACCESSKEYID)]"
                    }
                    else {
                        Write-Warning "DryRun: Would assign licenseplate with [ACCESSKEYID = $($correlatedLicensePlate.ACCESSKEYID)]. SplatParams: $($assignLicensePlateSplatParams | ConvertTo-Json)"
                    }
                }
                catch {
                    $ex = $PSItem

                    $auditMessage = "Error assigning licenseplate with [ACCESSKEYID = $($correlatedLicensePlate.ACCESSKEYID)]. Error: $($ex.Exception.Message)"
                    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $true
                        })

                    # Log query
                    Write-Warning "Query: $queryAssignLicensePlate"

                    # Throw terminal error
                    throw $auditMessage
                }
                #endregion Assign licenseplate

                #region Set AccountReference and AccountData and create auditlog
                [void]$outputContext.AccountReference.add("LicensePlate", @{
                        "ACCESSKEYID" = "$($correlatedLicensePlate.ACCESSKEYID)"
                    })

                foreach ($correlatedLicensePlateProperty in $correlatedLicensePlate.PSObject.Properties | Where-Object { $_.Name -in $licensePlatePropertiesToExport }) {
                    $outputContext.Data.LicensePlate | Add-Member -MemberType NoteProperty -Name $correlatedLicensePlateProperty.Name -Value $correlatedLicensePlateProperty.Value -Force
                }

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Assigned licenseplate with [ACCESSKEYID = $($correlatedLicensePlate.ACCESSKEYID)] with AccountReference: $($outputContext.AccountReference.LicensePlate | ConvertTo-Json)"
                        IsError = $false
                    })
                #endregion Set AccountReference and AccountData and create auditlog
                break
            }

            "Correlate" {
                [void]$outputContext.AccountReference.add("LicensePlate", @{
                        "ACCESSKEYID" = "$($correlatedLicensePlate.ACCESSKEYID)"
                    })

                foreach ($correlatedLicensePlateProperty in $correlatedLicensePlate.PSObject.Properties | Where-Object { $_.Name -in $licensePlatePropertiesToExport }) {
                    $outputContext.Data.LicensePlate | Add-Member -MemberType NoteProperty -Name $correlatedLicensePlateProperty.Name -Value $correlatedLicensePlateProperty.Value -Force
                }

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "CorrelateAccount" # Optionally specify a different action for this audit log
                        Message = "Correlated to licenseplate with AccountReference: $($outputContext.AccountReference.LicensePlate | ConvertTo-Json) on [CARDCLASSID] = [$($licensePlateAccount.CARDCLASSID)] AND [RCN] = [$($licensePlateAccount.RCN)]"
                        IsError = $false
                    })

                $outputContext.AccountCorrelated = $true

                break
            }

            "AlreadyAssigned" {
                $auditMessage = "Licenseplate where [CARDCLASSID] = [$($licensePlateAccount.CARDCLASSID)] AND [RCN] = [$($licensePlateAccount.RCN)] is already assigned to person [$($correlatedLicensePlate.PERSONID)]"
    
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })
            
                # Throw terminal error
                throw $auditMessage
    
                break
            }

            "MultipleFound" {
                $auditMessage = "Multiple licenseplates found where [CARDCLASSID] = [$($licensePlateAccount.CARDCLASSID)] AND [RCN] = [$($licensePlateAccount.RCN)]. Please correct this so the licenseplates are unique."

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })
        
                # Throw terminal error
                throw $auditMessage

                break
            }
        }
    }
    #endregion LicensePlate
}
catch {
    $ex = $PSItem
    Write-Warning "Terminal error occurred. Error Message: $($ex.Exception.Message)"
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if ($outputContext.AuditLogs.IsError -contains $true) {
        $outputContext.Success = $false
    }
    else {
        $outputContext.Success = $true
    }

    # Check if accountreference is set, if not set, set this with default value as this must contain a value
    if ([String]::IsNullOrEmpty($outputContext.AccountReference) -and $actionContext.DryRun -eq $true) {
        $outputContext.AccountReference = "DryRun: Currently not available"
    }

    if ($null -ne $script:WebSession) {
        # Log out session
        try {
            $logoutSplatParams = @{
                BaseUrl    = $actionContext.Configuration.BaseUrl
                JSessionID = $jSessionID
                QueryType  = "logout"
            }

            Write-Verbose "Logging out. SplatParams: $($logoutSplatParams | ConvertTo-Json)"   

            $loggedOut = Invoke-IProtectQuery @logoutSplatParams

            Write-Verbose "Logged out. Result: $($loggedOut | Out-String)"
        }
        catch {
            $ex = $PSItem

            $auditMessage = "Error logging out. Error: $($ex.Exception.Message)"
            Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

            # Logout failure is not critical
            Write-Warning $auditMessage
        }
    }
}