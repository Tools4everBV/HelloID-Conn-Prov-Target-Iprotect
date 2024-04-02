#################################################
# HelloID-Conn-Prov-Target-iProtect-Update
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
# Define correlation
$personCorrelationField = "PERSONID"
$personCorrelationValue = $actionContext.References.Account.Person.PERSONID

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
# Define correlation
$employeeCorrelationField = "EMPLOYEEID"
$employeeCorrelationValue = $actionContext.References.Account.Employee.EMPLOYEEID

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
# Define correlation
$keyCardCorrelationField = "ACCESSKEYID"
$keyCardCorrelationValue = $actionContext.References.Account.KeyCard.ACCESSKEYID

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
# Define correlation
$licensePlateCorrelationField = "ACCESSKEYID"
$licensePlateCorrelationValue = $actionContext.References.Account.LicensePlate.ACCESSKEYID

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
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw "The account reference could not be found"
    }

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
    #region Get current Person
    try {
        $queryCorrelatePerson = "
            SELECT
                $($personPropertiesToQuery -Join ',')
            FROM
                PERSON
            WHERE
                $personCorrelationField = $($personCorrelationValue)
            "

        $correlatePersonSplatParams = @{
            BaseUrl    = $actionContext.Configuration.BaseUrl
            JSessionID = $jSessionID
            Query      = $queryCorrelatePerson
            QueryType  = "query"
        }

        Write-Verbose "Querying person where [$personCorrelationField] = [$($personCorrelationValue)]. SplatParams: $($correlatePersonSplatParams | ConvertTo-Json)"

        $correlatedPerson = $null
        $correlatedPerson = Invoke-IProtectQuery @correlatePersonSplatParams
            
        Write-Verbose "Queried person where [$personCorrelationField] = [$($personCorrelationValue)]. Result: $($correlatedPerson | Out-String)"
    }
    catch {
        $ex = $PSItem

        $auditMessage = "Error querying person where [$personCorrelationField] = [$($personCorrelationValue)]. Error: $($ex.Exception.Message)"
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
    #endregion Get current Person

    if (($correlatedPerson | Measure-Object).count -eq 1) {
        try {
            Write-Verbose "Comparing current person to mapped properties"

            # Create reference object from correlated account
            $personReferenceObject = [PSCustomObject]@{}
            foreach ($correlatedPersonProperty in $correlatedPerson.PSObject.Properties) {
                $personReferenceObject | Add-Member -MemberType NoteProperty -Name $correlatedPersonProperty.Name -Value $correlatedPersonProperty.Value -Force
            }

            # Create difference object from mapped properties
            $personDifferenceObject = [PSCustomObject]@{}
            foreach ($personAccountProperty in $personAccount.PSObject.Properties) {
                $personDifferenceObject | Add-Member -MemberType NoteProperty -Name $personAccountProperty.Name -Value $personAccountProperty.Value -Force
            }

            $personSplatCompareProperties = @{
                ReferenceObject  = $personReferenceObject.PSObject.Properties | Where-Object { $_.Name -in $personPropertiesToCompare }
                DifferenceObject = $personDifferenceObject.PSObject.Properties | Where-Object { $_.Name -in $personPropertiesToCompare }
            }
            if ($null -ne $personSplatCompareProperties.ReferenceObject -and $null -ne $personSplatCompareProperties.DifferenceObject) {
                $personPropertiesChanged = Compare-Object @personSplatCompareProperties -PassThru
                $personOldProperties = $personPropertiesChanged | Where-Object { $_.SideIndicator -eq "<=" }
                $personNewProperties = $personPropertiesChanged | Where-Object { $_.SideIndicator -eq "=>" }
            }

            if ($personNewProperties) {
                $actionPerson = "Update"
                Write-Information "Person property(s) required to update: $($personNewProperties.Name -join ', ')"
            }
            else {
                $actionPerson = "NoChanges"
            }            

            Write-Verbose "Compared current person to mapped properties"
        }
        catch {
            $ex = $PSItem

            $auditMessage = "Error comparing current person to mapped properties. Error: $($ex.Exception.Message)"
            Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $true
                })
    
            # Throw terminal error
            throw $auditMessage
        }
    }
    elseif (($correlatedPerson | Measure-Object).count -gt 1) {
        $actionPerson = "MultipleFound"
    }
    elseif (($correlatedPerson | Measure-Object).count -eq 0) {
        $actionPerson = "NotFound"
    }

    # Process
    switch ($actionPerson) {
        "Update" {
            #region Update person
            try {
                # Create custom object with old and new values (for logging)
                $personChangedPropertiesObject = [PSCustomObject]@{
                    OldValues = @{}
                    NewValues = @{}
                }

                foreach ($personOldProperty in ($personOldProperties | Where-Object { $_.Name -in $personNewProperties.Name })) {
                    $personChangedPropertiesObject.OldValues.$($personOldProperty.Name) = $personOldProperty.Value
                }

                foreach ($personNewProperty in $personNewProperties) {
                    $personChangedPropertiesObject.NewValues.$($personNewProperty.Name) = $personNewProperty.Value
                }

                # Create object to update person as empty hashtable
                $objectUpdatePerson = @{}

                # Add the updated properties to object to update person
                foreach ($personNewProperty in $personNewProperties) {
                    # Enclose specific fields with single quotes
                    if ($personNewProperty.Name -in $personPropertiesToEncloseInSingleQuotes) {
                        [void]$objectUpdatePerson.Add("$($personNewProperty.Name)", "$($personNewProperty.Value)'")
                    }
                    # Enclose specific fields with hashtags
                    elseif ($personNewProperty.Name -in $personPropertiesToEncloseInHashtags) {
                        [void]$objectUpdatePerson.Add("$($personNewProperty.Name)", "#$($personNewProperty.Value)#")
                    }
                    else {
                        [void]$objectUpdatePerson.Add("$($personNewProperty.Name)", "$($personNewProperty.Value)")
                    }
                }

                # Seperate Properties with comma , and enclose values with single quotes ''
                $queryUpdatePersonPropertiesAndValues = ($objectUpdatePerson.Keys | ForEach-Object {
                        "$($_) = $($objectUpdatePerson.$_)"
                    }) -join " , "

                $queryUpdatePerson = "
                UPDATE
                    PERSON
                SET
                    $($queryUpdatePersonPropertiesAndValues)
                WHERE
                    $($personCorrelationField) = $($personCorrelationValue)
                "

                $updatePersonSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryUpdatePerson
                    QueryType  = "update"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Updating person with AccountReference: $($actionContext.References.Account.Person | ConvertTo-Json). SplatParams: $($updatePersonSplatParams | ConvertTo-Json)"   

                    $updatedPerson = Invoke-IProtectQuery @updatePersonSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Updated person with AccountReference: $($actionContext.References.Account.Person | ConvertTo-Json). Old values: $($personChangedPropertiesObject.oldValues | ConvertTo-Json). New values: $($personChangedPropertiesObject.newValues | ConvertTo-Json)"
                            IsError = $false
                        })

                }
                else {
                    Write-Warning "DryRun: Would update person with AccountReference: $($actionContext.References.Account.Person | ConvertTo-Json). SplatParams: $($updatePersonSplatParams | ConvertTo-Json)"
                }
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error updating person with AccountReference: $($actionContext.References.Account.Person | ConvertTo-Json). Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryUpdatePerson"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion Update person

            #region Set AccountReference and AccountData
            [void]$outputContext.AccountReference.add("Person", @{
                    "PERSONID" = "$($correlatedPerson.PERSONID)"
                })
    
            foreach ($correlatedPersonProperty in $correlatedPerson.PSObject.Properties | Where-Object { $_.Name -in $personPropertiesToExport }) {
                $outputContext.Data.Person | Add-Member -MemberType NoteProperty -Name $correlatedPersonProperty.Name -Value $correlatedPersonProperty.Value -Force
            }
            #endregion Set AccountReference and AccountData

            break
        }

        "NoChanges" {
            #region Set AccountReference and AccountData and create auditlog
            [void]$outputContext.AccountReference.add("Person", @{
                    "PERSONID" = "$($correlatedPerson.PERSONID)"
                })

            foreach ($correlatedPersonProperty in $correlatedPerson.PSObject.Properties | Where-Object { $_.Name -in $personPropertiesToExport }) {
                $outputContext.Data.Person | Add-Member -MemberType NoteProperty -Name $correlatedPersonProperty.Name -Value $correlatedPersonProperty.Value -Force
            }

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Skipped updating person with AccountReference: $($actionContext.References.Account.Person | ConvertTo-Json). Reason: No changes."
                    IsError = $false
                })
            #endregion Set AccountReference and AccountData and create auditlog

            break
        }

        "MultipleFound" {
            $auditMessage = "Multiple persons found where [$personCorrelationField] = [$($personCorrelationValue)]. Please correct this so the persons are unique."

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $true
                })
        
            # Throw terminal error
            throw $auditMessage

            break
        }

        "NotFound" {
            $auditMessage = "No person found where [$($personCorrelationField)] = [$($personCorrelationValue)]. Possibly indicating that it could be deleted, or not correlated."

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

    #region Get current Employee
    try {
        $queryCorrelateEmployee = "
            SELECT
                $($employeePropertiesToQuery -Join ',')
            FROM
                EMPLOYEE
            WHERE
                $employeeCorrelationField = $($employeeCorrelationValue)
            "

        $correlateEmployeeSplatParams = @{
            BaseUrl    = $actionContext.Configuration.BaseUrl
            JSessionID = $jSessionID
            Query      = $queryCorrelateEmployee
            QueryType  = "query"
        }

        Write-Verbose "Querying employee where [$employeeCorrelationField] = [$($employeeCorrelationValue)]. SplatParams: $($correlateEmployeeSplatParams | ConvertTo-Json)"

        $correlatedEmployee = $null
        $correlatedEmployee = Invoke-IProtectQuery @correlateEmployeeSplatParams
            
        Write-Verbose "Queried employee where [$employeeCorrelationField] = [$($employeeCorrelationValue)]. Result: $($correlatedEmployee | Out-String)"
    }
    catch {
        $ex = $PSItem

        $auditMessage = "Error querying employee where [$employeeCorrelationField] = [$($employeeCorrelationValue)]. Error: $($ex.Exception.Message)"
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
    #endregion Get current Employee

    if (($correlatedEmployee | Measure-Object).count -eq 1) {
        try {
            Write-Verbose "Comparing current employee to mapped properties"

            # Create reference object from correlated account
            $employeeReferenceObject = [PSCustomObject]@{}
            foreach ($correlatedEmployeeProperty in $correlatedEmployee.PSObject.Properties) {
                $employeeReferenceObject | Add-Member -MemberType NoteProperty -Name $correlatedEmployeeProperty.Name -Value $correlatedEmployeeProperty.Value -Force
            }

            # Create difference object from mapped properties
            $employeeDifferenceObject = [PSCustomObject]@{}
            foreach ($employeeAccountProperty in $employeeAccount.PSObject.Properties) {
                $employeeDifferenceObject | Add-Member -MemberType NoteProperty -Name $employeeAccountProperty.Name -Value $employeeAccountProperty.Value -Force
            }

            $employeeSplatCompareProperties = @{
                ReferenceObject  = $employeeReferenceObject.PSObject.Properties | Where-Object { $_.Name -in $employeePropertiesToCompare }
                DifferenceObject = $employeeDifferenceObject.PSObject.Properties | Where-Object { $_.Name -in $employeePropertiesToCompare }
            }
            if ($null -ne $employeeSplatCompareProperties.ReferenceObject -and $null -ne $employeeSplatCompareProperties.DifferenceObject) {
                $employeePropertiesChanged = Compare-Object @employeeSplatCompareProperties -PassThru
                $employeeOldProperties = $employeePropertiesChanged | Where-Object { $_.SideIndicator -eq "<=" }
                $employeeNewProperties = $employeePropertiesChanged | Where-Object { $_.SideIndicator -eq "=>" }
            }

            if ($employeeNewProperties) {
                $actionEmployee = "Update"
                Write-Information "Employee property(s) required to update: $($employeeNewProperties.Name -join ', ')"
            }
            else {
                $actionEmployee = "NoChanges"
            }            

            Write-Verbose "Compared current employee to mapped properties"
        }
        catch {
            $ex = $PSItem

            $auditMessage = "Error comparing current employee to mapped properties. Error: $($ex.Exception.Message)"
            Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $true
                })
    
            # Throw terminal error
            throw $auditMessage
        }
    }
    elseif (($correlatedEmployee | Measure-Object).count -gt 1) {
        $actionEmployee = "MultipleFound"
    }
    elseif (($correlatedEmployee | Measure-Object).count -eq 0) {
        $actionEmployee = "NotFound"
    }

    # Process
    switch ($actionEmployee) {
        "Update" {
            #region Update employee
            try {
                # Create custom object with old and new values (for logging)
                $employeeChangedPropertiesObject = [PSCustomObject]@{
                    OldValues = @{}
                    NewValues = @{}
                }

                foreach ($employeeOldProperty in ($employeeOldProperties | Where-Object { $_.Name -in $employeeNewProperties.Name })) {
                    $employeeChangedPropertiesObject.OldValues.$($employeeOldProperty.Name) = $employeeOldProperty.Value
                }

                foreach ($employeeNewProperty in $employeeNewProperties) {
                    $employeeChangedPropertiesObject.NewValues.$($employeeNewProperty.Name) = $employeeNewProperty.Value
                }

                # Create object to update employee as empty hashtable
                $objectUpdateEmployee = @{}

                # Add the updated properties to object to update employee
                foreach ($employeeNewProperty in $employeeNewProperties) {
                    # Enclose specific fields with single quotes
                    if ($employeeNewProperty.Name -in $employeePropertiesToEncloseInSingleQuotes) {
                        [void]$objectUpdateEmployee.Add("$($employeeNewProperty.Name)", "$($employeeNewProperty.Value)'")
                    }
                    # Enclose specific fields with hashtags
                    elseif ($employeeNewProperty.Name -in $employeePropertiesToEncloseInHashtags) {
                        [void]$objectUpdateEmployee.Add("$($employeeNewProperty.Name)", "#$($employeeNewProperty.Value)#")
                    }
                    else {
                        [void]$objectUpdateEmployee.Add("$($employeeNewProperty.Name)", "$($employeeNewProperty.Value)")
                    }
                }

                # Seperate Properties with comma , and enclose values with single quotes ''
                $queryUpdateEmployeePropertiesAndValues = ($objectUpdateEmployee.Keys | ForEach-Object {
                        "$($_) = $($objectUpdateEmployee.$_)"
                    }) -join " , "

                $queryUpdateEmployee = "
                UPDATE
                    EMPLOYEE
                SET
                    $($queryUpdateEmployeePropertiesAndValues)
                WHERE
                    $($employeeCorrelationField) = $($employeeCorrelationValue)
                "

                $updateEmployeeSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryUpdateEmployee
                    QueryType  = "update"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Updating employee with AccountReference: $($actionContext.References.Account.Employee | ConvertTo-Json). SplatParams: $($updateEmployeeSplatParams | ConvertTo-Json)"   

                    $updatedEmployee = Invoke-IProtectQuery @updateEmployeeSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Updated employee with AccountReference: $($actionContext.References.Account.Employee | ConvertTo-Json). Old values: $($employeeChangedPropertiesObject.oldValues | ConvertTo-Json). New values: $($employeeChangedPropertiesObject.newValues | ConvertTo-Json)"
                            IsError = $false
                        })

                }
                else {
                    Write-Warning "DryRun: Would update employee with AccountReference: $($actionContext.References.Account.Employee | ConvertTo-Json). SplatParams: $($updateEmployeeSplatParams | ConvertTo-Json)"
                }
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error updating employee with AccountReference: $($actionContext.References.Account.Employee | ConvertTo-Json). Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryUpdateEmployee"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion Update employee            

            #region Set AccountReference and AccountData
            [void]$outputContext.AccountReference.add("Employee", @{
                    "EMPLOYEEID" = "$($correlatedEmployee.EMPLOYEEID)"
                })

            foreach ($correlatedEmployeeProperty in $correlatedEmployee.PSObject.Properties | Where-Object { $_.Name -in $employeePropertiesToExport }) {
                $outputContext.Data.Employee | Add-Member -MemberType NoteProperty -Name $correlatedEmployeeProperty.Name -Value $correlatedEmployeeProperty.Value -Force
            }
            #endregion Set AccountReference and AccountData

            break
        }

        "NoChanges" {
            #region Set AccountReference and AccountData and create auditlog
            [void]$outputContext.AccountReference.add("Employee", @{
                    "EMPLOYEEID" = "$($correlatedEmployee.EMPLOYEEID)"
                })

            foreach ($correlatedEmployeeProperty in $correlatedEmployee.PSObject.Properties | Where-Object { $_.Name -in $employeePropertiesToExport }) {
                $outputContext.Data.Employee | Add-Member -MemberType NoteProperty -Name $correlatedEmployeeProperty.Name -Value $correlatedEmployeeProperty.Value -Force
            }

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Skipped updating employee with AccountReference: $($actionContext.References.Account.Employee | ConvertTo-Json). Reason: No changes."
                    IsError = $false
                })
            #endregion Set AccountReference and AccountData and create auditlog

            break
        }

        "MultipleFound" {
            $auditMessage = "Multiple employees found where [$employeeCorrelationField] = [$($employeeCorrelationValue)]. Please correct this so the employees are unique."

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $true
                })
        
            # Throw terminal error
            throw $auditMessage

            break
        }

        "NotFound" {
            $auditMessage = "No employee found where [$($employeeCorrelationField)] = [$($employeeCorrelationValue)]. Possibly indicating that it could be deleted, or not correlated."

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
    # Set PersonID with PersonID of created or correlated person
    $keyCardAccount.PERSONID = $correlatedPerson.PERSONID

    #region Get current KeyCard
    try {
        $queryCorrelateKeyCard = "
            SELECT
                $($keyCardPropertiesToQuery -Join ',')
            FROM
                ACCESSKEY
            WHERE
                $keyCardCorrelationField = $($keyCardCorrelationValue)
            "

        $correlateKeyCardSplatParams = @{
            BaseUrl    = $actionContext.Configuration.BaseUrl
            JSessionID = $jSessionID
            Query      = $queryCorrelateKeyCard
            QueryType  = "query"
        }

        Write-Verbose "Querying keyCard where [$keyCardCorrelationField] = [$($keyCardCorrelationValue)]. SplatParams: $($correlateKeyCardSplatParams | ConvertTo-Json)"

        $correlatedKeyCard = $null
        $correlatedKeyCard = Invoke-IProtectQuery @correlateKeyCardSplatParams
            
        Write-Verbose "Queried keyCard where [$keyCardCorrelationField] = [$($keyCardCorrelationValue)]. Result: $($correlatedKeyCard | Out-String)"
    }
    catch {
        $ex = $PSItem

        $auditMessage = "Error querying keyCard where [$keyCardCorrelationField] = [$($keyCardCorrelationValue)]. Error: $($ex.Exception.Message)"
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
    #endregion Get current KeyCard

    if (($correlatedKeyCard | Measure-Object).count -eq 1) {
        try {
            Write-Verbose "Comparing current keyCard to mapped properties"

            # Create reference object from correlated account
            $keyCardReferenceObject = [PSCustomObject]@{}
            foreach ($correlatedKeyCardProperty in $correlatedKeyCard.PSObject.Properties) {
                $keyCardReferenceObject | Add-Member -MemberType NoteProperty -Name $correlatedKeyCardProperty.Name -Value $correlatedKeyCardProperty.Value -Force
            }

            # Create difference object from mapped properties
            $keyCardDifferenceObject = [PSCustomObject]@{}
            foreach ($keyCardAccountProperty in $keyCardAccount.PSObject.Properties) {
                $keyCardDifferenceObject | Add-Member -MemberType NoteProperty -Name $keyCardAccountProperty.Name -Value $keyCardAccountProperty.Value -Force
            }

            $keyCardSplatCompareProperties = @{
                ReferenceObject  = $keyCardReferenceObject.PSObject.Properties | Where-Object { $_.Name -in $keyCardPropertiesToCompare }
                DifferenceObject = $keyCardDifferenceObject.PSObject.Properties | Where-Object { $_.Name -in $keyCardPropertiesToCompare }
            }
            if ($null -ne $keyCardSplatCompareProperties.ReferenceObject -and $null -ne $keyCardSplatCompareProperties.DifferenceObject) {
                $keyCardPropertiesChanged = Compare-Object @keyCardSplatCompareProperties -PassThru
                $keyCardOldProperties = $keyCardPropertiesChanged | Where-Object { $_.SideIndicator -eq "<=" }
                $keyCardNewProperties = $keyCardPropertiesChanged | Where-Object { $_.SideIndicator -eq "=>" }
            }

            if ($keyCardNewProperties) {
                if ([string]::IsNullOrEmpty($keyCardNewProperties.Value)) {
                    $actionKeyCard = "Delete"
                }
                else {
                    $actionKeyCard = "Update"
                    Write-Information "Keycard property(s) required to update: $($keyCardNewProperties.Name -join ', ')"
                }
            }
            else {
                $actionKeyCard = "NoChanges"
            }

            Write-Verbose "Compared current keyCard to mapped properties"
        }
        catch {
            $ex = $PSItem

            $auditMessage = "Error comparing current keyCard to mapped properties. Error: $($ex.Exception.Message)"
            Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $true
                })
    
            # Throw terminal error
            throw $auditMessage
        }
    }
    elseif (($correlatedKeyCard | Measure-Object).count -gt 1) {
        $actionKeyCard = "MultipleFound"
    }
    elseif (($correlatedKeyCard | Measure-Object).count -eq 0) {
        $actionKeyCard = "NotFound"
    }

    # Process
    switch ($actionKeyCard) {
        "Update" {
            #region 20230703-021 - GK - Retrieve current permissions of old keycard
            try {
                $queryGetPermissionsKeyCard = "
                SELECT
                    ACCESSKEYID,
                    KEYGROUPID,
                    KEYKEYGROUPID
                FROM
                    KEYKEYGROUP
                WHERE
                    $($keyCardCorrelationField) = $($keyCardCorrelationValue)
                "

                $getPermissionsKeyCardSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryGetPermissionsKeyCard
                    QueryType  = "query"
                }

                Write-Verbose "Querying permissions of keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. SplatParams: $($getPermissionsKeyCardSplatParams | ConvertTo-Json)"

                $currentPermissionsKeyCard = $null
                $currentPermissionsKeyCard = Invoke-IProtectQuery @getPermissionsKeyCardSplatParams

                Write-Verbose "Queried permissions of keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. Result: $($currentPermissionsKeyCard | Out-String)"
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error querying permissions of keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryGetPermissionsKeyCard"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion 20230703-021 - GK - Retrieve current permissions of old keycard

            #region 20230703-021 - GK - Create new keycard
            #region Create keycard
            try {
                $objectCreateKeyCard = @{}

                # Add the mapped fields to object to create keycard
                foreach ($keyCardAccountProperty in $keyCardAccount.PsObject.Properties | Where-Object { $null -ne $_.Value }) {
                    # Enclose specific fields with single quotes
                    if ($keyCardAccountProperty.Name -in $keyCardPropertiesToEncloseInSingleQuotes) {
                        [void]$objectCreateKeyCard.Add("$($keyCardAccountProperty.Name)", "$($keyCardAccountProperty.Value)'")
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
                #region Get created keycard by CARDCLASSID and RCN
                try {
                    $queryGetKeyCard = "
                    SELECT
                        $($keyCardPropertiesToQuery -Join ',')
                    FROM
                        ACCESSKEY
                    WHERE
                        CARDCLASSID = $($keyCardAccount.CARDCLASSID)
                        AND RCN = $($keyCardAccount.RCN)'
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
                #endregion Get created keycard by CARDCLASSID and RCN

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
            #endregion 20230703-021 - GK - Create new keycard

            #region 20230703-021 - GK - Assign permissions of old keycard to new keycard
            if (($currentPermissionsKeyCard | Measure-Object).Count -ge 1) {
                foreach ($currentPermissionKeyCard in $currentPermissionsKeyCard) {
                    #region Create permission for keycard
                    try {
                        $objectCreatePermissionKeyCard = @{
                            ACCESSKEYID = "$($correlatedKeyCard.ACCESSKEYID)"
                            KEYGROUPID  = "$($currentPermissionKeyCard.KEYGROUPID)"
                        }
    
                        # Seperate Property Names with comma ,
                        $queryCreatePermissionKeyCardProperties = $(($objectCreatePermissionKeyCard.Keys -join ","))
                        # Seperate Property Values with comma ,
                        $queryCreatePermissionKeyCardValues = $(($objectCreatePermissionKeyCard.Values -join ","))
    
                        $queryCreatePermissionKeyCard = "
                        INSERT INTO KEYKEYGROUP
                            ($($queryCreatePermissionKeyCardProperties))
                        VALUES
                            ($($queryCreatePermissionKeyCardValues))
                        "
        
                        $createPermissionKeyCardSplatParams = @{
                            BaseUrl    = $actionContext.Configuration.BaseUrl
                            JSessionID = $jSessionID
                            Query      = $queryCreatePermissionKeyCard
                            QueryType  = "update"
                        }
            
                        if (-Not($actionContext.DryRun -eq $true)) {
                            Write-Verbose "Creating permission where [KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)] for keycard with AccountReference: $($outputContext.AccountReference.KeyCard | ConvertTo-Json). SplatParams: $($createPermissionKeyCardSplatParams | ConvertTo-Json)"
            
                            $createdPermissionKeyCard = $null
                            $createdPermissionKeyCard = Invoke-IProtectQuery @createPermissionKeyCardSplatParams
    
                            $outputContext.AuditLogs.Add([PSCustomObject]@{
                                    # Action  = "" # Optional
                                    Message = "Created permission where [KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)] for keycard with AccountReference: $($outputContext.AccountReference.KeyCard | ConvertTo-Json)"
                                    IsError = $false
                                })
                        }
                        else {
                            Write-Warning "DryRun: Would create permission where [KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)] for keycard with AccountReference: $($outputContext.AccountReference.KeyCard | ConvertTo-Json). SplatParams: $($createPermissionKeyCardSplatParams | ConvertTo-Json)"
                        }
                    }
                    catch {
                        $ex = $PSItem

                        $auditMessage = "Error creating permission where [KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)] for keycard with AccountReference: $($outputContext.AccountReference.KeyCard | ConvertTo-Json). Error: $($ex.Exception.Message)"
                        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
            
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = $auditMessage
                                IsError = $true
                            })
            
                        # Log query
                        Write-Warning "Query: $querycreatePermissionKeyCard"
            
                        # Throw terminal error
                        throw $auditMessage
                    }
                    #endregion Create permission for keycard
                }
            }
            else {
                $auditMessage = "Skipped creating permissions of keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. Reason: No permissions found where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]."

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $false
                    })
            }
            #endregion 20230703-021 - GK - assign permissions of old keycard to new keycard

            #region 20230703-021 - GK - Delete current permissions of old keycard
            if (($currentPermissionsKeyCard | Measure-Object).Count -ge 1) {
                foreach ($currentPermissionKeyCard in $currentPermissionsKeyCard) {
                    #region Delete permission of keycard
                    try {
                        $queryDeletePermissionKeyCard = "
                        DELETE
                        FROM
                            KEYKEYGROUP
                        WHERE
                            KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)
                            AND $($keyCardCorrelationField) = $($keyCardCorrelationValue)
                        "
        
                        $deletePermissionKeyCardSplatParams = @{
                            BaseUrl    = $actionContext.Configuration.BaseUrl
                            JSessionID = $jSessionID
                            Query      = $querydeletePermissionKeyCard
                            QueryType  = "update"
                        }
            
                        if (-Not($actionContext.DryRun -eq $true)) { 
                            Write-Verbose "Deleting permission where [KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deletePermissionKeyCardSplatParams | ConvertTo-Json)"
            
                            $deletedPermissionKeyCard = $null
                            $deletedPermissionKeyCard = Invoke-IProtectQuery @deletePermissionKeyCardSplatParams
    
                            $outputContext.AuditLogs.Add([PSCustomObject]@{
                                    # Action  = "" # Optional
                                    Message = "Deleted permission where [KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json)"
                                    IsError = $false
                                })
                        }
                        else {
                            Write-Warning "DryRun: Would delete permission where [KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deletePermissionKeyCardSplatParams | ConvertTo-Json)"
                        }
                    }
                    catch {
                        $ex = $PSItem

                        $auditMessage = "Error deleting permission where [KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Error: $($ex.Exception.Message)"
                        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
            
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = $auditMessage
                                IsError = $true
                            })
            
                        # Log query
                        Write-Warning "Query: $querydeletePermissionKeyCard"
            
                        # Throw terminal error
                        throw $auditMessage
                    }
                    #endregion Delete permission of keycard
                }
            }
            else {
                $auditMessage = "Skipped deleting permissions of keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. Reason: No permissions found where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]."

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $false
                    })
            }
            #endregion 20230703-021 - GK - Delete current permissions of old keycard

            #region 20230703-021 - GK - Delete old keycard offline access rights
            #region Check if offline access rights for keycard exists
            try {
                $queryGetOfflineAccessRightsKeyCard = "
                SELECT
                    *
                FROM
                    OFFLINEACCESSRIGHTS
                WHERE
                    $($keyCardCorrelationField) = $($keyCardCorrelationValue)
                "

                $GetOfflineAccessRightsKeyCardSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryGetOfflineAccessRightsKeyCard
                    QueryType  = "query"
                }

                Write-Verbose "Querying offline access rights for keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. SplatParams: $($GetOfflineAccessRightsKeyCardSplatParams | ConvertTo-Json)"

                $currentOfflineAccessRightsKeyCard = $null
                $currentOfflineAccessRightsKeyCard = Invoke-IProtectQuery @GetOfflineAccessRightsKeyCardSplatParams

                Write-Verbose "Queried offline access rights for keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. Result: $($currentOfflineAccessRightsKeyCard | Out-String)"
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error querying offline access rights for keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryGetOfflineAccessRightsKeyCard"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion Check if offline access rights for keycard exists

            if (($currentOfflineAccessRightsKeyCard | Measure-Object).Count -ge 1) {
                #region Delete offline access rights for keycard
                try {
                    $queryDeleteOfflineAccessRightsKeyCard = "
                    DELETE
                        *
                    FROM
                        OFFLINEACCESSRIGHTS
                    WHERE
                        $($keyCardCorrelationField) = $($keyCardCorrelationValue)
                    "
    
                    $deleteOfflineAccessRightsKeyCardSplatParams = @{
                        BaseUrl    = $actionContext.Configuration.BaseUrl
                        JSessionID = $jSessionID
                        Query      = $querydeleteOfflineAccessRightsKeyCard
                        QueryType  = "update"
                    }
        
                    if (-Not($actionContext.DryRun -eq $true)) { 
                        Write-Verbose "Deleting offline access rights of keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deleteOfflineAccessRightsKeyCardSplatParams | ConvertTo-Json)"
        
                        $deletedOfflineAccessRightsKeyCard = $null
                        $deletedOfflineAccessRightsKeyCard = Invoke-IProtectQuery @deleteOfflineAccessRightsKeyCardSplatParams

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Deleted offline access rights of keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json)"
                                IsError = $false
                            })
                    }
                    else {
                        Write-Warning "DryRun: Would delete offline access rights of keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deleteOfflineAccessRightsKeyCardSplatParams | ConvertTo-Json)"
                    }
                }
                catch {
                    $ex = $PSItem

                    $auditMessage = "Error deleting offline access rights of keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Error: $($ex.Exception.Message)"
                    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $true
                        })
        
                    # Log query
                    Write-Warning "Query: $querydeleteOfflineAccessRightsKeyCard"
        
                    # Throw terminal error
                    throw $auditMessage
                }
                #endregion Delete offline access rights for keycard
            }
            else {
                $auditMessage = "Skipped deleting offline access rights from the keycard. Reason: No offline access rights found of keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json)."

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $false
                    })
            }
            #endregion 20230703-021 - GK - Delete old keycard offline access rights

            #region 20230703-021 - GK - Delete old keycard
            try {
                $queryDeleteKeyCard = "
                DELETE
                FROM
                    ACCESSKEY
                WHERE
                    $($keyCardCorrelationField) = $($keyCardCorrelationValue)
                "

                $deleteKeyCardSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryDeleteKeyCard
                    QueryType  = "update"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Deleting keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deleteKeyCardSplatParams | ConvertTo-Json)"   

                    $deletedKeyCard = Invoke-IProtectQuery @deleteKeyCardSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Deleted keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json)"
                            IsError = $false
                        })

                }
                else {
                    Write-Warning "DryRun: Would delete keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deleteKeyCardSplatParams | ConvertTo-Json)"
                }
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error deleting keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryDeleteKeyCard"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion 20230703-021 - GK - Delete old keycard

            #region Set AccountReference and AccountData
            [void]$outputContext.AccountReference.add("KeyCard", @{
                    "ACCESSKEYID" = "$($correlatedKeyCard.ACCESSKEYID)"
                })
        
            foreach ($correlatedKeyCardProperty in $correlatedKeyCard.PSObject.Properties | Where-Object { $_.Name -in $keyCardPropertiesToExport }) {
                $outputContext.Data.KeyCard | Add-Member -MemberType NoteProperty -Name $correlatedKeyCardProperty.Name -Value $correlatedKeyCardProperty.Value -Force
            }
            #endregion Set AccountReference and AccountData

            break
        }

        "Delete" {
            #region 20230703-021 - GK - Delete all assigned groups from keycard
            #region Retrieve current permissions of keycard
            try {
                $queryGetPermissionsKeyCard = "
                SELECT
                    ACCESSKEYID,
                    KEYGROUPID,
                    KEYKEYGROUPID
                FROM
                    KEYKEYGROUP
                WHERE
                    $($keyCardCorrelationField) = $($keyCardCorrelationValue)
                "

                $getPermissionsKeyCardSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryGetPermissionsKeyCard
                    QueryType  = "query"
                }

                Write-Verbose "Querying permissions of keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. SplatParams: $($getPermissionsKeyCardSplatParams | ConvertTo-Json)"

                $currentPermissionsKeyCard = $null
                $currentPermissionsKeyCard = Invoke-IProtectQuery @getPermissionsKeyCardSplatParams

                Write-Verbose "Queried permissions of keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. Result: $($currentPermissionsKeyCard | Out-String)"
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error querying permissions of keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryGetPermissionsKeyCard"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion Retrieve current permissions of keycard

            #region Delete current permissions of keycard
            if (($currentPermissionsKeyCard | Measure-Object).Count -ge 1) {
                foreach ($currentPermissionKeyCard in $currentPermissionsKeyCard) {
                    #region Delete permission of keycard
                    try {
                        $queryDeletePermissionKeyCard = "
                        DELETE
                        FROM
                            KEYKEYGROUP
                        WHERE
                            KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)
                        "
        
                        $deletePermissionKeyCardSplatParams = @{
                            BaseUrl    = $actionContext.Configuration.BaseUrl
                            JSessionID = $jSessionID
                            Query      = $querydeletePermissionKeyCard
                            QueryType  = "update"
                        }
            
                        Write-Verbose "Deleting permission of keycard where [KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)]. SplatParams: $($deletePermissionKeyCardSplatParams | ConvertTo-Json)"
            
                        $deletedPermissionKeyCard = $null
                        $deletedPermissionKeyCard = Invoke-IProtectQuery @deletePermissionKeyCardSplatParams
    
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Deleted permission of keycard where [KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)]"
                                IsError = $false
                            })
                    }
                    catch {
                        $ex = $PSItem

                        $auditMessage = "Error deleting permission of keycard where [KEYKEYGROUPID = $($currentPermissionKeyCard.KEYKEYGROUPID)]. Error: $($ex.Exception.Message)"
                        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
            
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = $auditMessage
                                IsError = $true
                            })
            
                        # Log query
                        Write-Warning "Query: $querydeletePermissionKeyCard"
            
                        # Throw terminal error
                        throw $auditMessage
                    }
                    #endregion Delete permission of keycard
                }
                #endregion Delete current permissions of keycard
            }
            else {
                $auditMessage = "Skipped deleting permissions of keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. Reason: No permissions found where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]."

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $false
                    })
            }
            #endregion 20230703-021 - GK - Delete all assigned groups from keycard

            #region 20230703-021 - GK - Delete offline access rights
            #region Check if offline access rights for keycard exists
            try {
                $queryGetOfflineAccessRightsKeyCard = "
                SELECT
                    *
                FROM
                    OFFLINEACCESSRIGHTS
                WHERE
                    $($keyCardCorrelationField) = $($keyCardCorrelationValue)
                "

                $GetOfflineAccessRightsKeyCardSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryGetOfflineAccessRightsKeyCard
                    QueryType  = "query"
                }

                Write-Verbose "Querying offline access rights for keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. SplatParams: $($GetOfflineAccessRightsKeyCardSplatParams | ConvertTo-Json)"

                $currentOfflineAccessRightsKeyCard = $null
                $currentOfflineAccessRightsKeyCard = Invoke-IProtectQuery @GetOfflineAccessRightsKeyCardSplatParams

                Write-Verbose "Queried offline access rights for keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. Result: $($currentOfflineAccessRightsKeyCard | Out-String)"
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error querying offline access rights for keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryGetOfflineAccessRightsKeyCard"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion Check if offline access rights for keycard exists

            if (($currentOfflineAccessRightsKeyCard | Measure-Object).Count -ge 1) {
                #region Delete offline access rights for keycard
                try {
                    $queryDeleteOfflineAccessRightsKeyCard = "
                    DELETE
                        *
                    FROM
                        OFFLINEACCESSRIGHTS
                    WHERE
                        $($keyCardCorrelationField) = $($keyCardCorrelationValue)
                    "
    
                    $deleteOfflineAccessRightsKeyCardSplatParams = @{
                        BaseUrl    = $actionContext.Configuration.BaseUrl
                        JSessionID = $jSessionID
                        Query      = $querydeleteOfflineAccessRightsKeyCard
                        QueryType  = "update"
                    }
        
                    Write-Verbose "Deleting offline access rights of keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. SplatParams: $($deleteOfflineAccessRightsKeyCardSplatParams | ConvertTo-Json)"
        
                    $deletedOfflineAccessRightsKeyCard = $null
                    $deletedOfflineAccessRightsKeyCard = Invoke-IProtectQuery @deleteOfflineAccessRightsKeyCardSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Deleted offline access rights of keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]"
                            IsError = $false
                        })
                }
                catch {
                    $ex = $PSItem

                    $auditMessage = "Error deleting offline access rights of keycard where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]. Error: $($ex.Exception.Message)"
                    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $true
                        })
        
                    # Log query
                    Write-Warning "Query: $querydeleteOfflineAccessRightsKeyCard"
        
                    # Throw terminal error
                    throw $auditMessage
                }
                #endregion Delete offline access rights for keycard
            }
            else {
                $auditMessage = "Skipped deleting offline access rights from the keycard. Reason: No offline access rights found where [$($keyCardCorrelationField) = $($keyCardCorrelationValue)]."

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $false
                    })
            }
            #endregion 20230703-021 - GK - Delete offline access rights

            #region Delete keycard
            try {
                $queryDeleteKeyCard = "
                DELETE
                FROM
                    ACCESSKEY
                WHERE
                    $($keyCardCorrelationField) = $($keyCardCorrelationValue)
                "

                $deleteKeyCardSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryDeleteKeyCard
                    QueryType  = "update"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Deleting keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deleteKeyCardSplatParams | ConvertTo-Json)"   

                    $deletedKeyCard = Invoke-IProtectQuery @deleteKeyCardSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Deleted keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json)"
                            IsError = $false
                        })

                }
                else {
                    Write-Warning "DryRun: Would delete keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deleteKeyCardSplatParams | ConvertTo-Json)"
                }
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error deleting keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryDeleteKeyCard"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion Delete keycard

            break
        }

        "NoChanges" {
            #region Set AccountReference and AccountData and create auditlog
            [void]$outputContext.AccountReference.add("KeyCard", @{
                    "ACCESSKEYID" = "$($correlatedKeyCard.ACCESSKEYID)"
                })

            foreach ($correlatedKeyCardProperty in $correlatedKeyCard.PSObject.Properties | Where-Object { $_.Name -in $keyCardPropertiesToExport }) {
                $outputContext.Data.KeyCard | Add-Member -MemberType NoteProperty -Name $correlatedKeyCardProperty.Name -Value $correlatedKeyCardProperty.Value -Force
            }

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Skipped updating keyCard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Reason: No changes."
                    IsError = $false
                })
            #endregion Set AccountReference and AccountData and create auditlog

            break
        }

        "MultipleFound" {
            $auditMessage = "Multiple keyCards found where [$keyCardCorrelationField] = [$($keyCardCorrelationValue)]. Please correct this so the keyCards are unique."

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $true
                })
        
            # Throw terminal error
            throw $auditMessage

            break
        }

        "NotFound" {
            $auditMessage = "No keyCard found where [$($keyCardCorrelationField)] = [$($keyCardCorrelationValue)]. Possibly indicating that it could be deleted, or not correlated."

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
    #endregion KeyCard

    #region LicensePlate
    # Set PersonID with PersonID of created or correlated person
    $licensePlateAccount.PERSONID = $correlatedPerson.PERSONID

    #region Get current LicensePlate
    try {
        $queryCorrelateLicensePlate = "
            SELECT
                $($licensePlatePropertiesToQuery -Join ',')
            FROM
                ACCESSKEY
            WHERE
                $licensePlateCorrelationField = $($licensePlateCorrelationValue)
            "

        $correlateLicensePlateSplatParams = @{
            BaseUrl    = $actionContext.Configuration.BaseUrl
            JSessionID = $jSessionID
            Query      = $queryCorrelateLicensePlate
            QueryType  = "query"
        }

        Write-Verbose "Querying licensePlate where [$licensePlateCorrelationField] = [$($licensePlateCorrelationValue)]. SplatParams: $($correlateLicensePlateSplatParams | ConvertTo-Json)"

        $correlatedLicensePlate = $null
        $correlatedLicensePlate = Invoke-IProtectQuery @correlateLicensePlateSplatParams
            
        Write-Verbose "Queried licensePlate where [$licensePlateCorrelationField] = [$($licensePlateCorrelationValue)]. Result: $($correlatedLicensePlate | Out-String)"
    }
    catch {
        $ex = $PSItem

        $auditMessage = "Error querying licensePlate where [$licensePlateCorrelationField] = [$($licensePlateCorrelationValue)]. Error: $($ex.Exception.Message)"
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
    #endregion Get current LicensePlate

    if (($correlatedLicensePlate | Measure-Object).count -eq 1) {
        try {
            Write-Verbose "Comparing current licensePlate to mapped properties"

            # Create reference object from correlated account
            $licensePlateReferenceObject = [PSCustomObject]@{}
            foreach ($correlatedLicensePlateProperty in $correlatedLicensePlate.PSObject.Properties) {
                $licensePlateReferenceObject | Add-Member -MemberType NoteProperty -Name $correlatedLicensePlateProperty.Name -Value $correlatedLicensePlateProperty.Value -Force
            }

            # Create difference object from mapped properties
            $licensePlateDifferenceObject = [PSCustomObject]@{}
            foreach ($licensePlateAccountProperty in $licensePlateAccount.PSObject.Properties) {
                $licensePlateDifferenceObject | Add-Member -MemberType NoteProperty -Name $licensePlateAccountProperty.Name -Value $licensePlateAccountProperty.Value -Force
            }

            $licensePlateSplatCompareProperties = @{
                ReferenceObject  = $licensePlateReferenceObject.PSObject.Properties | Where-Object { $_.Name -in $licensePlatePropertiesToCompare }
                DifferenceObject = $licensePlateDifferenceObject.PSObject.Properties | Where-Object { $_.Name -in $licensePlatePropertiesToCompare }
            }
            if ($null -ne $licensePlateSplatCompareProperties.ReferenceObject -and $null -ne $licensePlateSplatCompareProperties.DifferenceObject) {
                $licensePlatePropertiesChanged = Compare-Object @licensePlateSplatCompareProperties -PassThru
                $licensePlateOldProperties = $licensePlatePropertiesChanged | Where-Object { $_.SideIndicator -eq "<=" }
                $licensePlateNewProperties = $licensePlatePropertiesChanged | Where-Object { $_.SideIndicator -eq "=>" }
            }

            if ($licensePlateNewProperties) {
                if ([string]::IsNullOrEmpty($licensePlateNewProperties.Value)) {
                    if ($correlatedLicensePlate.PERSONID -eq $licensePlateAccount.PERSONID) {
                        $actionLicensePlate = "Unassign"
                    }
                    else {
                        $actionLicensePlate = "NoChanges"
                    }
                }
                else {
                    $actionLicensePlate = "Update"
                    Write-Information "Licenseplate property(s) required to update: $($licensePlateNewProperties.Name -join ', ')"
                }
            }
            else {
                $actionLicensePlate = "NoChanges"
            }

            Write-Verbose "Compared current licensePlate to mapped properties"
        }
        catch {
            $ex = $PSItem

            $auditMessage = "Error comparing current licensePlate to mapped properties. Error: $($ex.Exception.Message)"
            Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $true
                })
    
            # Throw terminal error
            throw $auditMessage
        }
    }
    elseif (($correlatedLicensePlate | Measure-Object).count -gt 1) {
        $actionLicensePlate = "MultipleFound"
    }
    elseif (($correlatedLicensePlate | Measure-Object).count -eq 0) {
        $actionLicensePlate = "NotFound"
    }

    # Process
    switch ($actionLicensePlate) {
        "Update" {
            #region Update licensePlate
            try {
                # Create custom object with old and new values (for logging)
                $licensePlateChangedPropertiesObject = [PSCustomObject]@{
                    OldValues = @{}
                    NewValues = @{}
                }

                foreach ($licensePlateOldProperty in ($licensePlateOldProperties | Where-Object { $_.Name -in $licensePlateNewProperties.Name })) {
                    $licensePlateChangedPropertiesObject.OldValues.$($licensePlateOldProperty.Name) = $licensePlateOldProperty.Value
                }

                foreach ($licensePlateNewProperty in $licensePlateNewProperties) {
                    $licensePlateChangedPropertiesObject.NewValues.$($licensePlateNewProperty.Name) = $licensePlateNewProperty.Value
                }

                # Create object to update licensePlate as empty hashtable
                $objectUpdateLicensePlate = @{}

                # Add the updated properties to object to update licensePlate
                foreach ($licensePlateNewProperty in $licensePlateNewProperties) {
                    # Enclose specific fields with single quotes
                    if ($licensePlateNewProperty.Name -in $licensePlatePropertiesToEncloseInSingleQuotes) {
                        [void]$objectUpdateLicensePlate.Add("$($licensePlateNewProperty.Name)", "$($licensePlateNewProperty.Value)'")
                    }
                    # Enclose specific fields with hashtags
                    elseif ($licensePlateNewProperty.Name -in $licensePlatePropertiesToEncloseInHashtags) {
                        [void]$objectUpdateLicensePlate.Add("$($licensePlateNewProperty.Name)", "#$($licensePlateNewProperty.Value)#")
                    }
                    else {
                        [void]$objectUpdateLicensePlate.Add("$($licensePlateNewProperty.Name)", "$($licensePlateNewProperty.Value)")
                    }
                }

                # Seperate Properties with comma , and enclose values with single quotes ''
                $queryUpdateLicensePlatePropertiesAndValues = ($objectUpdateLicensePlate.Keys | ForEach-Object {
                        "$($_) = $($objectUpdateLicensePlate.$_)"
                    }) -join " , "

                $queryUpdateLicensePlate = "
                UPDATE
                    ACCESSKEY
                SET
                    $($queryUpdateLicensePlatePropertiesAndValues)
                WHERE
                    $($licensePlateCorrelationField) = $($licensePlateCorrelationValue)
                "

                $updateLicensePlateSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryUpdateLicensePlate
                    QueryType  = "update"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Updating licensePlate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). SplatParams: $($updateLicensePlateSplatParams | ConvertTo-Json)"   

                    $updatedLicensePlate = Invoke-IProtectQuery @updateLicensePlateSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Updated licensePlate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). Old values: $($licensePlateChangedPropertiesObject.oldValues | ConvertTo-Json). New values: $($licensePlateChangedPropertiesObject.newValues | ConvertTo-Json)"
                            IsError = $false
                        })

                }
                else {
                    Write-Warning "DryRun: Would update licensePlate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). SplatParams: $($updateLicensePlateSplatParams | ConvertTo-Json)"
                }
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error updating licensePlate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryUpdateLicensePlate"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion Update licensePlate            

            #region Set AccountReference and AccountData
            [void]$outputContext.AccountReference.add("LicensePlate", @{
                    "ACCESSKEYID" = "$($correlatedLicensePlate.ACCESSKEYID)"
                })

            foreach ($correlatedLicensePlateProperty in $correlatedLicensePlate.PSObject.Properties | Where-Object { $_.Name -in $licensePlatePropertiesToExport }) {
                $outputContext.Data.LicensePlate | Add-Member -MemberType NoteProperty -Name $correlatedLicensePlateProperty.Name -Value $correlatedLicensePlateProperty.Value -Force
            }
            #endregion Set AccountReference and AccountData

            break
        }

        "Unassign" {
            #region Unassign licenseplate
            try {
                $queryUnassignLicensePlate = "
                UPDATE
                    ACCESSKEY
                SET
                    PERSONID = null , VALID = 0
                WHERE
                    $($licensePlateCorrelationField) = $($licensePlateCorrelationValue)
                "

                $unassignLicensePlateSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryUnassignLicensePlate
                    QueryType  = "update"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Unassigning licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). SplatParams: $($unassignLicensePlateSplatParams | ConvertTo-Json)"   

                    $unassignedLicensePlate = Invoke-IProtectQuery @unassignLicensePlateSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Unassigned licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json)"
                            IsError = $false
                        })

                }
                else {
                    Write-Warning "DryRun: Would unassign licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). SplatParams: $($unassignLicensePlateSplatParams | ConvertTo-Json)"
                }
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error unassigning licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryUnassignLicensePlate"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion Unassign licenseplate

            break
        }

        "NoChanges" {
            #region Set AccountReference and AccountData and create auditlog
            [void]$outputContext.AccountReference.add("LicensePlate", @{
                    "ACCESSKEYID" = "$($correlatedLicensePlate.ACCESSKEYID)"
                })
            
            foreach ($correlatedLicensePlateProperty in $correlatedLicensePlate.PSObject.Properties | Where-Object { $_.Name -in $licensePlatePropertiesToExport }) {
                $outputContext.Data.LicensePlate | Add-Member -MemberType NoteProperty -Name $correlatedLicensePlateProperty.Name -Value $correlatedLicensePlateProperty.Value -Force
            }

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Skipped updating licensePlate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). Reason: No changes."
                    IsError = $false
                })
            #endregion Set AccountReference and AccountData and create auditlog

            break
        }

        "MultipleFound" {
            $auditMessage = "Multiple licensePlates found where [$licensePlateCorrelationField] = [$($licensePlateCorrelationValue)]. Please correct this so the licensePlates are unique."

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $true
                })
        
            # Throw terminal error
            throw $auditMessage

            break
        }

        "NotFound" {
            $auditMessage = "No licensePlate found where [$($licensePlateCorrelationField)] = [$($licensePlateCorrelationValue)]. Possibly indicating that it could be deleted, or not correlated."

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
    if ($outputContext.AccountReference.Count -eq 0) {
        $outputContext.AccountReference = "Currently not available"
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