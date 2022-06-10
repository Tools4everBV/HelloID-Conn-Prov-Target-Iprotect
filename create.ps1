#####################################################
# HelloID-Conn-Prov-Target-Iprotect-Create
#
# Version: 2.0.0
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# The type of the accesskeys and License Plates differs between Iprotect implementations
$script:AccessKeyCardClassId = '2'
$script:LicensePlateCardClassID = '6'

$account = [PSCustomObject]@{
    EmployeeSalaryNR        = $p.ExternalId
    EmployeeHireDate        = $p.PrimaryContract.StartDate  # "yyyy-MM-dd HH:mm:ss"
    EmployeeTerminationDate = $p.PrimaryContract.endDate
    EmployeeBirthDate       = ""
    EmployeeLanguage        = "1"
    PersonName              = $p.UserName
    PersonFirstName         = $p.Name.GivenName
    PersonPrefix            = $p.Name.Initials
    PersonHomeAddress       = ""
    PersonHomeCity          = ""
    PersonHomeZip           = ""
    AccessKeyIsActive       = 0                             # 0 = False, 1 = true
    AccessKeyRCN            = $p.Custom.AccessKeyRCN
    LicensePlateRCN         = $p.Custom.LicensePlateRCN
    CountryCodeLicensePlate = 'NLD'                         #'NLD' | 'BEL'
}

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($config.IsDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

# Set to true if the accounts in Iprotect must be updated and the mapped Accesskey and Licenseplate must be set
[bool]$updatePerson = $true

#region functions
function Get-JSessionID {
    [CmdletBinding()]
    param ()

    $splatParams = @{
        Uri                = "$($config.BaseUrl)/xmlsql"
        Method             = 'Post'
        Headers            = @{'Content-Type' = 'application/x-www-form-urlencoded' }
        UseBasicParsing    = $true
        TimeoutSec         = 60
        MaximumRedirection = 0
        SessionVariable    = 'script:WebSession'
    }

    if ($config.ProxyAddress) {
        $splatParams['Proxy'] = $config.ProxyAddress
    }

    try {
        $requestResult = Invoke-WebRequest @splatParams -ErrorAction SilentlyContinue -Verbose:$false
        if ($null -ne $requestResult.Headers) {
            if ($null -ne $requestResult.Headers['Set-Cookie'] ) {
                $authorizationCookie = $requestResult.Headers['Set-Cookie']

                if ($authorizationCookie.IndexOf(';') -gt 0) {
                    $jsessionId = $authorizationCookie.Substring(0, $authorizationCookie.IndexOf(';'))
                }
            }
        }
        Write-Output $jsessionId
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-AuthenticationResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $JSessionID
    )

    $splatParams = @{
        Uri                = "$($config.BaseUrl)/j_security_check"
        Method             = 'POST'
        Headers            = @{'Content-Type' = 'application/x-www-form-urlencoded'; 'Cookie' = $JSessionID }
        UseBasicParsing    = $true
        MaximumRedirection = 0
        Body               = "&j_username=$($config.UserName)&j_password=$($config.Password)"
        WebSession         = $script:WebSession
    }
    try {
        Invoke-WebRequest @splatParams -ErrorAction SilentlyContinue -Verbose:$false
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Invoke-IProtectQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $JSessionID,

        [Parameter(Mandatory)]
        [string]
        $Query,

        [Parameter(Mandatory)]
        [string]
        $QueryType,

        [Parameter(Mandatory = $false)]
        [string]
        $QueryDescription
    )

    switch ($QueryType) {
        'query' { $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><query><sql>$query</sql></query>" }
        'update' { $queryBody = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><update><sql>$query</sql></update>" }
    }

    $splatParams = @{
        Uri                = "$($config.BaseUrl)/xmlsql"
        Method             = 'POST'
        Headers            = @{'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'; 'Cookie' = $JSessionID }
        UseBasicParsing    = $true
        MaximumRedirection = 0
        ContentType        = 'text/xml;charset=ISO-8859-1'
        Body               = $queryBody
        WebSession         = $script:WebSession
    }
    if ($config.ProxyServer) {
        $splatParams['Proxy'] = $config.ProxyServer
    }

    try {
        $queryResult = Invoke-WebRequest @splatParams -Verbose:$false
        switch ($queryType) {
            'query' {
                [xml] $xmlResult = $queryResult.Content
                $resultNode = $xmlResult.item('RESULT')
                $nodePath = 'ROWSET'
                $rowsetNode = $resultNode.SelectSingleNode($nodePath)

                $nodePath = 'ERROR'
                $errorNode = $resultNode.SelectSingleNode($nodePath)

                if ($null -ne $errorNode) {
                    $errorDescription = $ErrorNode.DESCRIPTION
                    $errorMessage = "Could not create iProtect account for person: [$($account.ExternalId)]. $QueryDescription. Error: $errorDescription"
                    throw $errorMessage
                }

                if ($null -ne $rowsetNode) {
                    $nodePath = 'ROW'
                    $rowNodes = $rowsetNode.SelectNodes($nodePath)
                    if ((-not ($null -eq $rowNodes) -and ($rowNodes.Count -gt 0))) {
                        Write-Output $rowNodes
                    } else {
                        Write-Output $null
                    }
                }
            }
            'update' {
                [xml] $xmlResult = $queryResult.Content
                $resultNode = $xmlResult.item('RESULT')
                $errorNode = $resultNode.SelectSingleNode("ERROR")
                if ($null -ne $errorNode) {
                    $errorMessage = "Could not create IProtect person account. $QueryDescription. Error: $($errorNode.DESCRIPTION)"
                    Write-Verbose $errorMessage
                    throw $errorMessage
                }
                Write-Output $resultNode
            }
        }
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function New-EmployeeUpdateQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject] $Account,

        [Parameter(Mandatory)]
        [string] $EmployeeSalaryNR
    )
    $separatorRequired = $false

    $query = "UPDATE EMPLOYEE SET"
    if ( ![string]::IsNullOrEmpty($Account.EmployeeHireDate)) {
        $query += " HireDate = "
        $query += " `#"
        $query += $Account.EmployeeHireDate
        $query += "`#"
        $separatorRequired = $true
    }
    if ( ![string]::IsNullOrEmpty($Account.EmployeeTerminationDate)) {
        if ($separatorRequired) { $query += "," }
        $query += " TerminationDate = "
        $query += " `#"
        $query += $Account.EmployeeTerminationDate
        $query += "`#"
        $separatorRequired = $true
    }
    if (  ![string]::IsNullOrEmpty($Account.EmployeeBirthDate)) {
        if ($separatorRequired) { $query += "," }
        $query += " BirthDate = "
        $query += " `#"
        $query += $Account.EmployeeBirthDate
        $query += "`#"
        $separatorRequired = $true
    }
    if ( ![string]::IsNullOrEmpty($Account.EmployeeLanguage)) {
        if ($separatorRequired) { $query += "," }
        $query += " Language = "
        $query += $Account.EmployeeLanguage
        $query += " "
        $separatorRequired = $true
    }
    $query += " WHERE SALARYNR = `'"
    $query += $EmployeeSalaryNR
    $query += "`' "

    if ($separatorRequired -eq $false) {
        $query = ""
    }
    Write-Output $query
}

function New-PersonUpdateQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject] $Account,

        [Parameter(Mandatory)]
        [string] $PersonID
    )

    $separatorRequired = $false

    $query = "UPDATE PERSON SET"

    if ( ![string]::IsNullOrEmpty($Account.PersonFirstName)) {
        $query += " FirstName = `'"
        $query += $Account.PersonFirstName
        $query += "`' "
        $separatorRequired = $true
    }
    if ( ![string]::IsNullOrEmpty($Account.PersonPrefix)) {
        if ($separatorRequired) { $query += "," }
        $query += " Prefix = `'"
        $query += $Account.PersonPrefix
        $query += "`'"
        $separatorRequired = $true
    }
    if (  ![string]::IsNullOrEmpty($Account.PersonHomeAddress)) {
        if ($separatorRequired) { $query += "," }
        $query += " HomeAddress = `'"
        $query += $Account.PersonHomeAddress
        $query += "`' "
        $separatorRequired = $true
    }
    if ( ![string]::IsNullOrEmpty($Account.PersonHomeCity)) {
        if ($separatorRequired) { $query += "," }
        $query += " HomeCity = `'"
        $query += $Account.PersonHomeCity
        $query += "`' "
        $separatorRequired = $true
    }
    $query += " WHERE PERSONID = $PersonID"

    if ($separatorRequired -eq $false) {
        $query = ""
    }
    Write-Output $query
}

function Invoke-Logout {
    [CmdletBinding()]
    param ()

    $headers = @{
        'Accept' = 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'
        'Cookie' = $JSessionID
    }
    $body = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><LOGOUT></LOGOUT>"
    $splatWebRequestParameters = @{
        Uri             = $config.BaseUrl + "/xmlsql"
        Method          = 'Post'
        Headers         = $headers
        UseBasicParsing = $true
        ContentType     = 'text/xml;charset=ISO-8859-1'
        Body            = $body
        WebSession      = $script:WebSession
    }

    if (-not  [string]::IsNullOrEmpty($config.ProxyAddress)) {
        $splatWebRequestParameters['Proxy'] = $config.ProxyAddress
    }

    try {
        Invoke-WebRequest @splatWebRequestParameters -Verbose:$false  -ErrorAction SilentlyContinue
    } catch {
        # logout failure is not critical, so only log "
        $errorMessage = "Warning, Iprotect logout failed error: $($_)"
        Write-Verbose $errorMessage
        $auditLogs.Add([PSCustomObject]@{
                Message = $errorMessage
                IsError = $false
            })

    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($ErrorObject.Exception.Response) {
                $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
            } else {
                $httpErrorObj.ErrorMessage = "$($ErrorObject.Exception.Message) $($ErrorObject.Exception.InnerException.Message)".trim(" ")
            }
        }
        Write-Output $httpErrorObj
    }
}

function Invoke-IprotectAssignAccessKey {
    [CmdletBinding()]
    param(
        [string]
        $AccessKeyRCN,

        [string]
        $CardClassId,


        [string]
        $PersonId,

        [ValidateSet(0, 1)]
        [int]
        $isActive,

        [string]
        $JSessionID
    )
    try {
        $query = "SELECT ACCESSKEYID,CARDCLASSID,ENDDATE,PERSONID,RCN,VALID,VISITORID FROM Accesskey WHERE CARDCLASSID = $CardClassId AND RCN = '$AccessKeyRCN'"
        $existingKey = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType 'query'

        if ($null -ne $existingKey) {
            if ((-not ([string]::IsNullorEmpty($existingKey.PersonId))) -and (-not ($existingKey.PersonId -eq $PersonId))) {
                throw "The supplied Accesskey [$($AccessKeyRCN)] is already assigned to [$($existingKey.PersonId)]"
            } elseif ($existingKey.PersonId -eq $PersonId) {
                Write-Verbose "Correlated AccessKey Type [$CardClassId] RCN [$AccessKeyRCN] to Account [$PersonId]"
            } else {
                Write-Verbose  "Assign AccessKey Type [$CardClassId] RCN [$AccessKeyRCN]  to Account [$PersonId]"
                $queryUpdate = "UPDATE Accesskey SET RCN = '$AccessKeyRCN', PERSONID = $PersonId  WHERE ACCESSKEYID = $($existingKey.ACCESSKEYID)"
                $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $queryUpdate -QueryType 'update'
            }
            $accessKeyId = $existingKey.ACCESSKEYID
        } else {
            Write-Verbose "Assign and Create AccessKey Type [$CardClassId] RCN [$($AccessKeyRCN)] to Account [$PersonId]"
            $queryCreate = "INSERT INTO Accesskey (CARDCLASSID,PERSONID,RCN,VALID) VALUES ($CardClassId, $($PersonId), '$($AccessKeyRCN)', $isActive)"
            $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $queryCreate -QueryType 'update'

            # Get AccessKeyId
            $queryGet = "SELECT ACCESSKEYID,CARDCLASSID,ENDDATE,PERSONID,RCN,VALID,VISITORID FROM Accesskey WHERE CARDCLASSID = $CardClassId AND RCN = '$($AccessKeyRCN)'"
            $accessKey = Invoke-IProtectQuery -JSessionID $jSessionID -Query $queryGet -QueryType 'query'
            if ($null -eq $accessKey)
            {
                throw "The allegedly just created Accesskey with RCN [$($AccessKeyRCN)] cannot be found in the database]"
            }
            $accessKeyId = $accessKey.ACCESSKEYID

        }
        Write-Output $accessKeyId
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion

# Begin
try {
    # Verify if a user must be either [created and correlated], [updated and correlated] or just [correlated]
    $EmployeeExists = $false
    $action = 'Lookup'

    Write-Verbose 'Getting Get-JSessionID'
    $jSessionID = Get-JSessionID
    Write-Verbose 'Authenticate with the IProtect'
    $authenicationResult = Get-AuthenticationResult -JSessionID $jSessionID

    if (-Not ($authenicationResult.StatusCode -eq 302)) {
        $success = $false
        $ErrorMessage = "Iprotect query for person [$($p.ExternalId)]. Authentication failed with error [$($authenicationResult.StatusCode)]"
        throw $ErrorMessage
    } else {
        Write-Verbose 'Successfully Authenticated'
    }

    Write-Verbose "Query if there is already an Employee with the specified EmployeeSalaryNR"
    $query = "SELECT
    TABLEEMPLOYEE.PERSONID as person_id,
    TABLEPERSON.NAME as person_name,
    TABLEEMPLOYEE.EMPLOYEEID as employee_id,
    TABLEEMPLOYEE.SALARYNR as employee_salarynr
    FROM employee TABLEEMPLOYEE
    LEFT OUTER JOIN person TABLEPERSON ON TABLEPERSON.personID = TABLEEMPLOYEE.personID
    WHERE TABLEEMPLOYEE.SALARYNR = "
    $query += "`'"
    $query += $account.EmployeeSalaryNR
    $query += "`'"


    $QueryDescription = "Finding Employee with EmployeeSalaryNR [$($account.EmployeeSalaryNR)]"
    Write-Verbose $QueryDescription
    $RowNodes = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType "query" -QueryDescription $QueryDescription
    foreach ($rowNode in $rowNodes) {
        $curObject = @{
            PERSONID   = $rowNode.PERSON_ID
            PERSONNAME = $rowNode.PERSON_NAME
            SALARYNR   = $rowNode.EMPLOYEE_SALARYNR
            EMPLOYEEID = $rowNode.EMPLOYEE_ID
        }
        # Note there will be only one row as salarynr should be unique
        $EmployeeExists = $true
        $selectedPersonId = $curObject.PERSONID
        $selectedEmployeeID = $curObject.EMPLOYEEID

        if ($curObject.PERSONNAME -ne $Account.PersonName) {
            $ErrorMessage = "iprotect create for person " + $p.ExternalId + " with name " +
            $account.PersonName + " failed. Employee is already associated with person `'" +
            $curObject.PERSONNAME + "`'"
            throw $ErrorMessage
        }
    }

    if (-not($EmployeeExists)) {
        $action = 'Create-Correlate'
    } elseif ($updatePerson -eq $true) {
        $action = 'Update-Correlate'
    } else {
        $action = 'Correlate'
    }

    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true) {
        $auditLogs.Add([PSCustomObject]@{
                Message = "$action Iprotect account for: [$($p.DisplayName)], will be executed during enforcement"
            })
    }

    # Process
    if (-not($dryRun -eq $true)) {
        switch ($action) {
            'Create-Correlate' {
                Write-Verbose 'Creating and correlating Iprotect account'
                [bool]$personObjectIsCreated = $false
                $query = "SELECT PERSONID, NAME, FIRSTNAME FROM PERSON WHERE NAME = "
                $query += "`'"
                $query += $account.PersonName
                $query += "`' AND FIRSTNAME = "
                $query += "`'"
                $query += $account.PersonFirstName
                $query += "`'"
                $QueryDescription = "Lookup of existing Person object with PersonName = $($account.PersonName) and Firstname = $($account.PersonFirstName)"
                Write-Verbose $queryDescription
                $rowNodes = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType "query" -QueryDescription $QueryDescription
                if (-Not ($null -eq $rowNodes)) {
                    if ($rowNodes.Count -gt 1) {
                        $ErrorMessage = "Unable to create person object for employee. There are already multiple person objects with name [" + $account.PersonName +
                        "] and firstname[" + $account.FirstName + " ]  Iprotect query for lookup of person " + $p.ExternalId + " failed"
                        throw $ErrorMessage
                    }
                }
                $selectedPersonId = $null
                foreach ($rowNode in $rowNodes) {
                    #there will be only 0 or one rows
                    $curObject = @{
                        PERSONID  = $rowNode.PERSONID
                        NAME      = $rowNode.NAME
                        FIRSTNAME = $rowNode.FIRSTNAME
                    }
                    $selectedPersonId = $curObject.PERSONID
                }

                if ($null -eq $selectedPersonId) {
                    Write-Verbose 'The person object does not exist, so create it'
                    $PersonName = $Account.PersonName
                    $FirstName = $Account.PersonFirstName
                    $query = "INSERT INTO Person (NAME, FIRSTNAME) VALUES (`'$PersonName`',`'$FirstName`')"
                    $queryDescription = "Create a new person object with NAME = $PersonName , FIRSTNAME = $FirstName"
                    Write-Verbose $queryDescription
                    $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType "update" -QueryDescription $QueryDescription

                    # Collect PersonID from just created person object
                    $query = "SELECT PERSONID ,NAME, FIRSTNAME FROM PERSON WHERE NAME = "
                    $query += "`'"
                    $query += $account.PersonName
                    $query += "`' AND FIRSTNAME = "
                    $query += "`'"
                    $query += $account.PersonFirstName
                    $query += "`'"
                    $queryDescription = "Collect PersonID from just created person object with NAME = $PersonName , FIRSTNAME = $FirstName"
                    Write-Verbose $queryDescription
                    $rowNodes = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType "query" -QueryDescription $QueryDescription

                    if ($null -eq $rowNodes) {
                        $ErrorMessage = "Unable to get PersonID of just created person object with name [" + $account.PersonName + "] and firstname[" +
                        $account.FirstName + " ].  Iprotect query for lookup of person " + $p.ExternalId + " failed"
                        throw $ErrorMessage
                    }
                    foreach ($rowNode in $rowNodes) {
                        #there will be exactly 1 rows
                        $curObject = @{
                            PERSONID  = $rowNode.PERSONID
                            NAME      = $rowNode.NAME
                            FIRSTNAME = $rowNode.FIRSTNAME
                        }
                        $selectedPersonId = $curObject.PERSONID
                        $personObjectIsCreated = $true
                        break
                    }
                }
                # the PersonId is now known, so create the employee object
                $query = "INSERT INTO Employee (SALARYNR, PersonID) VALUES ('$($account.EmployeeSalaryNR)',$selectedPersonId)"
                $queryDescription = "Create new Employee object, SALARYNR = $($account.EmployeeSalaryNR) PersonID = $selectedPersonId"
                Write-Verbose  $queryDescription
                $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType 'update' -QueryDescription $QueryDescription

                $query = "SELECT EMPLOYEEID, SALARYNR FROM employee WHERE SALARYNR = '$($account.EmployeeSalaryNR)'"
                $employeeObject = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query  -QueryType 'Query'



                # update the account to set all optional attibutes as required
                $query = New-EmployeeUpdateQuery -account $account -EmployeeSalaryNR $account.EmployeeSalaryNR
                $queryDescription = "Updating Employee object with EmployeeSalaryNR [$($account.EmployeeSalaryNR)]"
                Write-Verbose  $queryDescription
                $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType 'update' -QueryDescription $QueryDescription

                if ($personObjectIsCreated -or $updatePerson) {
                    $query = New-PersonUpdateQuery -account $account -PersonId $selectedPersonId
                    $queryDescription = "Updating person object with PersonId [$selectedPersonId]"
                    Write-Verbose  $queryDescription
                    $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType 'update' -QueryDescription $QueryDescription
                }

                if (-not [string]::IsNullOrEmpty($account.AccessKeyRCN)) {
                    Write-Verbose "AccessKey [$($account.AccessKeyRCN)] found in Mapping"
                    $splatInvokeAssign = @{
                        AccessKeyRCN = $($account.AccessKeyRCN)
                        CardClassId  = $script:AccessKeyCardClassId
                        PersonId     = $selectedPersonId
                        IsActive     = $account.AccessKeyIsActive
                        JSessionID   = $jSessionID
                    }
                    $accessKeyId = Invoke-IprotectAssignAccessKey @splatInvokeAssign

                    $auditLogs.Add([PSCustomObject]@{
                            Message = "Set Accesskey [$($account.AccessKeyRCN)] to account [$($account.EmployeeSalaryNR)]. AccessKeyReference is: [$($accessKeyId)]"
                            IsError = $false
                        })
                }

                if (-not [string]::IsNullOrEmpty($account.LicensePlateRCN)) {
                    $licensePlateRCN = "$($account.CountryCodeLicensePlate),$($account.LicensePlateRCN)"
                    Write-Verbose "LicensePlate [$licensePlateRCN] found in Mapping"
                    $splatInvokeAssign = @{
                        AccessKeyRCN = $licensePlateRCN
                        CardClassId  = $script:LicensePlateCardClassID
                        PersonId     = $selectedPersonId
                        IsActive     = 1 # Create Always active
                        JSessionID   = $jSessionID
                    }
                    $accessKeyLicensePlateId = Invoke-IprotectAssignAccessKey @splatInvokeAssign
                    $auditLogs.Add([PSCustomObject]@{
                            Message = "Set LicensePlate [$licensePlateRCN] to account [$($account.EmployeeSalaryNR)]. LicensePlateReference is: [$accessKeyLicensePlateId]"
                            IsError = $false
                        })
                }
                $aRef = @{
                    EmployeeId              = $employeeObject.EMPLOYEEID
                    PersonId                = $selectedPersonId
                    AccessKeyId             = $accessKeyId
                    AccessKeyIdLicensePlate = $accessKeyLicensePlateId
                }
                break
            }

            'Update-Correlate' {
                Write-Verbose "Updating and correlating Iprotect account with EmployeeID [$selectedEmployeeID] and SalaryNR [$($account.EmployeeSalaryNR)]"
                $query = New-EmployeeUpdateQuery -account $account -EmployeeSalaryNR $account.EmployeeSalaryNR
                $queryDescription = "Updating Employee object with EmployeeSalaryNR [$($account.EmployeeSalaryNR)]"
                Write-Verbose  $queryDescription
                $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType "update" -QueryDescription $QueryDescription

                $query = New-PersonUpdateQuery -account $account -PersonId $selectedPersonId
                $queryDescription = "Updating person object with PersonId [$selectedPersonId]"
                Write-Verbose  $queryDescription
                $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType "update" -QueryDescription $QueryDescription

                if (-not [string]::IsNullOrEmpty($account.AccessKeyRCN)) {
                    Write-Verbose "AccessKey [$($account.AccessKeyRCN)] found in Mapping"
                    $splatInvokeAssign = @{
                        AccessKeyRCN = $($account.AccessKeyRCN)
                        CardClassId  = $script:AccessKeyCardClassId
                        PersonId     = $selectedPersonId
                        IsActive     = $account.AccessKeyIsActive
                        JSessionID   = $jSessionID
                    }
                    $accessKeyId = Invoke-IprotectAssignAccessKey @splatInvokeAssign

                    $auditLogs.Add([PSCustomObject]@{
                            Message = "Set Accesskey [$($account.AccessKeyRCN)] to account [$($account.EmployeeSalaryNR)]. AccessKeyReference is: [$($accessKeyId)]"
                            IsError = $false
                        })
                }

                if (-not [string]::IsNullOrEmpty($account.LicensePlateRCN)) {
                    $licensePlateRCN = "$($account.CountryCodeLicensePlate),$($account.LicensePlateRCN)"
                    Write-Verbose "LicensePlate [$licensePlateRCN] found in Mapping"
                    $splatInvokeAssign = @{
                        AccessKeyRCN = $licensePlateRCN
                        CardClassId  = $script:LicensePlateCardClassID
                        PersonId     = $selectedPersonId
                        IsActive     = 1 # Create Always active
                        JSessionID   = $jSessionID
                    }
                    $accessKeyLicensePlateId = Invoke-IprotectAssignAccessKey @splatInvokeAssign
                    $auditLogs.Add([PSCustomObject]@{
                            Message = "Set LicensePlate [$licensePlateRCN] to account [$($account.EmployeeSalaryNR)]. LicensePlateReference is: [$accessKeyLicensePlateId]"  #TODO Var Checken
                            IsError = $false
                        })
                }
                $aRef = @{
                    EmployeeId              = $selectedEmployeeID
                    PersonId                = $selectedPersonId
                    AccessKeyId             = $accessKeyId
                    AccessKeyIdLicensePlate = $accessKeyLicensePlateId
                }
                break
            }

            'Correlate' {
                Write-Verbose 'Correlating Iprotect account'
                $aRef = @{
                    EmployeeId              = $selectedEmployeeID
                    PersonId                = $selectedPersonId
                    AccessKeyId             = $null
                    AccessKeyIdLicensePlate = $null
                }
                break
            }
        }

        $success = $true

        $auditLogs.Add([PSCustomObject]@{
                Message = "$action account was successful. AccountReference: EmployeeId = [$($aRef.EmployeeId)] PersonId = [$($aRef.PersonId)] AccessKeyId = [$($aRef.AccessKeyId)] AccessKeyIdLicensePlate = [$($aRef.AccessKeyIdLicensePlate)]"
                IsError = $false
            })

    }
} catch {
    $success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -ErrorObject $ex
        $errorMessage = "Could not $action Iprotect account. Error: $($errorObj.ErrorMessage)"
    } else {
        $errorMessage = "Could not $action Iprotect account. Error: $($ex.Exception.Message)"
    }
    Write-Verbose $errorMessage
    $auditLogs.Add([PSCustomObject]@{
            Message = $errorMessage
            IsError = $true
        })
    # End
} finally {

    if ($null -ne $script:WebSession) {
        $null = Invoke-logout
    }

    $result = [PSCustomObject]@{
        Success          = $success
        AccountReference = $aRef
        Auditlogs        = $auditLogs
        Account          = $account
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
