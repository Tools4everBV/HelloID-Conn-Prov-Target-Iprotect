#####################################################
# HelloID-Conn-Prov-Target-Iprotect-Update
#
# Version: 2.0.0
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

$script:AccessKeyCardClassID = '2'
$script:LicensePlateCardClassID = '6'

$account = [PSCustomObject]@{
    EmployeeSalaryNR        = $p.ExternalId
    EmployeeHireDate        = $p.PrimaryContract.StartDate  # "yyyy-MM-dd HH:mm:ss"
    EmployeeTerminationDate = $p.PrimaryContract.EndDate
    EmployeeBirthDate       = ""
    EmployeeLanguage        = "1"
    PersonName              = $p.UserName
    PersonFirstName         = $p.Name.GivenName
    PersonPrefix            = $p.Name.Initials
    PersonHomeAddress       = ""
    PersonHomeCity          = ""
    PersonHomeZip           = ""
    AccessKeyIsActive       = 1                             # 0 = False, 1 = true
    AccessKeyRCN            = $p.Custom.AccessKeyRCN
    LicensePlateRCN         = $p.Custom.LicensePlateRCN
    CountryCodeLicensePlate = 'NLD'                         #'NLD' | 'BEL'
}


$previousAccount = [PSCustomObject]@{
    EmployeeSalaryNR        = $pp.ExternalId
    EmployeeHireDate        = $pp.PrimaryContract.StartDate # "yyyy-MM-dd HH:mm:ss"
    EmployeeTerminationDate = $pp.PrimaryContract.EndDate
    EmployeeBirthDate       = ""
    EmployeeLanguage        = "1"
    PersonName              = $pp.UserName
    PersonFirstName         = $pp.Name.GivenName
    PersonPrefix            = $pp.Name.Initials
    PersonHomeAddress       = ""
    PersonHomeCity          = ""
    PersonHomeZip           = ""
    AccessKeyIsActive       = 1                             # 0 = False, 1 = true
    AccessKeyRCN            = $pp.Custom.AccessKeyRCN
    LicensePlateRCN         = $pp.Custom.LicensePlateRCN
    CountryCodeLicensePlate = 'NLD'                         #'NLD' | 'BEL'
}

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($config.IsDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

#region functions
function Get-JSessionID {
    [CmdletBinding()]
    param (
    )

    $splatParams = @{
        Uri                = "$($config.BaseUrl)/xmlsql"
        Method             = 'Post'
        Headers            = @{'Content-Type' = "application/x-www-form-urlencoded" }
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
                    $jsessionId = $authorizationCookie.Substring(0, $authorizationCookie.IndexOf(';'));
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
        Body               = $queryBody;
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
                # $resultNode = $xmlResult.RESULT
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
                    throw "Could not create IProtect person account. $QueryDescription. Error: $($errorNode.DESCRIPTION)";
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
        [string] $EmployeeID
    )
    $separatorRequired = $false

    $query = "UPDATE EMPLOYEE SET"
    if ( ![string]::IsNullOrEmpty($Account.EmployeeHireDate)) {
        $query += " HireDate = `#$($Account.EmployeeHireDate)`# "
        $separatorRequired = $true;
    }
    if ( ![string]::IsNullOrEmpty($Account.EmployeeTerminationDate)) {
        if ($separatorRequired) { $query += "," }
        $query += " TerminationDate = `#$($Account.EmployeeTerminationDate)`# "
        $separatorRequired = $true;
    }
    if (  ![string]::IsNullOrEmpty($Account.EmployeeBirthDate)) {
        if ($separatorRequired) { $query += "," }
        $query += " BirthDate = `#$($Account.EmployeeBirthDate)`# "
        $separatorRequired = $true;
    }
    if ( ![string]::IsNullOrEmpty($Account.EmployeeLanguage)) {
        if ($separatorRequired) { $query += "," }
        $query += " Language = $($Account.EmployeeLanguage) "
        $separatorRequired = $true;
    }
    $query += " WHERE EMPLOYEEID = $EmployeeID "

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
        $query += " FirstName = `'$($Account.PersonFirstName)`' "
        $separatorRequired = $true;
    }
    if ( ![string]::IsNullOrEmpty($Account.PersonPrefix)) {
        if ($separatorRequired) { $query += "," }
        $query += " Prefix = `'$($Account.PersonPrefix)`' "
        $separatorRequired = $true;
    }
    if (  ![string]::IsNullOrEmpty($Account.PersonHomeAddress)) {
        if ($separatorRequired) { $query += "," }
        $query += " HomeAddress = `'$($Account.PersonHomeAddress)`' "
        $separatorRequired = $true;
    }
    if ( ![string]::IsNullOrEmpty($Account.PersonHomeCity)) {
        if ($separatorRequired) { $query += "," }
        $query += " HomeCity = `'$($Account.PersonHomeCity)`' "
        $separatorRequired = $true;
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
    $body = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><LOGOUT></LOGOUT>";
    $splatWebRequestParameters = @{
        Uri             = $config.BaseUrl + "/xmlsql"
        Method          = 'Post'
        Headers         = $headers
        UseBasicParsing = $true
        ContentType     = 'text/xml;charset=ISO-8859-1'
        Body            = $body;
        WebSession      = $script:WebSession
    }

    if (-not  [string]::IsNullOrEmpty($config.ProxyAddress)) {
        $splatWebRequestParameters['Proxy'] = $config.ProxyAddress
    }

    try {
        Invoke-WebRequest @splatWebRequestParameters -Verbose:$false   -ErrorAction SilentlyContinue
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
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
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

            if ((-not $null -eq $existingKey.PersonId) -and (-not $existingKey.PersonId -eq $PersonId)) {
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
            $accessKeyId = $accessKey.ACCESSKEYID
        }
        Write-Output $accessKeyId
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion

try {
    # Verify if the account must be updated
    $splatCompareProperties = @{
        ReferenceObject  = @($previousAccount.PSObject.Properties)
        DifferenceObject = @($account.PSObject.Properties)
    }
    $propertiesChanged = (Compare-Object @splatCompareProperties -PassThru).Where({ $_.SideIndicator -eq '=>' })
    if ($propertiesChanged) {
        $action = 'Update'
    } else {
        $action = 'NoChanges'
    }

    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true) {
        $auditLogs.Add([PSCustomObject]@{
                Message = "Update Iprotect account for: [$($p.DisplayName)]. $action will be executed during enforcement"
            })
    }

    if (-not($dryRun -eq $true)) {
        switch ($action) {
            'Update' {
                Write-Verbose "Updating Iprotect account with accountReference: [$($aRef.PersonId)]"
                Write-Verbose "The following properties need an update: [$($propertiesChanged.name -join ',')]"

                $jSessionID = Get-JSessionID
                $authenicationResult = Get-AuthenticationResult -JSessionID $jSessionID

                if (-Not ($authenicationResult.StatusCode -eq 302)) {
                    $ErrorMessage = "iprotect query for person " + $account.EmployeeSalaryNR + ". Authentication failed with error $($authenicationResult.StatusCode)";
                    throw $ErrorMessage
                }

                # Update the fields on the employee object
                $query = New-EmployeeUpdateQuery -account $account -EmployeeID $aRef.EmployeeID
                $queryDescription = "Updating Employee object with EmployeeSalaryNR $($account.EmployeeSalaryNR)"
                if (![string]::IsNullOrEmpty($query)) {
                    $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType "update" -QueryDescription $QueryDescription
                }

                # Update the fields on the Person object

                $query = New-PersonUpdateQuery -account $account -PersonID $aRef.PersonID
                $queryDescription = "Updating person object with PersonId $($aRef.PersonID)"
                if (![string]::IsNullOrEmpty($query)) {
                    $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType "update" -QueryDescription $QueryDescription
                }

                if ($propertiesChanged.name -eq 'AccessKeyRCN') {
                    if ($null -ne $account.accessKeyRCN) {

                        if ($aRef.AccessKeyId) {
                            $QueryDescription = "Update RCN of accesskey $($aRef.AccessKeyId) from person $($aRef.personId) to the new value '$($account.accessKeyRCN)"
                            $query = "UPDATE Accesskey SET RCN = '$($account.accessKeyRCN)' WHERE ACCESSKEYID = $($aRef.AccessKeyId)"
                            $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType 'update' -QueryDescription $QueryDescription

                        } else {
                            $splatInvokeAssign = @{
                                AccessKeyRCN = $account.AccessKeyRCN
                                CardClassId  = $script:AccessKeyCardClassId
                                PersonId     = $aRef.personId
                                IsActive     = $account.AccessKeyIsActive
                                JSessionID   = $jSessionID
                            }
                            $aRef.AccessKeyId = Invoke-IprotectAssignAccessKey @splatInvokeAssign
                        }
                        $auditLogs.Add([PSCustomObject]@{
                                Message = "Set Accesskey [$($account.AccessKeyRCN)] to account [$($aRef.personId)]. AccessKeyReference is: [$($aRef.AccessKeyId)]"
                                IsError = $false
                            }
                        )
                    } else {
                        Write-Verbose "Update.ps1 does not support updating the AccessKeyRCN from [$($previousAccount.accessKeyRCN)] to Null"
                        Write-Verbose 'AccessKeyRCN can only removed in the delete.ps1 script'
                    }
                }

                if ($propertiesChanged.name -eq 'LicensePlateRCN') {
                    $licensePlateRCN = "$($account.CountryCodeLicensePlate),$($account.LicensePlateRCN)"
                    if ($aRef.AccessKeyIdLicensePlate) {
                        $QueryDescription = "Update RCN of LicensePlate [$($aRef.AccessKeyIdLicensePlate)] from person [$($aRef.personId)] to the new value [$($licensePlateRCN)])"
                        $query = "UPDATE Accesskey SET RCN = '$($licensePlateRCN)' WHERE ACCESSKEYID = $($aRef.AccessKeyIdLicensePlate)"
                        $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType 'update' -QueryDescription $QueryDescription

                    } else {
                        $splatInvokeAssign = @{
                            AccessKeyRCN = $licensePlateRCN
                            CardClassId  = $script:LicensePlateCardClassID
                            PersonId     = $aRef.personId
                            IsActive     = 1 # Create Always active
                            JSessionID   = $jSessionID
                        }
                        $aRef.AccessKeyIdLicensePlate = Invoke-IprotectAssignAccessKey @splatInvokeAssign
                    }
                    $auditLogs.Add([PSCustomObject]@{
                            Message = "Set LicensePlate [$($licensePlateRCN)] to account [$($aRef.personId)]. AccessKeyReference is: [$($aRef.AccessKeyIdLicensePlate)]"
                            IsError = $false
                        }
                    )
                }
                $success = $true
                $auditMessage = 'Update account was successful'
                break

            }

            'NoChanges' {
                Write-Verbose "No changes to Iprotect account with accountReference: [$($aRef.PersonId)]"
                $success = $true
                $auditMessage = 'Update account was successful (No Changes)'
                break
            }
        }
        $auditLogs.Add([PSCustomObject]@{
                Message = $auditMessage
                IsError = $false
            })
    }
} catch {
    $success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -ErrorObject $ex
        $errorMessage = "Could not update Iprotect account. Error: $($errorObj.ErrorMessage)"
    } else {
        $errorMessage = "Could not update Iprotect account. Error: $($ex.Exception.Message)"
    }
    Write-Verbose $errorMessage
    $auditLogs.Add([PSCustomObject]@{
            Message = $errorMessage
            IsError = $true
        })
} finally {
    if ($null -ne $script:WebSession) {
        $null = Invoke-logout
    }

    $result = [PSCustomObject]@{
        Account          = $account
        AccountReference = $aRef
        Auditlogs        = $auditLogs
        Success          = $success
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
