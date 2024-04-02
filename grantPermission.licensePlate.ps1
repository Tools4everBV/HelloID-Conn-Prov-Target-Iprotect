#################################################
# HelloID-Conn-Prov-Target-iProtect-Permissions-KeyGroups-LicensePlate-Grant
# PowerShell V2
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

#region LicensePlate
# Define correlation
$licensePlateCorrelationField = "ACCESSKEYID"
$licensePlateCorrelationValue = $actionContext.References.Account.LicensePlate.ACCESSKEYID

# Define Account mapping object
$licensePlateAccount = [PSCustomObject]$actionContext.Data.LicensePlate

# Define properties to query
$licensePlatePropertiesToQuery = @("ACCESSKEYID") + $licensePlateAccount.PSObject.Properties.Name | Select-Object -Unique
#endRegion LicensePlate

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

        Write-Verbose "Querying licenseplate where [$licensePlateCorrelationField] = [$($licensePlateCorrelationValue)]. SplatParams: $($correlateLicensePlateSplatParams | ConvertTo-Json)"

        $correlatedLicensePlate = $null
        $correlatedLicensePlate = Invoke-IProtectQuery @correlateLicensePlateSplatParams
            
        Write-Verbose "Queried licenseplate where [$licensePlateCorrelationField] = [$($licensePlateCorrelationValue)]. Result: $($correlatedLicensePlate | Out-String)"
    }
    catch {
        $ex = $PSItem

        $auditMessage = "Error querying licenseplate where [$licensePlateCorrelationField] = [$($licensePlateCorrelationValue)]. Error: $($ex.Exception.Message)"
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
        $actionLicensePlate = "GrantPermission"
    }
    elseif (($correlatedLicensePlate | Measure-Object).count -gt 1) {
        $actionLicensePlate = "MultipleFound"
    }
    elseif (($correlatedLicensePlate | Measure-Object).count -eq 0) {
        $actionLicensePlate = "NotFound"
    }

    # Process
    switch ($actionLicensePlate) {
        "GrantPermission" {
            #region Create permission for licenseplate
            try {
                $objectCreatePermissionLicensePlate = @{
                    ACCESSKEYID = "$($correlatedLicensePlate.ACCESSKEYID)"
                    KEYGROUPID  = "$($actionContext.References.Permission.Id)"
                }

                # Seperate Property Names with comma ,
                $queryCreatePermissionLicensePlateProperties = $(($objectCreatePermissionLicensePlate.Keys -join ","))
                # Seperate Property Values with comma ,
                $queryCreatePermissionLicensePlateValues = $(($objectCreatePermissionLicensePlate.Values -join ","))

                $queryCreatePermissionLicensePlate = "
                INSERT INTO KEYKEYGROUP
                    ($($queryCreatePermissionLicensePlateProperties))
                VALUES
                    ($($queryCreatePermissionLicensePlateValues))
                "

                $createPermissionLicensePlateSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryCreatePermissionLicensePlate
                    QueryType  = "update"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Creating permission where [KEYKEYGROUPID = $($actionContext.References.Permission.Id)] for licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). SplatParams: $($createPermissionLicensePlateSplatParams | ConvertTo-Json)"

                    $createdPermissionLicensePlate = $null
                    $createdPermissionLicensePlate = Invoke-IProtectQuery @createPermissionLicensePlateSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Created permission where [KEYKEYGROUPID = $($actionContext.References.Permission.Id)] for licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json)"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would create permission where [KEYKEYGROUPID = $($actionContext.References.Permission.Id)] for licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). SplatParams: $($createPermissionLicensePlateSplatParams | ConvertTo-Json)"
                }
            }
            catch {
                $ex = $PSItem

                if ($ex.Exception.Message -like "*Value already exists*" -or $ex.Exception.Message -like "*Kolom waarde is niet uniek*") {
                    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                    $auditMessage = "Skipped creating permission where [KEYKEYGROUPID = $($actionContext.References.Permission.Id)] for licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). Reason: Permission for accesskey already exists."

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $false
                        })
                }
                else {
                    $auditMessage = "Error creating permission where [KEYKEYGROUPID = $($actionContext.References.Permission.Id)] for licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). SplatParams: $($createPermissionLicensePlateSplatParams | ConvertTo-Json). Error: $($ex.Exception.Message)"
                    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $true
                        })

                    # Log query
                    Write-Warning "Query: $querycreatePermissionLicensePlate"

                    # Throw terminal error
                    throw $auditMessage
                }
            }
            #endregion Create permission for licenseplate

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