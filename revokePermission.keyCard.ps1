#################################################
# HelloID-Conn-Prov-Target-iProtect-Permissions-KeyGroups-KeyCard-Revoke
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

#region KeyCard
# Define correlation
$keyCardCorrelationField = "ACCESSKEYID"
$keyCardCorrelationValue = $actionContext.References.Account.KeyCard.ACCESSKEYID

# Define Account mapping object
$keyCardAccount = [PSCustomObject]$actionContext.Data.KeyCard

# Define properties to query
$keyCardPropertiesToQuery = @("ACCESSKEYID") + $keyCardAccount.PSObject.Properties.Name | Select-Object -Unique
#endRegion KeyCard

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

        Write-Verbose "Querying keycard where [$keyCardCorrelationField] = [$($keyCardCorrelationValue)]. SplatParams: $($correlateKeyCardSplatParams | ConvertTo-Json)"

        $correlatedKeyCard = $null
        $correlatedKeyCard = Invoke-IProtectQuery @correlateKeyCardSplatParams
            
        Write-Verbose "Queried keycard where [$keyCardCorrelationField] = [$($keyCardCorrelationValue)]. Result: $($correlatedKeyCard | Out-String)"
    }
    catch {
        $ex = $PSItem

        $auditMessage = "Error querying keycard where [$keyCardCorrelationField] = [$($keyCardCorrelationValue)]. Error: $($ex.Exception.Message)"
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
        $actionKeyCard = "RevokePermission"
    }
    elseif (($correlatedKeyCard | Measure-Object).count -gt 1) {
        $actionKeyCard = "MultipleFound"
    }
    elseif (($correlatedKeyCard | Measure-Object).count -eq 0) {
        $actionKeyCard = "NotFound"
    }

    # Process
    switch ($actionKeyCard) {
        "RevokePermission" {
            #region Get current permission for keycard
            try {
                $queryCorrelatePermissionKeyCard = "
                SELECT
                    KEYKEYGROUPID
                FROM
                    KEYKEYGROUP
                WHERE
                    KEYGROUPID = $($actionContext.References.Permission.Id)
                    AND ACCESSKEYID = $($correlatedKeyCard.ACCESSKEYID)
                "

                $correlatePermissionKeyCardSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryCorrelatePermissionKeyCard
                    QueryType  = "query"
                }

                Write-Verbose "Querying permission for keycard where [KEYGROUPID] = [$($actionContext.References.Permission.Id)] AND [ACCESSKEYID] = [$($correlatedKeyCard.ACCESSKEYID)]. SplatParams: $($correlatePermissionKeyCardSplatParams | ConvertTo-Json)"

                $correlatedPermissionKeyCard = $null
                $correlatedPermissionKeyCard = Invoke-IProtectQuery @correlatePermissionKeyCardSplatParams
            
                Write-Verbose "Queried permission for permission for keycard where [$keyCardCorrelationField] = [$($keyCardCorrelationValue)]. Result: $($correlatedPermissionKeyCard | Out-String)"
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error querying permission for keycard where [$keyCardCorrelationField] = [$($keyCardCorrelationValue)]. Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryCorrelatePermissionKeyCard"
        
                # Throw terminal error
                throw $auditMessage
            }
            #endregion Get current permission for keycard

            if (($correlatedPermissionKeyCard | Measure-Object).count -eq 1) {
                #region Delete permission for keycard
                try {
                    $queryDeletePermissionKeyCard = "
                    DELETE
                        *
                    FROM
                        KEYKEYGROUP
                    WHERE
                        KEYKEYGROUPID = $($correlatedPermissionKeyCard.KEYKEYGROUPID)
                    "

                    $deletPermissionKeyCardSplatParams = @{
                        BaseUrl    = $actionContext.Configuration.BaseUrl
                        JSessionID = $jSessionID
                        Query      = $queryDeletePermissionKeyCard
                        QueryType  = "update"
                    }

                    if (-Not($actionContext.DryRun -eq $true)) {
                        Write-Verbose "Deleting permission where [KEYKEYGROUPID = $($actionContext.References.Permission.Id)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deletPermissionKeyCardSplatParams | ConvertTo-Json)"

                        $deletedPermissionKeyCard = $null
                        $deletedPermissionKeyCard = Invoke-IProtectQuery @deletPermissionKeyCardSplatParams

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Deleted permission where [KEYKEYGROUPID = $($actionContext.References.Permission.Id)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json)"
                                IsError = $false
                            })
                    }
                    else {
                        Write-Warning "DryRun: Would delete permission where [KEYKEYGROUPID = $($actionContext.References.Permission.Id)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deletPermissionKeyCardSplatParams | ConvertTo-Json)"
                    }
                }
                catch {
                    $ex = $PSItem

                    if ($ex.Exception.Message -like "*Value already exists*" -or $ex.Exception.Message -like "*Kolom waarde is niet uniek*") {
                        Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                        $auditMessage = "Skipped deleting permission where [KEYKEYGROUPID = $($actionContext.References.Permission.Id)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Reason: Permission for accesskey already exists."

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                Message = $auditMessage
                                IsError = $false
                            })
                    }
                    else {
                        $auditMessage = "Error deleting permission where [KEYKEYGROUPID = $($actionContext.References.Permission.Id)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deletPermissionKeyCardSplatParams | ConvertTo-Json). Error: $($ex.Exception.Message)"
                        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = $auditMessage
                                IsError = $true
                            })

                        # Log query
                        Write-Warning "Query: $queryDeletePermissionKeyCard"

                        # Throw terminal error
                        throw $auditMessage
                    }
                }
                #endregion Delete permission for keycard
            }
            else {
                $auditMessage = "Skipped deleting permission where [KEYKEYGROUPID = $($actionContext.References.Permission.Id)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Reason: Permission for accesskey already no longer."

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $false
                    })
            }

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
            $auditMessage = "Skipped deleting permission where [KEYKEYGROUPID = $($actionContext.References.Permission.Id)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Reason: No keycard found where [$($correlationField)] = [$($correlationValue)]. Possibly indicating that it could be deleted, or not correlated."

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $false
                })

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