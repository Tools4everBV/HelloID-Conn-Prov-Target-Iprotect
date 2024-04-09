#################################################
# HelloID-Conn-Prov-Target-iProtect-Permissions-KeyGroups-KeyCard
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

    #region Get keygroups for keycard
    try {
        $queryGetKeyGroupsKeyCard = "
        SELECT
            KEYGROUPID,
            NAME
        FROM
            KEYGROUP
        "

        $getKeyGroupsKeyCardSplatParams = @{
            BaseUrl    = $actionContext.Configuration.BaseUrl
            JSessionID = $jSessionID
            Query      = $queryGetKeyGroupsKeyCard
            QueryType  = "query"
        }

        Write-Verbose "Querying keygroups for keycard. SplatParams: $($getKeyGroupsKeyCardSplatParams | ConvertTo-Json)"

        $keyGroupsKeyCard = $null
        $keyGroupsKeyCard = Invoke-IProtectQuery @getKeyGroupsKeyCardSplatParams

        #region GK - Filter out reference type 15 as this only used for access key of type license plate with parking gate authorization
        $keyGroupsKeyCard = $keyGroupsKeyCard | Where-Object { $_.KEYGROUPID -ne 15 }
        #endregion GK - Filter out reference type 15 as this only used for access key of type license plate with parking gate authorization
            
        Write-Information "Queried keygroups for keycard. Result count: $(($keyGroupsKeyCard | Measure-Object).Count)"
    }
    catch {
        $ex = $PSItem

        $auditMessage = "Error querying keygroups for keycard. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = $auditMessage
                IsError = $true
            })

        # Log query
        Write-Warning "Query: $queryGetKeyGroupsKeyCard"
        
        # Throw terminal error
        throw $auditMessage
    }
    #endregion Get keygroups for keycard
}
catch {
    $ex = $PSItem
    Write-Warning "Terminal error occurred. Error Message: $($ex.Exception.Message)"
}
finally {
    # Send results
    foreach ($keyGroupKeyCard in $keyGroupsKeyCard) {
        # Shorten DisplayName to max. 100 chars
        $displayName = "KeyGroup - KeyCard - $($keyGroupKeyCard.NAME)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length)) 
        $permission = @{
            DisplayName    = $displayName
            Identification = @{
                Id   = $keyGroupKeyCard.KEYGROUPID
                Name = $keyGroupKeyCard.NAME
                Type = "KeyGroup"
            }
        }

        $outputContext.Permissions.Add($permission)
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