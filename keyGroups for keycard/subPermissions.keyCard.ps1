#####################################################
# HelloID-Conn-Prov-Target-iProtect-SubPermissions-KeyGroups-KeyCard-Revoke
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

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$currentPermissions = @{ }
foreach ($permission in $actionContext.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}

#region KeyGroup for KeyCard
# Define correlation
$keyGroupKeyCardCorrelationField = "NAME"

# Define properties to query
$keyGroupKeyCardPropertiesToQuery = @("KEYGROUPID", "NAME") | Select-Object -Unique
#endRegion KeyGroup for KeyCard

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

    #region Get keygroups for keycard
    try {
        $queryGetKeyGroupsKeyCard = "
        SELECT
            $($keyGroupKeyCardPropertiesToQuery -Join ',')
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

        # Group on correlation property to check if group exists (as correlation property has to be unique for a group)
        $keyGroupsKeyCardGrouped = $keyGroupsKeyCard | Group-Object $keyGroupKeyCardCorrelationField -AsHashTable -AsString

        Write-Verbose "Queried keygroups for keycard. Result count: $(($keyGroupsKeyCard | Measure-Object).Count)"
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

    $desiredPermissions = @{ }
    if (-Not($actionContext.Operation -eq "revoke")) {
        # Person Based Logic
        $iProtectGroups = $personContext.Person.Custom.iProtectGroups -split "\|"
        Write-Verbose "iProtectGroups: $($iProtectGroups | ConvertTo-Json)"
        if (-not[String]::IsNullOrEmpty($iProtectGroups)) {
            foreach ($iProtectGroup in $iProtectGroups) {
                try {
                    $keyGroupKeyCardCorrelationValue = $iProtectGroup
                    Write-Verbose "Checking keygroup for keycard where [$keyGroupKeyCardCorrelationField] = [$($keyGroupKeyCardCorrelationValue)]"
        
                    $keyGroupKeyCard = $null
                    $keyGroupKeyCard = $keyGroupsKeyCardGrouped["$($keyGroupKeyCardCorrelationValue)"]
        
                    if (($keyGroupKeyCard | Measure-Object).count -eq 0) {
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "No keygroup for keycard found where [$keyGroupKeyCardCorrelationField] = [$($keyGroupKeyCardCorrelationValue)]."
                                IsError = $true
                            })
                    }
                    elseif (($keyGroupKeyCard | Measure-Object).count -gt 1) {
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Multiple keygroups for keycard found where [$keyGroupKeyCardCorrelationField] = [$($keyGroupKeyCardCorrelationValue)]. Please correct this so the groups are unique."
                                IsError = $true
                            })
                    }
                    else {
                        # Add group to desired permissions with the id as key and the displayname as value (use id to avoid issues with name changes and for uniqueness)
                        $desiredPermissions["$($keyGroupKeyCard.KEYGROUPID)"] = $keyGroupKeyCard.NAME
                    }
                }
                catch {
                    $ex = $PSItem
        
                    $auditMessage = "Error checking keygroup for keycard where [$keyGroupKeyCardCorrelationField] = [$($keyGroupKeyCardCorrelationValue)]. Error: $($ex.Exception.Message)"
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
        }
    }
    Write-Warning ("Existing Permissions: {0}" -f ($eRef.CurrentPermissions.DisplayName | ConvertTo-Json))
    Write-Warning ("Desired Permissions: {0}" -f ($desiredPermissions.Values | ConvertTo-Json))

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

    # Compare desired with current permissions and grant permissions
    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })

        if (-Not $currentPermissions.ContainsKey($permission.Name)) {
            #region Create permission for keycard
            try {
                $objectCreatePermissionKeyCard = @{
                    ACCESSKEYID = "$($correlatedKeyCard.ACCESSKEYID)"
                    KEYGROUPID  = "$($permission.Name)"
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
                    Write-Verbose "Creating permission where [KEYKEYGROUPID = $($permission.Name)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($createPermissionKeyCardSplatParams | ConvertTo-Json)"

                    $createdPermissionKeyCard = $null
                    $createdPermissionKeyCard = Invoke-IProtectQuery @createPermissionKeyCardSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Created permission where [KEYKEYGROUPID = $($permission.Name)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json)"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would create permission where [KEYKEYGROUPID = $($permission.Name)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($createPermissionKeyCardSplatParams | ConvertTo-Json)"
                }
            }
            catch {
                $ex = $PSItem

                if ($ex.Exception.Message -like "*Value already exists*" -or $ex.Exception.Message -like "*Kolom waarde is niet uniek*") {
                    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                    $auditMessage = "Skipped creating permission where [KEYKEYGROUPID = $($permission.Name)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Reason: Permission for accesskey already exists."

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $false
                        })
                }
                else {
                    $auditMessage = "Error creating permission where [KEYKEYGROUPID = $($permission.Name)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($createPermissionKeyCardSplatParams | ConvertTo-Json). Error: $($ex.Exception.Message)"
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
            }
            #endregion Create permission for keycard
        }
    }

    # Compare current with desired permissions and revoke permissions
    $newCurrentPermissions = @{ }
    foreach ($permission in $currentPermissions.GetEnumerator()) {
        if (-Not $desiredPermissions.ContainsKey($permission.Name) -AND $permission.Name -ne "No permissions defined") {
            #region Get current permission for keycard
            try {
                $queryCorrelatePermissionKeyCard = "
                SELECT
                    KEYKEYGROUPID
                FROM
                    KEYKEYGROUP
                WHERE
                    KEYGROUPID = $($permission.Name)
                    AND ACCESSKEYID = $($correlatedKeyCard.ACCESSKEYID)
                "

                $correlatePermissionKeyCardSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryCorrelatePermissionKeyCard
                    QueryType  = "query"
                }

                Write-Verbose "Querying permission for keycard where [KEYGROUPID] = [$($permission.Name)] AND [ACCESSKEYID] = [$($correlatedKeyCard.ACCESSKEYID)]. SplatParams: $($correlatePermissionKeyCardSplatParams | ConvertTo-Json)"

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
                        Write-Verbose "Deleting permission where [KEYKEYGROUPID = $($permission.Name)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deletPermissionKeyCardSplatParams | ConvertTo-Json)"

                        $deletedPermissionKeyCard = $null
                        $deletedPermissionKeyCard = Invoke-IProtectQuery @deletPermissionKeyCardSplatParams

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Deleted permission where [KEYKEYGROUPID = $($permission.Name)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json)"
                                IsError = $false
                            })
                    }
                    else {
                        Write-Warning "DryRun: Would delete permission where [KEYKEYGROUPID = $($permission.Name)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deletPermissionKeyCardSplatParams | ConvertTo-Json)"
                    }
                }
                catch {
                    $ex = $PSItem

                    if ($ex.Exception.Message -like "*Value already exists*" -or $ex.Exception.Message -like "*Kolom waarde is niet uniek*") {
                        Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                        $auditMessage = "Skipped deleting permission where [KEYKEYGROUPID = $($permission.Name)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Reason: Permission for accesskey already exists."

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                Message = $auditMessage
                                IsError = $false
                            })
                    }
                    else {
                        $auditMessage = "Error deleting permission where [KEYKEYGROUPID = $($permission.Name)] for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($deletPermissionKeyCardSplatParams | ConvertTo-Json). Error: $($ex.Exception.Message)"
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
        }
        else {
            $newCurrentPermissions[$permission.Name] = $permission.Value
        }
    }
}
catch {
    $ex = $PSItem
    Write-Warning "Terminal error occurred. Error Message: $($ex.Exception.Message)"
}
finally {
    # Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
    if ($actionContext.Operation -match "update|grant" -AND $outputContext.SubPermissions.count -eq 0) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = "No permissions defined"
                Reference   = [PSCustomObject]@{ Id = "No permissions defined" }
            })

        Write-Warning "Skipped creating permissions for keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Reason: No permissions defined."
    }

    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
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