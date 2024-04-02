#################################################
# HelloID-Conn-Prov-Target-iProtect-Delete
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

#region Person
# Define correlation
$personCorrelationField = "PERSONID"
$personCorrelationValue = $actionContext.References.Account.Person.PERSONID

# Define Account mapping object
$personAccount = [PSCustomObject]$actionContext.Data.Person

# Define properties to query
$personPropertiesToQuery = @("PERSONID") + $personAccount.PSObject.Properties.Name | Select-Object -Unique
#endRegion Person

#region Employee
# Define correlation
$employeeCorrelationField = "EMPLOYEEID"
$employeeCorrelationValue = $actionContext.References.Account.Employee.EMPLOYEEID

# Define Account mapping object
$employeeAccount = [PSCustomObject]$actionContext.Data.Employee

# Define properties to query
$employeePropertiesToQuery = @("EMPLOYEEID") + $employeeAccount.PSObject.Properties.Name | Select-Object -Unique
#endRegion Employee

#region KeyCard
# Define correlation
$keyCardCorrelationField = "ACCESSKEYID"
$keyCardCorrelationValue = $actionContext.References.Account.KeyCard.ACCESSKEYID

# Define Account mapping object
$keyCardAccount = [PSCustomObject]$actionContext.Data.KeyCard

# Define properties to query
$keyCardPropertiesToQuery = @("ACCESSKEYID") + $keyCardAccount.PSObject.Properties.Name | Select-Object -Unique
#endRegion KeyCard

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

    #region KeyCard
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
        $actionKeyCard = "Delete"
    }
    elseif (($correlatedKeyCard | Measure-Object).count -gt 1) {
        $actionKeyCard = "MultipleFound"
    }
    elseif (($correlatedKeyCard | Measure-Object).count -eq 0) {
        $actionKeyCard = "NotFound"
    }

    # Process
    switch ($actionKeyCard) {
        "Delete" {
            #region 20230703-021 - GK - Delete all assigned groups from badge
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
            #endregion 20230703-021 - GK - Delete all assigned groups from badge

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

        "MultipleFound" {
            $auditMessage = "Multiple keycards found where [$keyCardCorrelationField] = [$($keyCardCorrelationValue)]. Please correct this so the keycards are unique."

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
            $auditMessage = "Skipped deleting keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Reason: No keycard found where [$($correlationField)] = [$($correlationValue)]. Possibly indicating that it could be deleted, or not correlated."
    
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $false
                })
    
            break
        }
    }
    #endregion KeyCard

    #region LicensePlate
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
        $actionLicensePlate = "Delete"
    }
    elseif (($correlatedLicensePlate | Measure-Object).count -gt 1) {
        $actionLicensePlate = "MultipleFound"
    }
    elseif (($correlatedLicensePlate | Measure-Object).count -eq 0) {
        $actionLicensePlate = "NotFound"
    }

    # Process
    switch ($actionLicensePlate) {
        "Delete" {
            #region Unassign licenseplate
            try {
                $queryUnassignLicensePlate = "
                UPDATE
                    ACCESSKEY
                SET
                    PERSONID = null
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

        "MultipleFound" {
            $auditMessage = "Multiple licenseplates found where [$licensePlateCorrelationField] = [$($licensePlateCorrelationValue)]. Please correct this so the licenseplates are unique."

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
            $auditMessage = "Skipped deleting licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). Reason: No licenseplate found where [$($correlationField)] = [$($correlationValue)]. Possibly indicating that it could be deleted, or not correlated."
    
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $false
                })
    
            break
        }
    }
    #endregion LicensePlate

    #region Employee
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
        $actionEmployee = "Delete"
    }
    elseif (($correlatedEmployee | Measure-Object).count -gt 1) {
        $actionEmployee = "MultipleFound"
    }
    elseif (($correlatedEmployee | Measure-Object).count -eq 0) {
        $actionEmployee = "NotFound"
    }

    # Process
    switch ($actionEmployee) {
        "Delete" {
            #region Delete employee
            try {
                $queryDeleteEmployee = "
                DELETE
                FROM
                    EMPLOYEE
                WHERE
                    $($employeeCorrelationField) = $($employeeCorrelationValue)
                "

                $deleteEmployeeSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryDeleteEmployee
                    QueryType  = "update"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Deleting employee with AccountReference: $($actionContext.References.Account.Employee | ConvertTo-Json). SplatParams: $($deleteEmployeeSplatParams | ConvertTo-Json)"   

                    $deletedEmployee = Invoke-IProtectQuery @deleteEmployeeSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Deleted employee with AccountReference: $($actionContext.References.Account.Employee | ConvertTo-Json)"
                            IsError = $false
                        })

                }
                else {
                    Write-Warning "DryRun: Would delete employee with AccountReference: $($actionContext.References.Account.Employee | ConvertTo-Json). SplatParams: $($deleteEmployeeSplatParams | ConvertTo-Json)"
                }
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error deleting employee with AccountReference: $($actionContext.References.Account.Employee | ConvertTo-Json). Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryDeleteEmployee"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion Delete employee

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
            $auditMessage = "Skipped deleting employee with AccountReference: $($actionContext.References.Account.Employee | ConvertTo-Json). Reason: No employee found where [$($correlationField)] = [$($correlationValue)]. Possibly indicating that it could be deleted, or not correlated."
    
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $false
                })
    
            break
        }
    }
    #endregion Employee

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
        $actionPerson = "Delete"
    }
    elseif (($correlatedPerson | Measure-Object).count -gt 1) {
        $actionPerson = "MultipleFound"
    }
    elseif (($correlatedPerson | Measure-Object).count -eq 0) {
        $actionPerson = "NotFound"
    }

    # Process
    switch ($actionPerson) {
        "Delete" {
            #region Delete person
            try {
                $queryDeletePerson = "
                DELETE
                FROM
                    PERSON
                WHERE
                    $($personCorrelationField) = $($personCorrelationValue)
                "

                $deletePersonSplatParams = @{
                    BaseUrl    = $actionContext.Configuration.BaseUrl
                    JSessionID = $jSessionID
                    Query      = $queryDeletePerson
                    QueryType  = "update"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Deleting person with AccountReference: $($actionContext.References.Account.Person | ConvertTo-Json). SplatParams: $($deletePersonSplatParams | ConvertTo-Json)"   

                    $deletedPerson = Invoke-IProtectQuery @deletePersonSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Deleted person with AccountReference: $($actionContext.References.Account.Person | ConvertTo-Json)"
                            IsError = $false
                        })

                }
                else {
                    Write-Warning "DryRun: Would delete person with AccountReference: $($actionContext.References.Account.Person | ConvertTo-Json). SplatParams: $($deletePersonSplatParams | ConvertTo-Json)"
                }
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error deleting person with AccountReference: $($actionContext.References.Account.Person | ConvertTo-Json). Error: $($ex.Exception.Message)"
                Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $true
                    })

                # Log query
                Write-Warning "Query: $queryDeletePerson"

                # Throw terminal error
                throw $auditMessage
            }
            #endregion Delete person

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
            $auditMessage = "Skipped deleting person with AccountReference: $($actionContext.References.Account.Person | ConvertTo-Json). Reason: No person found where [$($correlationField)] = [$($correlationValue)]. Possibly indicating that it could be deleted, or not correlated."
    
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = $auditMessage
                    IsError = $false
                })
    
            break
        }
    }
    #endregion Person
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
    if ([String]::IsNullOrEmpty($outputContext.AccountReference)) {
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