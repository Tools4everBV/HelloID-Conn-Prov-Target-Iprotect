#################################################################
# HelloID-Conn-Prov-Target-IProtect-RevokePermission-Group
# PowerShell V2
#################################################################

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

# Begin
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

    $splatGetUser = @{
        JSessionID = $jSessionID
        WebSession = $webSession
        Query      = $queryGetPerson
        QueryType  = 'query'
    }
    
    $correlatedAccount = Invoke-IProtectQuery @splatGetUser

    if ($null -ne $correlatedAccount) {
        Write-Information "Getting linked  accessKey Cards of employee [$($actionContext.References.Account)]"F
        $queryGetAccessKeys = "SELECT
            accesskeyid,
            rcn,
            personid,
            valid,
            startdate,
            enddate,
            unlimited
        FROM
            accesskey
        WHERE
            personid = $($actionContext.References.Account)"

        $splatGetAccessKeys = @{
            JSessionID = $jSessionID
            WebSession = $webSession
            Query      = $queryGetAccessKeys
            QueryType  = 'query'
        }

        $accessKeyList = Invoke-IProtectQuery @splatGetAccessKeys
    }

    $accessKeyCount = ($accessKeyList | Measure-Object).Count
    if ($null -ne $correlatedAccount -and $accessKeyCount -gt 0) {
        $action = 'RevokePermission'
    }
    elseif ($null -ne $correlatedAccount) {
        $action = 'NoAccessKeysFound'
    }
    else {
        $action = 'NotFound'
    }
    # Process
    switch ($action) {
        'RevokePermission' {
            foreach ($accessKey in $accessKeyList) {
                Write-Information "Getting IProtect GroupId for AccessKey: [$($accessKey.AccessKeyId)] RCN: [$($accessKey.RCN)]"
                $getKeyKeyGroupIdQuery = "
                SELECT
                    KEYKEYGROUPID,
                    KEYGROUPID,
                    ACCESSKEYID
                FROM keykeygroup
                WHERE keykeygroup.accesskeyid = $($accessKey.AccessKeyId)"

                $splatGetKeyKeyGroupId = @{
                    JSessionID = $jSessionID
                    WebSession = $webSession
                    Query      = $getKeyKeyGroupIdQuery
                    QueryType  = 'query'
                }

                $keyKeyGroupPerAccessKey = Invoke-IProtectQuery @splatGetKeyKeyGroupId
                
                $keyKeyGroup = $keyKeyGroupPerAccessKey | Where-Object { $_.KeyGroupId -eq $actionContext.References.Permission.Reference }
                if (-not ($null -eq $keyKeyGroup )) {
                    $deleteKeyKeyGroupIdQuery = "
                            DELETE FROM keykeygroup
                            WHERE keykeygroupid = $($keyKeyGroup.KeyKeyGroupId)"
                    if (-not($actionContext.DryRun -eq $true)) {
                        Write-Information "Revoking IProtect permission: [$($actionContext.References.Permission.Reference)] from AccessKey [$($accessKey.AccessKeyId)] RCN: [$($accessKey.RCN)]"
                        $splatDeleteKeyKeyGroupId = @{
                            JSessionID = $jSessionID
                            WebSession = $webSession
                            Query      = $deleteKeyKeyGroupIdQuery
                            QueryType  = 'update'
                        }

                        $null = Invoke-IProtectQuery @splatDeleteKeyKeyGroupId
                    }
                    else {
                        Write-Information "[DryRun] Revoke IProtect permission: [$($actionContext.References.Permission.Reference)] from AccessKey [$($accessKey.AccessKeyId)] RCN: [$($accessKey.RCN)], will be executed during enforcement"
                    }
                }
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Revoke permission [$($actionContext.PermissionDisplayName)] [$($actionContext.References.Permission.Reference)] from AccessKey [$($accessKey.AccessKeyId)] RCN: [$($accessKey.RCN)] was successful"
                        IsError = $false
                    })
            }

            if ( -not ($outputContext.AuditLogs.IsError -contains $true)) {
                $outputContext.Success = $true
            }
        }

        'NoAccessKeysFound' {
            Write-Information "IProtect account: [$($actionContext.References.Account)] has no linked AccessKeys. Cannot revoke permission [$($actionContext.PermissionDisplayName)] [$($actionContext.References.Permission.Reference)], action skipped"
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "IProtect account: [$($actionContext.References.Account)] has no linked AccessKeys. Cannot revoke permission [$($actionContext.PermissionDisplayName)] [$($actionContext.References.Permission.Reference)], action skipped"
                    IsError = $false
                })
            break
        }

        'NotFound' {
            Write-Information "IProtect account: [$($actionContext.References.Account)] could not be found, possibly indicating that it could be deleted"
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "IProtect account: [$($actionContext.References.Account)] could not be found, possibly indicating that it could be deleted"
                    IsError = $false
                })
            break
        }
    }
}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-IProtectError -ErrorObject $ex
        $auditMessage = "Could not revoke IProtect permission. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Could not revoke IProtect permission. Error: $($_.Exception.Message)"
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