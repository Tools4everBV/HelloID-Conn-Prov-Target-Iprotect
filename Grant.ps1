#####################################################
# HelloID-Conn-Prov-Target-Iprotect-Entitlement-KeyGroupGrant
#
# Version: 2.0.0
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$pRef = $permissionReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

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
        Headers            = @{'Content-Type' = 'application/x-www-form-urlencoded' }
        UseBasicParsing    = $true
        TimeoutSec         = 6000
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
        Write-Verbose "$($_.Exception.Message)" -Verbose
        Write-Verbose "$($_.Exception.InnerException.Message)" -Verbose
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
    if ($config.ProxyAddress) {
        $splatParams['Proxy'] = $config.ProxyAddress
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
                    $errorMessage = "Could not Invoke-IProtectQuery: $QueryDescription. Error: $errorDescription"
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
                    throw "Could not Invoke-IProtectQuery. $QueryDescription. Error: $($errorNode.DESCRIPTION)";
                }
                Write-Output $resultNode
            }
        }
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
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
#endregion

try {
    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true) {
        $auditLogs.Add([PSCustomObject]@{
                Message = "Grant Iprotect entitlement: [$($pRef.DisplayName)] to: [$($p.DisplayName)] will be executed during enforcement"
            })
    }
    $jSessionID = Get-JSessionID
    $authenicationResult = Get-AuthenticationResult -JSessionID $jSessionID

    if (-Not ($authenicationResult.StatusCode -eq 302)) {
        throw  "Authentication failed with error $($authenicationResult.StatusCode)";
    }

    if (-not($dryRun -eq $true)) {
        Write-Verbose "Granting Iprotect entitlement: [$($pRef.DisplayName)]"
        try {
            $insertQuery = "INSERT INTO keykeygroup (accesskeyid, keygroupid) VALUES ($($aRef.AccessKeyId), $($pref.Reference))"
            $result = Invoke-IProtectQuery -JSessionID $jSessionID -Query $insertQuery -QueryType 'Update'
        } catch {
            if (-not $_.Exception.Message.contains('already exists')) {
                throw $_
            }
        }
        $auditLogs.Add([PSCustomObject]@{
                Message = "Grant Iprotect entitlement: [$($pRef.DisplayName)] was successful, ACCESS_KEY_ID Added: [$($($aRef.AccessKeyId))]"
                IsError = $false
            })
    }
    $success = $true
} catch {
    $success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -ErrorObject $ex
        $errorMessage = "Could not grant Iprotect entitlement: [$($pRef.DisplayName)]. Error: $($errorObj.ErrorMessage)"
    } else {
        $errorMessage = "Could not grant Iprotect entitlement: [$($pRef.DisplayName)]. Error: $($ex.Exception.Message)"
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
        Success   = $success
        Auditlogs = $auditLogs
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
