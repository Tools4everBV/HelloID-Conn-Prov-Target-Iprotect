#####################################################
# HelloID-Conn-Prov-Target-Iprotect-Delete
#
# Version: 2.0.0
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

#Set DeletePerson to false if deleting the employee object is sufficient, leaving the person object intact.
#deleteperson may easily fail if there are still other database tables that refer to it
$deletePerson = $true

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
                    $errorMessage = "Error executing Iprotect sql command. $QueryDescription. Error: $errorDescription"
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
                $errorNode = $resultNode.SelectSingleNode('ERROR')
                if ($null -ne $errorNode) {
                    throw "Error executing Iprotect sql command. $QueryDescription. Error: $($errorNode.DESCRIPTION)";
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
                Message = "Delete Iprotect account from: [$($p.DisplayName)] will be executed during enforcement"
            })
    }

    if (-not($dryRun -eq $true)) {
        Write-Verbose "Deleting Iprotect account with accountReference: [$($aRef.EmployeeId)]"
        $success = $false

        $jSessionID = Get-JSessionID
        $authenticationResult = Get-AuthenticationResult -JSessionID $jSessionID

        if (-Not ($authenticationResult.StatusCode -eq 302)) {
            $success = $false
            $ErrorMessage = "iprotect query for person " + $p.ExternalId + ". Authentication failed with error $($authenticationResult.StatusCode)";
            throw $ErrorMessage
        }

        # it is assumed that keygroup memberships for both the accesskey and the licenseplate (if any)  are removed by helloid prior of running this delete script

        # remove the assigment to the user from the Accesskey
        if (![string]::IsNullOrEmpty($aRef.AccesskeyId)) {
            $query = "UPDATE Accesskey SET PersonID = null WHERE ACCESSKEYID = $($aRef.AccesskeyID)"
            $QueryDescription = "Unassign accesskey [$($aRef.AccesskeyID)] from user [$($aRef.EmployeeId)]"
            $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType "update" -QueryDescription $QueryDescription
            $auditLogs.Add([PSCustomObject]@{
                    Message = "Successfully executed task:  `'$QueryDescription`' "
                    IsError = $false
                })
        }

        # remove the assigment to the user from the Licensplate
        if (![string]::IsNullOrEmpty($aRef.AccessKeyIdLicensePlate)) {
            $query = "UPDATE Accesskey SET PersonID = null WHERE ACCESSKEYID = $($aRef.AccessKeyIdLicensePlate)"
            $QueryDescription = "Unassign LicensePlate [$($aRef.AccessKeyIdLicensePlate)] from employee [$($aRef.EmployeeId)]"
            $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType "update" -QueryDescription $QueryDescription
            $auditLogs.Add([PSCustomObject]@{
                    Message = "Successfully executed task:  `'$QueryDescription`' "
                    IsError = $false
                })
        }

        # employee object has to be deleted prior to the person object because of dependency
        $query = "DELETE FROM EMPLOYEE WHERE EMPLOYEEID = $($aRef.EmployeeID)"
        $queryDescription = "Deleting Employee object with EmployeeId $($aRef.EmployeeID)"

        try {
            $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType "update" -QueryDescription $QueryDescription
        } catch {
            if (-not $_.Exception.Message -match 'SQLExtendedException: No where match') {
                throw $_
            }
            Write-Verbose "Employee account [$($aRef.EmployeeID)] already removed!" -Verbose
        }

        if ($deletePerson -eq $true) {
            $query = "DELETE FROM PERSON WHERE PERSONID = $($aRef.PersonID)"
            $queryDescription = "Deleting person object with personid $($aRef.PersonID)"
            $null = Invoke-IProtectQuery -JSessionID $jSessionID -Query $query -QueryType "update" -QueryDescription $QueryDescription
        }

        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Message = "Iprotect account  delete  for employee " + $p.ExternalId + " was succesful"
                IsError = $false
            })
    }
} catch {

    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -ErrorObject $ex
        $errorMessage = "Could not delete Iprotect account. Error: $($errorObj.ErrorMessage)"
    } else {
        $errorMessage = "Could not delete Iprotect account. Error: $($ex.Exception.Message)"
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
