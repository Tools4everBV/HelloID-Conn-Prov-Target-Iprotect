#################################################
# HelloID-Conn-Prov-Target-iProtect-Disable
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

# Define properties to enclose in specific characters
# String values have to be enclosed in single quotes
$keyCardPropertiesToEncloseInSingleQuotes = @(
    "RCN"
)
# Date values have to be enclosed in hashtags
$keyCardPropertiesToEncloseInHashtags = @()

# Define properties to compare for update
# Currently, only VALID is supported
$keyCardPropertiesToCompare = @("VALID")

# Define properties to query
$keyCardPropertiesToQuery = @("ACCESSKEYID") + $keyCardAccount.PSObject.Properties.Name | Select-Object -Unique
#endRegion KeyCard

#region LicensePlate
# Define correlation
$licensePlateCorrelationField = "ACCESSKEYID"
$licensePlateCorrelationValue = $actionContext.References.Account.LicensePlate.ACCESSKEYID

# Define Account mapping object
$licensePlateAccount = [PSCustomObject]$actionContext.Data.LicensePlate

# Define properties to enclose in specific characters
# String values have to be enclosed in single quotes
$licensePlatePropertiesToEncloseInSingleQuotes = @(
    "RCN"
)
# Date values have to be enclosed in hashtags
$licensePlatePropertiesToEncloseInHashtags = @()

# Define properties to compare for update
# Currently, only VALID is supported
$licensePlatePropertiesToCompare = @("VALID")

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
    if (-not [string]::IsNullOrEmpty($keyCardCorrelationValue)) {
        #region Get current keycard
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
        #endregion Get current keycard

        if (($correlatedKeyCard | Measure-Object).count -eq 1) {
            try {
                Write-Verbose "Comparing current keyCard to mapped properties"

                # Create reference object from correlated account
                $keyCardReferenceObject = [PSCustomObject]@{}
                foreach ($correlatedKeyCardProperty in $correlatedKeyCard.PSObject.Properties) {
                    $keyCardReferenceObject | Add-Member -MemberType NoteProperty -Name $correlatedKeyCardProperty.Name -Value $correlatedKeyCardProperty.Value -Force
                }

                # Create difference object from mapped properties
                $keyCardDifferenceObject = [PSCustomObject]@{}
                foreach ($keyCardAccountProperty in $keyCardAccount.PSObject.Properties) {
                    $keyCardDifferenceObject | Add-Member -MemberType NoteProperty -Name $keyCardAccountProperty.Name -Value $keyCardAccountProperty.Value -Force
                }

                $keyCardSplatCompareProperties = @{
                    ReferenceObject  = $keyCardReferenceObject.PSObject.Properties | Where-Object { $_.Name -in $keyCardPropertiesToCompare }
                    DifferenceObject = $keyCardDifferenceObject.PSObject.Properties | Where-Object { $_.Name -in $keyCardPropertiesToCompare }
                }
                if ($null -ne $keyCardSplatCompareProperties.ReferenceObject -and $null -ne $keyCardSplatCompareProperties.DifferenceObject) {
                    $keyCardPropertiesChanged = Compare-Object @keyCardSplatCompareProperties -PassThru
                    $keyCardOldProperties = $keyCardPropertiesChanged | Where-Object { $_.SideIndicator -eq "<=" }
                    $keyCardNewProperties = $keyCardPropertiesChanged | Where-Object { $_.SideIndicator -eq "=>" }
                }

                if ($keyCardNewProperties) {
                    $actionKeyCard = "Disable"
                    Write-Information "Keycard property(s) required to update: $($keyCardNewProperties.Name -join ', ')"
                }
                else {
                    $actionKeyCard = "NoChanges"
                }

                Write-Verbose "Compared current keyCard to mapped properties"
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error comparing current keyCard to mapped properties. Error: $($ex.Exception.Message)"
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
        elseif (($correlatedKeyCard | Measure-Object).count -gt 1) {
            $actionKeyCard = "MultipleFound"
        }
        elseif (($correlatedKeyCard | Measure-Object).count -eq 0) {
            $actionKeyCard = "NotFound"
        }

        # Process
        switch ($actionKeyCard) {
            "Disable" {
                #region Disable keycard
                try {
                    # Create object to disable keycard as empty hashtable
                    $objectDisableKeyCard = @{}

                    # Add the disabled properties to object to disable keycard
                    foreach ($keyCardNewProperty in $keyCardNewProperties) {
                        # Enclose specific fields with single quotes
                        if ($keyCardNewProperty.Name -in $keyCardPropertiesToEncloseInSingleQuotes) {
                            [void]$objectDisableKeyCard.Add("$($keyCardNewProperty.Name)", "'$($keyCardNewProperty.Value)'")
                        }
                        # Enclose specific fields with hashtags
                        elseif ($keyCardNewProperty.Name -in $keyCardPropertiesToEncloseInHashtags) {
                            [void]$objectDisableKeyCard.Add("$($keyCardNewProperty.Name)", "#$($keyCardNewProperty.Value)#")
                        }
                        else {
                            [void]$objectDisableKeyCard.Add("$($keyCardNewProperty.Name)", "$($keyCardNewProperty.Value)")
                        }
                    }

                    # Seperate Properties with comma , and enclose values with single quotes ''
                    $queryDisableKeyCardPropertiesAndValues = ($objectDisableKeyCard.Keys | ForEach-Object {
                            "$($_) = $($objectDisableKeyCard.$_)"
                        }) -join " , "

                    $queryDisableKeyCard = "
                UPDATE
                    ACCESSKEY
                SET
                    $queryDisableKeyCardPropertiesAndValues
                WHERE
                    $($keyCardCorrelationField) = $($keyCardCorrelationValue)
                "

                    $disableKeyCardSplatParams = @{
                        BaseUrl    = $actionContext.Configuration.BaseUrl
                        JSessionID = $jSessionID
                        Query      = $queryDisableKeyCard
                        QueryType  = "update"
                    }

                    if (-Not($actionContext.DryRun -eq $true)) {
                        Write-Verbose "Disabling keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($disableKeyCardSplatParams | ConvertTo-Json)"   

                        $disabledKeyCard = Invoke-IProtectQuery @disableKeyCardSplatParams

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Disabled keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json)"
                                IsError = $false
                            })

                    }
                    else {
                        Write-Warning "DryRun: Would disable keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). SplatParams: $($disableKeyCardSplatParams | ConvertTo-Json)"
                    }
                }
                catch {
                    $ex = $PSItem

                    $auditMessage = "Error disabling keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Error: $($ex.Exception.Message)"
                    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $true
                        })

                    # Log query
                    Write-Warning "Query: $queryDisableKeyCard"

                    # Throw terminal error
                    throw $auditMessage
                }
                #endregion Disable keycard

                break
            }

            "NoChanges" {
                $auditMessage = "Skipped disabling keyCard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Reason: No changes."

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = $auditMessage
                        IsError = $false
                    })
                
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
                $auditMessage = "Skipped disabling keycard with AccountReference: $($actionContext.References.Account.KeyCard | ConvertTo-Json). Reason: No keycard found where [$($correlationField)] = [$($correlationValue)]. Possibly indicating that it could be deleted, or not correlated."
    
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $false
                    })

                break
            }
        }
    }
    #endregion KeyCard

    #region LicensePlate
    if (-not [string]::IsNullOrEmpty($licensePlateCorrelationValue)) {
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
            try {
                Write-Verbose "Comparing current licensePlate to mapped properties"

                # Create reference object from correlated account
                $licensePlateReferenceObject = [PSCustomObject]@{}
                foreach ($correlatedLicensePlateProperty in $correlatedLicensePlate.PSObject.Properties) {
                    $licensePlateReferenceObject | Add-Member -MemberType NoteProperty -Name $correlatedLicensePlateProperty.Name -Value $correlatedLicensePlateProperty.Value -Force
                }

                # Create difference object from mapped properties
                $licensePlateDifferenceObject = [PSCustomObject]@{}
                foreach ($licensePlateAccountProperty in $licensePlateAccount.PSObject.Properties) {
                    $licensePlateDifferenceObject | Add-Member -MemberType NoteProperty -Name $licensePlateAccountProperty.Name -Value $licensePlateAccountProperty.Value -Force
                }

                $licensePlateSplatCompareProperties = @{
                    ReferenceObject  = $licensePlateReferenceObject.PSObject.Properties | Where-Object { $_.Name -in $licensePlatePropertiesToCompare }
                    DifferenceObject = $licensePlateDifferenceObject.PSObject.Properties | Where-Object { $_.Name -in $licensePlatePropertiesToCompare }
                }

                if ($null -ne $licensePlateSplatCompareProperties.ReferenceObject -and $null -ne $licensePlateSplatCompareProperties.DifferenceObject) {
                    $licensePlatePropertiesChanged = Compare-Object @licensePlateSplatCompareProperties -PassThru
                    $licensePlateOldProperties = $licensePlatePropertiesChanged | Where-Object { $_.SideIndicator -eq "<=" }
                    $licensePlateNewProperties = $licensePlatePropertiesChanged | Where-Object { $_.SideIndicator -eq "=>" }
                }

                if ($licensePlateNewProperties) {
                    $actionLicensePlate = "Disable"
                    Write-Information "Licenseplate property(s) required to update: $($licensePlateNewProperties.Name -join ', ')"
                }
                else {
                    $actionLicensePlate = "NoChanges"
                }

                Write-Verbose "Compared current licensePlate to mapped properties"
            }
            catch {
                $ex = $PSItem

                $auditMessage = "Error comparing current licensePlate to mapped properties. Error: $($ex.Exception.Message)"
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
        elseif (($correlatedLicensePlate | Measure-Object).count -gt 1) {
            $actionLicensePlate = "MultipleFound"
        }
        elseif (($correlatedLicensePlate | Measure-Object).count -eq 0) {
            $actionLicensePlate = "NotFound"
        }

        # Process
        switch ($actionLicensePlate) {
            "Disable" {
                #region Disable licenseplate
                try {
                    # Create object to disable licenseplate as empty hashtable
                    $objectDisableLicensePlate = @{}

                    # Add the disabled properties to object to disable licenseplate
                    foreach ($licenseplateNewProperty in $licenseplateNewProperties) {
                        # Enclose specific fields with single quotes
                        if ($licenseplateNewProperty.Name -in $licenseplatePropertiesToEncloseInSingleQuotes) {
                            [void]$objectDisableLicensePlate.Add("$($licenseplateNewProperty.Name)", "'$($licenseplateNewProperty.Value)'")
                        }
                        # Enclose specific fields with hashtags
                        elseif ($licenseplateNewProperty.Name -in $licenseplatePropertiesToEncloseInHashtags) {
                            [void]$objectDisableLicensePlate.Add("$($licenseplateNewProperty.Name)", "#$($licenseplateNewProperty.Value)#")
                        }
                        else {
                            [void]$objectDisableLicensePlate.Add("$($licenseplateNewProperty.Name)", "$($licenseplateNewProperty.Value)")
                        }
                    }

                    # Seperate Properties with comma , and enclose values with single quotes ''
                    $queryDisableLicensePlatePropertiesAndValues = ($objectDisableLicensePlate.Keys | ForEach-Object {
                            "$($_) = $($objectDisableLicensePlate.$_)"
                        }) -join " , "

                    $queryDisableLicensePlate = "
                UPDATE
                    ACCESSKEY
                SET
                    $queryDisableLicensePlatePropertiesAndValues
                WHERE
                    $($licensePlateCorrelationField) = $($licensePlateCorrelationValue)
                "

                    $disableLicensePlateSplatParams = @{
                        BaseUrl    = $actionContext.Configuration.BaseUrl
                        JSessionID = $jSessionID
                        Query      = $queryDisableLicensePlate
                        QueryType  = "update"
                    }

                    if (-Not($actionContext.DryRun -eq $true)) {
                        Write-Verbose "Disabling licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). SplatParams: $($disableLicensePlateSplatParams | ConvertTo-Json)"   

                        $disabledLicensePlate = Invoke-IProtectQuery @disableLicensePlateSplatParams

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Disabled licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json)"
                                IsError = $false
                            })
                    }
                    else {
                        Write-Warning "DryRun: Would disable licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). SplatParams: $($disableLicensePlateSplatParams | ConvertTo-Json)"
                    }
                }
                catch {
                    $ex = $PSItem

                    $auditMessage = "Error disabling licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). Error: $($ex.Exception.Message)"
                    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = $auditMessage
                            IsError = $true
                        })

                    # Log query
                    Write-Warning "Query: $queryDisableLicensePlate"

                    # Throw terminal error
                    throw $auditMessage
                }
                #endregion Disable licenseplate

                break
            }

            "NoChanges" {
                $auditMessage = "Skipped disabling licensePlate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). Reason: No changes."

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = $auditMessage
                        IsError = $false
                    })
                
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
                $auditMessage = "Skipped disabling licenseplate with AccountReference: $($actionContext.References.Account.LicensePlate | ConvertTo-Json). Reason: No licenseplate found where [$($correlationField)] = [$($correlationValue)]. Possibly indicating that it could be deleted, or not correlated."
    
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = $auditMessage
                        IsError = $false
                    })

                break
            }
        }
    }
    #endregion LicensePlate
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