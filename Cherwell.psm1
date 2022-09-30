Class Cherwell {
    hidden [string]$Server
    [ValidateSet("Internal", "Windows")]
    hidden [string]$Authentication
    hidden [pscredential]$Credential
    hidden [string]$URI
    hidden [string]$TokenURI
    hidden [string]$APIKEY
    hidden [string]$Token
    [DateTime]$TokenExpiration
    hidden [hashtable]$RequestHeader
    hidden [hashtable]$TokenRequestBody
    [BusinessObject[]]$BusinessObjects
    [BusinessObject]$CurrentBusinessObject
    [BusinessObjectRecord]$CurrentRecord
    [Search]$CurrentSearch
    [BusinessObjectRecord[]]$SearchResults

    Cherwell([string]$Server, [string]$Authentication, [string]$APIKEY, [pscredential]$Credential) {
        $this.Server = $Server
        $this.Authentication = $Authentication
        $this.Credential = $Credential
        $this.URI = "https://$($Server)/CherwellAPI"
        $this.APIKEY = $APIKEY
    }
    Cherwell([string]$Server, [string]$Authentication, [string]$APIKEY) {
        $this.Server = $Server
        $this.Authentication = $Authentication
        $this.URI = "https://$($Server)/CherwellAPI"
        $this.APIKEY = $APIKEY
    }
    Cherwell([string]$Server, [string]$Authentication, [pscredential]$Credential) {
        if (-not $env:Cherwell_Client_ID) {
            throw "API-Key (Client_ID) missing. Either pass it as an Argument or set the Environment Variable 'Cherwell_Client_ID'."
        }
        $this.APIKEY = $env:Cherwell_Client_ID
        $this.Server = $Server
        $this.Authentication = $Authentication
        $this.Credential = $Credential
        $this.URI = "https://$($Server)/CherwellAPI"
    }
    Cherwell([string]$Server, [string]$Authentication) {
        if (-not $env:Cherwell_Client_ID) {
            throw "API-Key (Client_ID) missing. Either pass it as an Argument or set the Environment Variable 'Cherwell_Client_ID'."
        }
        $this.APIKEY = $env:Cherwell_Client_ID
        $this.Server = $Server
        $this.Authentication = $Authentication
        $this.Credential = Get-Credential
        $this.URI = "https://$($Server)/CherwellAPI"
    }
    Cherwell([string]$Server) {
        if (-not $env:Cherwell_Client_ID) {
            throw "API-Key (Client_ID) missing. Either pass it as an Argument or set the Environment Variable 'Cherwell_Client_ID'."
        }
        $this.APIKEY = $env:Cherwell_Client_ID

        $query = $true
        while ($query) {
            $Selection = Read-Host @"
────────────────────────────────────────────
Please select an Authentication-Method:
1) Windows (DEFAULT)
2) Internal

Your Selection
"@
            switch ($Selection) {
                "2" { 
                    $this.Authentication = "Internal"
                    $query = $false
                }
                "1" {
                    $this.Authentication = "Windows"
                    $query = $false
                }
                Default {
                    $this.Authentication = "Windows"
                    $query = $false
                }
            }
        }

        $this.Server = $Server
        $this.Credential = Get-Credential
        $this.URI = "https://$($Server)/CherwellAPI"
    }
    Cherwell() {
        $Selection = ""
        $query = $true
        while ($query) {
            $Selection = Read-Host @"
────────────────────────────────────────────
Please select an Authentication-Method:
1) Windows (DEFAULT)
2) Internal

Your Selection
"@
            switch ($Selection -ne "") {
                "2" { 
                    $this.Authentication = "Internal"
                    $query = $false
                }
                "1" {
                    $this.Authentication = "Windows"
                    $query = $false
                }
                Default {
                    $this.Authentication = "Windows"
                    $query = $false
                }
            }
        }

        $query = $true
        while ($query) {
            $Selection = Read-Host @"
`r`r`r────────────────────────────────────────────
Please submit a Server (FQDN)
"@
            if ($Selection -ne "") {
                $this.Server = $Selection
                $query = $false
            }
        }
        $this.Credential = Get-Credential
        $this.URI = "https://$($Selection)/CherwellAPI"
        $this.APIKEY = "f4cdf151-57ef-4fda-bc58-431c4ee46aa0"
    }
    
    [void] Login() {
        $requestBody = @{
            "Accept"     = "application/json"
            "grant_type" = "password"
            "client_id"  = $this.APIKEY
        }
        
        $this.TokenURI = "$($this.URI)/token?auth_mode=$($this.Authentication)&api_key=$($this.APIKEY)"

        if ($this.Authentication -eq "Windows") {
            
            $requestBody.Add("username", "$($this.Credential.GetNetworkCredential().Domain)\$($this.Credential.GetNetworkCredential().UserName)")
        } else {
            $requestBody.Add("username", $this.Credential.GetNetworkCredential().UserName)
        }
        $requestBody.Add("password", $this.Credential.GetNetworkCredential().Password)

        $this.TokenRequestBody = $requestBody
        $requestArgs = @{
            "Method"      = "POST"
            "Uri"         = $this.TokenURI
            "Body"        = $this.TokenRequestBody
            "ContentType" = "application/json"
        }

        $response = Invoke-RestMethod @requestArgs
        $this.UpdateVerification(
            $response.access_token,
            $response.expires_in
        )
    }

    [bool] hidden VerifyToken() {
        if (-not $this.TokenExpiration) {
            return $false
        }
        return (Get-Date) -le $this.TokenExpiration
    }

    [void] hidden RefreshToken() {
        if (-not $this.VerifyToken()) {
            $this.Login()
            return
        }
        $requestBody = $this.TokenRequestBody
        if ($requestBody.refresh_token) {
            $requestBody.refresh_token = $this.Token
        }
        else {
            $requestBody.Add("refresh_token", $this.Token)
        }
        $response = Invoke-RestMethod -Method POST -Uri $this.TokenURI -Body $requestBody -ContentType application/json
        $this.UpdateVerification(
            $response.access_token,
            $response.expires_in
        )
    }
    
    [void] hidden UpdateVerification(
        [string]$Token,
        [int]$TokenExpiresIn
    ) {
        $this.Token = $Token
        $this.TokenExpiration = (Get-Date).AddSeconds($TokenExpiresIn - 10)
        $this.RequestHeader = @{"Authorization" = "Bearer $($Token)" }
    }

    [void] hidden GetBusinessObjects() {
        if (-not $this.VerifyToken()) {
            $this.RefreshToken()
        }
        $response = Invoke-RestMethod -Method GET -Headers $this.RequestHeader `
            -ContentType "appliaction/json" -Uri "$($this.URI)/api/V1/getbusinessobjectsummaries/type/All"
        
        foreach ($bo in $response) {
            $this.BusinessObjects += [BusinessObject]::new(
                $bo.busObId,
                $bo.displayName,
                $bo.name,
                $bo.major,
                $bo.group,
                $bo.lookup,
                $bo.supporting
            )

            foreach ($b in $bo.groupSummaries) {
                $this.BusinessObjects += [BusinessObject]::new(
                    $b.busObId,
                    $b.displayName,
                    $b.name,
                    $b.major,
                    $b.group,
                    $b.lookup,
                    $b.supporting
                )
            }
        }
    }

    [void] hidden GetCurrentRelationships() {
        [Relationship[]]$Relationships = @()
        $requestURI = "$($this.URI)/api/V1/getbusinessobjectschema/busobid/$($this.CurrentBusinessObject.BusinessObjectID)"
        $requestBody = @{
            "busobId"              = $this.CurrentBusinessObject.BusinessObjectID
            "includerelationships" = $true
        }
        $response = Invoke-RestMethod -Method GET -Headers $this.RequestHeader `
            -Uri $requestURI -Body $requestBody -ContentType application/json

        foreach ($rel in $response.relationships) {
            $Relationships += [Relationship]::new(
                $rel.relationshipId,
                $rel.displayName,
                $rel.description,
                $this.CurrentBusinessObject.BusinessObjectID,
                $rel.target,
                $rel.cardinality
            )
        }
        $this.CurrentBusinessObject.Relationships = $Relationships
    }

    [BusinessObjectRecord] hidden GetBusinessObjectTemplate() {
        if (-not $this.VerifyToken()) {
            $this.RefreshToken()
        }
        if (-not $this.CurrentBusinessObject) {
            throw "No BusinessObject selected. Please use SelectBusinessObjectByDisplayName prior using this Method."
        }
        
        [BusinessObjectRecord]$Template = [BusinessObjectRecord]::new(
            $this.CurrentBusinessObject,
            $this.CurrentBusinessObject.BusinessObjectID
        )

        $requestURI = "$($this.URI)/api/V1/getbusinessobjecttemplate"

        $requestBody = @{
            "busObId"    = $this.CurrentBusinessObject.BusinessObjectID
            "includeAll" = $true
        }

        $response = Invoke-RestMethod -Method Post -Headers $this.RequestHeader -Uri $requestURI -Body $requestBody
        
        [Field[]]$Fields = @()

        foreach ($f in $response.fields) {
            $Fields += [Field]::new(
                $f.displayName,
                $f.name,
                $f.fieldId,
                $f.fullFieldId,
                $f.value,
                $f.dirty,
                $false
            )
        }

        $Template.Fields = $Fields
        $Template = $this.MarkRequiredFields($Template)
        $this.CurrentRecord = $Template

        return $Template
    }

    [void] SelectBusinessObjectByDisplayName(
        [string]$DisplayName
    ) {
        if (-not $this.BusinessObjects) {
            if (-not $this.VerifyToken()) {
                $this.RefreshToken()
            }
            $this.GetBusinessObjects()
        }
        if (-not $DisplayName -in $this.BusinessObjects) {
            throw "No BusinessObject found: $($DisplayName)"
        }
        $this.CurrentBusinessObject = $this.BusinessObjects | Where-Object { $_.DisplayName -eq $DisplayName }
        $this.GetCurrentRelationships()
        $this.GetBusinessObjectTemplate()
    } 
    
    [BusinessObjectRecord[]] GetRecordBySearch(
        [string]$SearchText
    ) {
        if (-not $this.VerifyToken()) {
            $this.RefreshToken()
        }
        if (-not $this.CurrentBusinessObject) {
            throw "No BusinessObject selected. Please use SelectBusinessObjectByDisplayName prior using this Method."
        }
        [BusinessObjectRecord[]]$Records = @()
        $requestURI = "$($this.URI)/api/V1/getquicksearchresults"
        $requestBody = @{
            "busObIds"   = $this.CurrentBusinessObject.BusinessObjectID
            "searchText" = $SearchText   
        }
        
        $response = Invoke-RestMethod -Method POST -Headers $this.RequestHeader -Uri $requestURI -Body $requestBody

        ($response.groups | Where-Object { $_.title -like "$($this.CurrentBusinessObject.DisplayName)*" }).simpleResultsListItems | ForEach-Object {
            $Records += $this.GetRecordByRecordID($_.busObRecId)
        }

        $this.CurrentRecord = $Records[0]

        return $Records
    }

    [BusinessObjectRecord] GetRecordByPublicID(
        [string]$PublicID
    ) {
        if (-not $this.VerifyToken()) {
            $this.RefreshToken()
        }
        [BusinessObjectRecord]$Record = $null
                
        if (-not $this.CurrentBusinessObject) {
            throw "No BusinessObject selected. Please use SelectBusinessObjectByDisplayName prior using this Method."
        }
        
        $requestURI = "$($this.URI)/api/V1/getbusinessobject/busobid/$($this.CurrentBusinessObject.BusObID)/publicid/$($PublicID)"
                
        $response = Invoke-RestMethod -Method GET -Headers $this.RequestHeader -Uri $requestURI -ContentType application/json
                
        [Field[]]$Fields = @()
                
        foreach ($f in $response.fields) {
            $Fields += [Field]::new(
                $f.displayName,
                $f.name,
                $f.fieldId,
                $f.fullFieldId,
                $f.value,
                $f.dirty,
                $false
            )
        }
        
        [Link[]]$Links = @()
        foreach ($l in $response.links) {
            $Links += [Link]::new(
                $l.name,
                $l.url
            )
        }

        $Record = [BusinessObjectRecord]::new(
            $this.CurrentBusinessObject,
            $response.busObRecId,
            $response.busObId,
            $response.busObPublicId,
            $Fields,
            $Links

        )
        $Record = $this.MarkRequiredFields($Record)
        $this.CurrentRecord = $Record
        return $Record
    }
    
    [BusinessObjectRecord] GetRecordByRecordID(
        [string]$RecordID
    ) {
        if (-not $this.VerifyToken()) {
            $this.RefreshToken()
        }
        [BusinessObjectRecord]$Record = $null
                
        if (-not $this.CurrentBusinessObject) {
            throw "No BusinessObject selected. Please use SelectBusinessObjectByDisplayName prior using this Method."
        }

        $requestURI = "$($this.URI)/api/V1/getbusinessobject/busobid/$($this.CurrentBusinessObject.BusinessObjectID)/busobrecid/$($RecordID)"
                
        $response = Invoke-RestMethod -Method GET -Headers $this.RequestHeader -Uri $requestURI -ContentType application/json
                
        [Field[]]$Fields = @()
                
        foreach ($f in $response.fields) {
            $Fields += [Field]::new(
                $f.displayName,
                $f.name,
                $f.fieldId,
                $f.fullFieldId,
                $f.value,
                $f.dirty,
                $false
            )
        }
        
        [Link[]]$Links = @()
        foreach ($l in $response.links) {
            $Links += [Link]::new(
                $l.name,
                $l.url
            )
        }

        $Record = [BusinessObjectRecord]::new(
            $this.CurrentBusinessObject,
            $response.busObId,
            $response.busObRecId,
            $response.busObPublicId,
            $Fields,
            $Links
        )

        $Record = $this.MarkRequiredFields($Record)
        $this.CurrentRecord = $Record
        return $Record
    }

    [void] SaveRecord() {
        if (-not $this.CurrentRecord) {
            throw "No Record to save. Please use one of the Methods GetRecordByRecordID, GetRecordByPublicID, GetRecordBySearch or GetBusinessObjectTemplate to grab a Record and modify it with the Method UpdateFieldByDisplayName prior Saving."
        }
        if (-not $this.VerifyToken()) {
            $this.RefreshToken()
        }

        $requestURI = "$($this.URI)/api/V1/savebusinessobject"

        $fields = @()
        $this.CurrentRecord.Fields | Where-Object { $_.Dirty -eq $true } | ForEach-Object {
            $fields += @{
                "dirty"       = $_.Dirty
                "displayName" = $_.DisplayName
                "fieldId"     = $_.FieldID
                "fullFieldId" = $_.FullFieldID
                "name"        = $_.Name
                "value"       = $_.Value
            }
        }

        $requestBody = @{
            "busObId" = $this.CurrentRecord.BusinessObjectID
            "fields"  = $fields
            "persist" = $true
        } 

        if ($this.CurrentRecord.RecordID) {
            $requestBody.Add("busObRecId", $this.CurrentRecord.RecordID)
        }

        $requestBody = $requestBody | ConvertTo-Json
        $requestBody = [System.Text.Encoding]::UTF8.GetBytes($requestBody)

        $response = Invoke-RestMethod -Method POST -Headers $this.RequestHeader -Uri $requestURI -Body $requestBody -ContentType application/json
        Write-Host $response
        $this.GetRecordByRecordID($response.busObRecId)
    }

    [void] DeleteRecord(
        [BusinessObjectRecord]$Record
    ) {
        if (-not $this.VerifyToken()) {
            $this.RefreshToken()
        }

        $Record.Delete($this.RequestHeader, $this.URI)
    }
    
    [void] RefreshCurrentRecord() {
        $this.CurrentRecord = $this.GetRecordByRecordID($this.CurrentRecord.RecordID)
    }

    [void] LinkChild(
        [BusinessObjectRecord]$ChildRecord
    ) {
        $RelationshipID = $null
        foreach ($rel in $this.CurrentRecord.BusinessObject.Relationships) {
            if ($rel.TargetBusinessObjectID -eq $ChildRecord.BusinessObjectID) {
                $RelationshipID = $rel.RelationshipID
            }
        }

        if (-not $RelationshipID) {
            throw "No Relationship found. Parent: $($this.CurrentRecord.BusinessObject.DisplayName), Record: $($this.CurrentRecord.PublicID), Child: $($ChildRecord.BusinessObject.DisplayName), ChildRecord: $($ChildRecord.PublicID)"
        }

        $this.CurrentRecord.LinkChildByRecordID(
            $this.RequestHeader,
            $this.URI,
            $RelationshipID,
            $ChildRecord.BusinessObjectID,
            $ChildRecord.RecordID
        )
    }

    [void] LinkChildByIDs(
        [string]$ChildBusinessObjectID,
        [string]$ChildRecordID
    ) {
        $RelationshipID = $null
        foreach ($rel in $this.CurrentRecord.BusinessObject.Relationships) {
            if ($rel.TargetBusinessObjectID -eq $ChildBusinessObjectID) {
                $RelationshipID = $rel.RelationshipID
            }
        }

        if (-not $RelationshipID) {
            throw "No Relationship found. Parent: $($this.CurrentRecord.BusinessObjectID), Record: $($this.CurrentRecord.RecordID), Child: $($ChildBusinessObjectID), ChildRecord: $($ChildRecordID)"
        }

        $this.CurrentRecord.LinkChildByRecordID(
            $this.RequestHeader,
            $this.URI,
            $RelationshipID,
            $ChildBusinessObjectID,
            $ChildRecordID
        )
    }

    [BusinessObjectRecord] hidden MarkRequiredFields(
        [BusinessObjectRecord]$Record
    ) {
        if (-not $this.VerifyToken()) {
            $this.RefreshToken()
        }
        if (-not $this.CurrentBusinessObject) {
            throw "No BusinessObject selected. Please use SelectBusinessObjectByDisplayName prior using this Method."
        }
        $requestURI = "$($this.URI)/api/V1/getbusinessobjecttemplate"

        $requestBody = @{
            "busObId"         = $this.CurrentBusinessObject.BusinessObjectID
            "includeRequired" = $true
        }

        $response = Invoke-RestMethod -Method Post -Headers $this.RequestHeader -Uri $requestURI -Body $requestBody
        
        foreach ($f in $response.fields) {
            foreach ($rf in $Record.Fields) {
                if ($rf.Name -eq $f.name) {
                    $rf.Required = $true
                }
            }
        }
        return $Record
    }

    [void] NewSearch() {
        if (-not $this.CurrentBusinessObject) {
            throw "No BusinessObject selected. Please use SelectBusinessObjectByDisplayName prior using this Method."
        }
        $this.CurrentSearch = [Search]::new($this.CurrentBusinessObject)
    }

    [void] NewSearch(
        [SearchFilter[]]$SearchFilters
    ) {
        if (-not $this.CurrentBusinessObject) {
            throw "No BusinessObject selected. Please use SelectBusinessObjectByDisplayName prior using this Method."
        }
        $this.CurrentSearch = [Search]::new($this.CurrentBusinessObject, $SearchFilters)
    }

    [void] GetSearchResults(
        [bool]$IncludeAllFields
    ) {
        if (-not $this.CurrentSearch) {
            $this.NewSearch()
        }
        if (-not $this.CurrentSearch.BusinessObject) {
            $this.CurrentSearch.BusinessObject = $this.CurrentBusinessObject
        }
        if (-not $this.VerifyToken()) {
            $this.RefreshToken()
        }
        [BusinessObjectRecord[]]$Records = $null

        $requestURI = "$($this.URI)/api/V1/getsearchresults"
        
        $PageNumber = 1
        $PageSize = 200
        $Collected = 0
        $TotalRows = 0
        $response = $null
        do {
            Write-Host "`r$(" "*60)" -NoNewline
            Write-Host "`rCurrent Page: $($PageNumber) Collected: $($Collected) of $($TotalRows)" -NoNewline
            $requestBody = $this.CurrentSearch.GetRequestBody($IncludeAllFields, $PageNumber, $PageSize) | ConvertTo-Json
    
            $response = Invoke-RestMethod -Method Post -Headers $this.RequestHeader -Uri $requestURI -Body $requestBody -ContentType application/json
            $TotalRows = $response.totalRows
            $Collected += $response.businessObjects.Count
            $PageNumber++
            
            foreach ($r in $response.businessObjects) {
                [Field[]]$Fields = @()
                foreach ($f in $r.fields) {
                    $Fields += [Field]::new(
                        $f.displayName,
                        $f.name,
                        $f.fieldId,
                        $f.fullFieldId,
                        $f.value,
                        $f.dirty,
                        $false 
                    )
                    
                }

                [Link[]]$Links = @()
                foreach ($l in $r.links) {
                    $Links += [Link]::new(
                        $l.name,
                        $l.url
                    )
                }
    
                $Record = [BusinessObjectRecord]::new(
                    $this.CurrentBusinessObject,
                    $r.busObId,
                    $r.busObRecId,
                    $r.busObPublicId,
                    $Fields,
                    $Links
                )

                $Records += $Record
            }
        } while ($Collected -lt $TotalRows)
        Write-Host "`r$(" "*60)" -NoNewline
        Write-Host "`rCollected $($Collected) of $($TotalRows) Datasets" -NoNewline
        Write-Host ""

        $this.SearchResults = $Records
    }

    [void] AddSearchFilterByFieldDisplayName(
        [string]$DisplayName,
        [string]$Operator,
        [string]$Value
    ) {
        if ("eq", "gt", "lt", "contains", "startswith" -notcontains $Operator) {
            throw "Invalid Operator. Please use 'eq', 'gt', 'lt', 'contains' or 'startswith'"
        }
        if (-not $this.CurrentRecord) {
            throw "No Record to save. Please use one of the Methods GetRecordByRecordID, GetRecordByPublicID, GetRecordBySearch or GetBusinessObjectTemplate to grab a Record and modify it with the Method UpdateFieldByDisplayName prior Saving."
        }
        if (-not $this.CurrentSearch) {
            $this.NewSearch()
        }
        
        $this.CurrentSearch.AddSearchFilterByField($this.CurrentRecord.GetFieldByDisplayName($DisplayName), $Operator, $Value)
    }
}

Class BusinessObject {
    [string]$BusinessObjectID
    [string]$DisplayName
    [string]$Name
    [bool]$Major
    [bool]$Group
    [bool]$Lookup
    [bool]$Supporting
    [Relationship[]]$Relationships
    
    BusinessObject(
        [string]$BusinessObjectID,
        [string]$DisplayName,
        [string]$Name,
        [bool]$Major,
        [bool]$Group,
        [bool]$Lookup,
        [bool]$Supporting,
        [Relationship[]]$Relationships
    ) {
        $this.BusinessObjectID = $BusinessObjectID
        $this.DisplayName = $DisplayName
        $this.Name = $Name
        $this.Major = $Major
        $this.Group = $Group
        $this.Lookup = $Lookup
        $this.Supporting = $Supporting
        $this.Relationships = $Relationships
    }

    BusinessObject(
        [string]$BusinessObjectID,
        [string]$DisplayName,
        [string]$Name,
        [bool]$Major,
        [bool]$Group,
        [bool]$Lookup,
        [bool]$Supporting
    ) {
        $this.BusinessObjectID = $BusinessObjectID
        $this.DisplayName = $DisplayName
        $this.Name = $Name
        $this.Major = $Major
        $this.Group = $Group
        $this.Lookup = $Lookup
        $this.Supporting = $Supporting
    }
}

Class Relationship {
    [string]$RelationshipID
    [string]$DisplayName
    [string]$Description
    [string]$BusinessObjectID
    [string]$TargetBusinessObjectID
    [ValidateSet("OneToOne", "OneToMany")]
    [string]$RelationshipType
    
    Relationship(
        [string]$RelationshipID,
        [string]$DisplayName,
        [string]$Description,
        [string]$BusinessObjectID,
        [string]$TargetBusinessObjectID,
        [string]$RelationshipType
    ) {
        $this.RelationshipID = $RelationshipID
        $this.DisplayName = $DisplayName
        $this.Description = $Description
        $this.BusinessObjectID = $BusinessObjectID
        $this.TargetBusinessObjectID = $TargetBusinessObjectID
        $this.RelationshipType = $RelationshipType
    }
}

Class BusinessObjectRecord {
    [BusinessObject]$BusinessObject
    [string]$BusinessObjectID
    [string]$RecordID
    [string]$PublicID
    [Field[]]$Fields
    [Link[]]$Links

    BusinessObjectRecord(
        [BusinessObject]$BusinessObject,
        [string]$BusinessObjectID,
        [string]$RecordID,
        [string]$PublicID,
        [Field[]]$Fields,
        [Link[]]$Links
    ) {
        $this.BusinessObject = $BusinessObject
        $this.BusinessObjectID = $BusinessObjectID
        $this.RecordID = $RecordID
        $this.PublicID = $PublicID
        $this.Fields = $Fields
        $this.Links = $Links
    }
    BusinessObjectRecord(
        [BusinessObject]$BusinessObject,
        [string]$BusinessObjectID,
        [string]$RecordID,
        [string]$PublicID,
        [Field[]]$Fields
    ) {
        $this.BusinessObject = $BusinessObject
        $this.BusinessObjectID = $BusinessObjectID
        $this.RecordID = $RecordID
        $this.PublicID = $PublicID
        $this.Fields = $Fields
    }
    BusinessObjectRecord(
        [BusinessObject]$BusinessObject,
        [string]$BusinessObjectID
    ) {
        $this.BusinessObject = $BusinessObject
        $this.BusinessObjectID = $BusinessObjectID
    }

    [psobject] Print() {
        $output = New-Object -TypeName PSObject

        Add-Member -InputObject $output -MemberType NoteProperty -Name "BusinessObject" -Value $this.BusinessObject.DisplayName
        Add-Member -InputObject $output -MemberType NoteProperty -Name "BusinessObjectID" -Value $this.BusinessObject.BusinessObjectID
        Add-Member -InputObject $output -MemberType NoteProperty -Name "RecordID" -Value $this.RecordID
        Add-Member -InputObject $output -MemberType NoteProperty -Name "PublicID" -Value $this.PublicID

        foreach ($f in $this.Fields | Sort-Object -Property Required, DisplayName) {
            if ([string]::IsNullOrEmpty($f.Value)) {
                continue
            }
            if ($f.Required) {
                $DisplayName = "$($f.DisplayName) (Required)"
            } else {
                $DisplayName = "$($f.DisplayName)"
            }
            Add-Member -InputObject $output -MemberType NoteProperty -Name $DisplayName -Value "$($f.Value)"
        }
        return $output
    }
    [psobject] PrintAll() {
        $output = New-Object -TypeName PSObject

        Add-Member -InputObject $output -MemberType NoteProperty -Name "BusinessObject" -Value $this.BusinessObject.DisplayName
        Add-Member -InputObject $output -MemberType NoteProperty -Name "BusinessObjectID" -Value $this.BusinessObject.BusinessObjectID
        Add-Member -InputObject $output -MemberType NoteProperty -Name "RecordID" -Value $this.RecordID
        Add-Member -InputObject $output -MemberType NoteProperty -Name "PublicID" -Value $this.PublicID

        foreach ($f in $this.Fields | Sort-Object -Property Required, DisplayName) {
            if ($f.Required) {
                $DisplayName = "$($f.DisplayName) (Required)"
            } else {
                $DisplayName = "$($f.DisplayName)"
            }
            Add-Member -InputObject $output -MemberType NoteProperty -Name $DisplayName -Value "$($f.Value)"
        }
        return $output
    }

    [void] UpdateFieldByDisplayName(
        [string]$DisplayName,
        [string]$Value
    ) {
        foreach ($f in $this.Fields) {
            if ($DisplayName -eq $f.DisplayName) {
                $f.Update($Value)
            }
        }
    }

    [Field] GetFieldByDisplayName(
        [string]$DisplayName
    ) {
        [Field]$Field = $null

        foreach ($f in $this.Fields) {
            if ($DisplayName -eq $f.DisplayName) {
                $Field = $f
            }
        }
        if ($null -eq $Field) {
            throw "Field not found: $($DisplayName) in $($this.BusinessObject.DisplayName)"
        }
        return $Field
    }

    [void] Delete(
        [hashtable]$RequestHeader,
        [string]$URI
    ) {
        $requestURI = "$($URI)/api/V1/deletebusinessobject/busobid/$($this.BusinessObjectID)/busobrecid/$($this.RecordID)"
        
        $response = Invoke-RestMethod -Method Delete -Headers $RequestHeader -Uri $requestURI
        Write-Host ($response | ConvertTo-Json)
    }

    [void] LinkChildByRecordID(
        [hashtable]$RequestHeader,
        [string]$URI,
        [string]$RelationshipID,
        [string]$ChildBusinessObjectID,
        [string]$ChildRecordID
    ) {
        $requestURI = "$($URI)/api/V1/linkrelatedbusinessobject/parentbusobid/$($this.BusinessObjectID)/parentbusobrecid/$($this.RecordID)/relationshipid/$($RelationshipID)/busobid/$($ChildBusinessObjectID)/busobrecid/$($ChildRecordID)"
        
        $response = Invoke-RestMethod -Method GET -Headers $RequestHeader -Uri $requestURI 
        Write-Host ($response | ConvertTo-Json)
    }
}

Class Field {
    [string]$DisplayName
    [string]$Name
    [string]$FieldID
    [string]$FullFieldID
    [string]$Value
    [bool]$Dirty
    [bool]$Required

    Field(
        [string]$DisplayName,
        [string]$Name,
        [string]$FieldID,
        [string]$FullFieldID,
        [string]$Value,
        [bool]$Dirty,
        [bool]$Required
    ) {
        $this.DisplayName = $DisplayName
        $this.Name = $Name
        $this.FieldID = $FieldID
        $this.FullFieldID = $FullFieldID
        $this.Value = $Value
        $this.Dirty = $Dirty
        $this.Required = $Required
    }

    [void] Update(
        [string]$Value
    ) {
        $this.Value = $Value
        $this.Dirty = $true
    }
}

Class Link {
    [string]$Name
    [string]$URL

    Link(
        [string]$Name,
        [string]$URL
    ) {
        $this.Name = $Name
        $this.URL = $URL
    }
}

Class SearchFilter {
    [Field]$Field
    [ValidateSet("eq", "gt", "lt", "contains", "startswith")]
    [string]$Operator = "eq"
    [string]$Value

    SearchFilter(
        [Field]$Field,
        [string]$Operator,
        [string]$Value
    ) {
        $this.Field = $Field
        $this.Operator = $Operator
        $this.Value = $Value
    }

    [hashtable] ToHashtable() {
        return @{
            "fieldId"  = $this.Field.FieldID
            "operator" = $this.Operator
            "value"    = $this.Value
        }
    }
}

Class Search {
    [BusinessObject]$BusinessObject
    [SearchFilter[]]$SearchFilters
    
    Search(
        [BusinessObject]$BusinessObject,
        [SearchFilter[]]$SearchFilters
    ) {
        $this.BusinessObject = $BusinessObject
        $this.SearchFilters = $SearchFilters
    }

    Search(
        [BusinessObject]$BusinessObject
    ) {
        $this.BusinessObject = $BusinessObject
    }

    [hashtable] GetRequestBody(
        [bool]$IncludeAllFields,
        [int]$PageNumber,
        [int]$PageSize
    ) {
        $SearchFilters_ = @()
        foreach ($f in $this.SearchFilters) {
            $SearchFilters_ += $f.ToHashtable()
        }

        $requestBody = @{
            "busObId"          = $this.BusinessObject.BusinessObjectID
            "includeAllFields" = $IncludeAllFields
            "filters"          = $SearchFilters_
            "pageNumber"       = $PageNumber
            "pageSize"         = $PageSize
        }

        return $requestBody
    }

    [void] AddSearchFilter(
        [SearchFilter]$SearchFilter
    ) {
        $this.SearchFilters += $SearchFilter
    }

    [void] AddSearchFilterByField(
        [Field]$Field,
        [string]$Operator,
        [string]$Value
    ) {
        if ("eq", "gt", "lt", "contains", "startswith" -notcontains $Operator) {
            throw "Invalid Operator. Please use 'eq', 'gt', 'lt', 'contains' or 'startswith'"
        }
        $this.AddSearchFilter(
            [SearchFilter]::new(
                $Field,
                $Operator,
                $Value
            )
        )
    }

    [void] RemoveSearchFilterByDisplayName(
        [string]$DisplayName
    ) {
        [SearchFilter[]]$NewSearchFilters = @()
        foreach ($f in $this.SearchFilters) {
            if ($f.Field.DisplayName -eq $DisplayName) {
                continue
            }

            $NewSearchFilters += $f
        }
        $this.SearchFilters = $NewSearchFilters
    }
}

function New-CherwellConnection() {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true
        )]
        [string]
        $Server,
        [Parameter(
            Mandatory = $false
        )]
        [ValidateSet("Internal", "Windows")]
        [string]
        $Authentication = "Windows",
        [Parameter(
            Mandatory = $false
        )]
        [string]
        $APIKEY,
        [Parameter(
            Mandatory = $false
        )]
        [pscredential]
        $Credential
    )

    if (($Server) -and (-not $Authentication) -and (-not $Credential) -and (-not $APIKEY)) {
        $Connection = [cherwell]::new($Server)
    }
    elseif (($Server) -and ($Authentication) -and (-not $Credential) -and (-not $APIKEY)) {
        $Connection = [cherwell]::new($Server, $Authentication)
    }
    elseif (($Server) -and ($Authentication) -and (-not $Credential) -and ($APIKEY)) {
        $Connection = [cherwell]::new($Server, $Authentication, $APIKEY)
    }
    elseif (($Server) -and ($Authentication) -and ($Credential) -and (-not $APIKEY)) {
        $Connection = [cherwell]::new($Server, $Authentication, $Credential)
    }
    elseif (($Server) -and ($Authentication) -and ($Credential) -and ($APIKEY)) {
        $Connection = [cherwell]::new($Server, $Authentication, $APIKEY,$Credential)
    }
    else {
        $Connection = [cherwell]::new()
    }
    
    $Connection.Login()
    return $Connection
}

Export-ModuleMember *