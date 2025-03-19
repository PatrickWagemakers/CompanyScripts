# Company-specific variables
$maindir = "\\server.domain.nl\powershell$\Scripts\Scripts"
$workdir = "\\server.domain.nl\powershell$\Scripts\Scripts"
$transdir = $workdir + '\transcripts'
$srvADFS = 'adfs.domain.daa.nl'
$srvEXCH = 'http://exchange.domain.daa.nl/Powershell/'
$goodcert = "CERTTHUMBNAIL"
$tenantID = "TENANTID"
$AZappID = "AZ-APP-ID"
$EXCHappID = "Exch-APP-ID"
$organization = "domain.onmicrosoft.com"
$serviceAccount = 'serviceaccount'
$exchangeAccount = 'exchangeaccount'
$testMailbox = 'ict@domain.nl'
$testAlias = 'ict'
$AzureDomain = "Company Domain"
$Domain = "domain.n"
$filelocale = "$workdir\Certificates\CreateUser_PSN_Certificate.pfx"

# Initialize error counter
$errorCount = 0

# User and transcript setup
$user = (Get-WMIObject -class Win32_ComputerSystem | select username).username
$uitvoerder = $user.split('\')[1]
$timestamp = (Get-date -format 'ddMMyyyyHHmmss')
$Transcriptfile = "$transdir\debug_$uitvoerder$timestamp.txt"
$debugfile = "$transdir\debugtrans_$uitvoerder$timestamp.txt"

Start-Transcript -Path $Transcriptfile
Start-Sleep -Seconds 1

# Importing modules
Import-Module ActiveDirectory
Import-Module "$maindir\Company_FrameWork.psm1"
Import-Module ExchangeOnlineManagement
Import-Module gmsacredential
Import-Module AzureAD
Import-Module CredentialManager

Start-Sleep -Seconds 1

# Retrieve credentials
$Servicecredentials = Get-GMSACredential -GMSAName $serviceAccount -Domain $domain
$Exchcredentials = Get-StoredCredential -target $exchangeAccount
$adminsrv = $Servicecredentials.userName
$excusr = $Exchcredentials.username

# Check installed module versions
$modules = @(
    @{Name = 'MicrosoftTeams'; MinVersion = '5.1.0'},
    @{Name = 'CredentialManager'; MinVersion = '2.0'},
    @{Name = 'gmsacredential'; MinVersion = '0.6'},
    @{Name = 'exchangeonlinemanagement'; MinVersion = '3.0.15'},
    @{Name = 'azuread'; MinVersion = '2.0.2'},
    @{Name = 'msonline'; MinVersion = '1.1.183'},
    @{Name = 'az'; MinVersion = '9.4.0'}
)

foreach ($module in $modules) {
    $mod = Get-InstalledModule -Name $module.Name
    $version = $mod.Version
    add-content -path $debugfile -value "$($module.Name) versie (minimaal v $($module.MinVersion) ?) : $version"
    Start-Sleep -Seconds 1
}

# ADFS Session
$DHPADFS2Session = New-PSSession -ComputerName $srvADFS -Credential $Servicecredentials
if (-not($DHPADFS2Session)) {
    add-content -path $debugfile -value "There is no session with AD-AADSync"
    $errorCount++
} else {
    add-content -path $debugfile -value "There is a session with AD-AADSync"
    Remove-PSSession $DHPADFS2Session
}

Start-Sleep -Seconds 1

# Certificate check
$Certs = Get-ChildItem -Path Cert:CurrentUser\MY | Where-Object {$_.Subject -match "CreateUser"} | Select-Object Thumbprint
$certs = $Certs.Thumbprint
if ($Certs -eq $goodcert) {
    add-content -path $debugfile -value "The right Certificate is installed"
} else {
    add-content -path $debugfile -value "The right Certificate is not installed"
    $errorCount++
    Write-Host 'Password and Secret are stored in the Password Vault'
    $certpass = Read-Host 'Place the correct Certificate Password for UserCreateScript_SPN :'
    $Pass = ConvertTo-SecureString -String $certpass -Force -AsPlainText
    $User = "whatever"
    $Cred = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $User, $Pass
    Import-PfxCertificate -FilePath $filelocale -CertStoreLocation Cert:\CurrentUser\My -Password $Cred.Password
    $Certs = Get-ChildItem -Path Cert:CurrentUser\MY | Where-Object {$_.Subject -match "CreateUser"} | Select-Object Thumbprint
    $certs = $Certs.Thumbprint
    if ($Certs -eq $goodcert) {
        add-content -path $debugfile -value "The right Certificate is now installed"
    } else {
        add-content -path $debugfile -value "The right Certificate is still not installed"
        $errorCount++
    }
}

Start-Sleep -Seconds 1

# Exchange On-Prem Session
$ExchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $srvEXCH -Authentication Kerberos -Credential $Exchcredentials
if (-not($ExchangeSession)) {
    add-content -path $debugfile -value "There is NO session with Exchange OnPrem"
    $errorCount++
} else {
    add-content -path $debugfile -value "There is a session with Exchange Onprem"
    Remove-PSSession $ExchangeSession
}

Start-Sleep -Seconds 1

# Exchange Online Session
Connect-ExchangeOnline -CertificateThumbPrint $goodcert -Organization $organization -AppID $ExchappID
$boxtest = (Get-ExoMailbox -Identity $testMailbox -Properties alias).Alias
if ($boxtest -ne $testAlias) {
    add-content -path $debugfile -value "There is NO session with ExchangeOnline"
    $errorCount++
} else {
    add-content -path $debugfile -value "There is a session with ExchangeOnline"
    Disconnect-ExchangeOnline -Confirm:$false
}

Start-Sleep -Seconds 1

# Azure AD Session
Connect-AzureAD -TenantId $tenantID -ApplicationId $AZappID -CertificateThumbprint $goodcert
$azureconnected = (Get-AzureADTenantDetail).DisplayName
if ($azureconnected -ne $AzureDomain) {
    add-content -path $debugfile -value "There is NO session with Azure"
    $errorCount++
} else {
    add-content -path $debugfile -value "There is a session with Azure"
    Disconnect-AzureAD
}

Start-Sleep -Seconds 1
add-content -path $debugfile -value "Einde of the Checks"

# Display error count if there are any errors
if ($errorCount -gt 0) {
    Write-Host "Total number of errors: $errorCount"
}
