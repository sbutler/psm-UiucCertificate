# Copyright (c) 2018 University of Illinois Board of Trustees
# All rights reserved.
#
# Developed by:       Technology Services
#                     University of Illinois at Urbana-Champaign
#                     https://techservices.illinois.edu/
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal with the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimers.
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimers in the
#   documentation and/or other materials provided with the distribution.
# * Neither the names of Technology Services, University of Illinois at
#   Urbana-Champaign, nor the names of its contributors may be used to
#   endorse or promote products derived from this Software without
#   specific prior written permission.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR
# ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE SOFTWARE.

Enum UiucCertificateScope {
  CurrentUser
  LocalMachine
  WebHosting
}

Set-Variable CertificateSubjectFormat -Option Constant -Value 'CN={0}, OU=Urbana-Champaign Campus, O=University of Illinois, L=Urbana, S=Illinois, C=US'
Set-Variable CertificateSubjectCNPattern -Option Constant -Value '(?:^|[\s,])CN=(?<cn>[^,]*)(?:,|$)'
Set-Variable ThumbprintPattern -Option Constant -Value '^[a-f0-9]{40}$'


<#
.SYNOPSIS
Finds a certificate in the Windows certificate store, returning a new
X509Certificate2 object.

.INPUTS

object. This can be either an X509Certificate object, a string
thumbprint, or a DNS domain.

.PARAMETER Certificate

X509Certificate object which will be copied as a new X509Certificate2.

.PARAMETER Thumbprint

SHA1 hash of the certificate to find.

.PARAMETER DnsName

Primary DNS domain name for the certificate to find. Using this parameter
might match multiple certificates.

.PARAMETER Scope

Where the certificate is stored: CurrentUser, LocalMachine, or
WebHosting. If LocalMachine or WebHosting then the user must be the
Adminsitrator.

.OUTPUTS

System.Security.Cryptography.X509Certificates.X509Certificate2.
Any found certificates that match the input criteria. The return value
should be disposed when you are finished using it.
#>
Function Find-UiucCertificate {
  Param(
    [parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true, ParameterSetName="InputObject")]
    [ValidateNotNullOrEmpty()]
    [object]$InputObject,

    [parameter(Mandatory=$true, ParameterSetName="Certificate")]
    [ValidateNotNullOrEmpty()]
    [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,

    [parameter(Mandatory=$true, ParameterSetName="DnsName")]
    [ValidateNotNullOrEmpty()]
    [string]$DnsName,

    [parameter(Mandatory=$true, ParameterSetName="Thumbprint")]
    [ValidateNotNullOrEmpty()]
    [string]$Thumbprint,

    [parameter(ParameterSetName="InputObject")]
    [parameter(ParameterSetName="DnsName")]
    [parameter(ParameterSetName="Thumbprint")]
    [UiucCertificateScope]$Scope = [UiucCertificateScope]::CurrentUser
  )

  Begin {
    Switch ($Scope) {
      CurrentUser     { $CertBase = 'Cert:\CurrentUser\My' }
      LocalMachine    { $CertBase = 'Cert:\LocalMachine\My' }
      WebHosting      { $CertBase = 'Cert:\LocalMachine\WebHosting' }
    }
  }

  Process {
    $setName = $PSCmdlet.ParameterSetName
    If ($setName -eq "InputObject") {
      # Do some detection of the data we were passed
      If ($InputObject -is [string]) {
        If ($InputObject -match $ThumbprintPattern) {
          $setName = "Thumbprint"
          $Thumbprint = $InputObject
        } Else {
          $setName = "DnsName"
          $DnsName = $InputObject
        }
      } ElseIf ($InputObject -is [System.Security.Cryptography.X509Certificates.X509Certificate]) {
        $setName = "Certificate"
        $Certificate = $InputObject
      }
    }

    Switch ($setName) {
      Certificate { New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $Certficate }
      Thumbprint  { Get-Item (Join-Path $CertBase $Thumbprint) }
      DnsName     { Get-ChildItem -LiteralPath $CertBase -DnsName $DnsName }
    }
  }
}


<#
.SYNOPSIS
Request certificate signing request (CSR) formatted for UIUC signing,
either using a new private key or renewing an existing certificate.

.INPUTS

object. This can be either an X509Certificate object, a string
thumbprint, or a DNS domain.

.PARAMETER Certificate

X509Certificate object of an existing certificate to generate the
request for.

.PARAMETER Thumbprint

SHA1 hash of an existing certificate to generate the request for.

.PARAMETER DnsName

Primary DNS domain name for the certificate to generate the request for.
Using this parameter might generate multiple requests when renewing.

.PARAMETER Renew

Renew an existing certificate instead of generating a new private key.
If the certificate cannot be found in the local stores then nothing
is done.

.PARAMETER Path

Path to save the CSR file as "$domain-csr.pem".If this is not
specified then the CSR is only available on the pipeline.

.PARAMETER HashAlgorithm

Hashing algorithm used for the CSR.

.PARAMETER KeyLength

Length of the private key in bits if creating a new private key. This
must be 2048 if you will submit the request for signing.

.PARAMETER Scope

Where the certificate is stored: CurrentUser, LocalMachine, or
WebHosting. If LocalMachine or WebHosting then the user must be the
Adminsitrator.

.OUTPUTS

@{DnsName; Subject; CertificateSigningRequest}.
Information about each certificate created. The values are strings in
PEM format.
#>
Function Request-UiucCertificate {
  Param(
    [parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true, ParameterSetName="InputObject")]
    [ValidateNotNullOrEmpty()]
    [object]$InputObject,

    [parameter(Mandatory=$true, ParameterSetName="Certificate")]
    [ValidateNotNullOrEmpty()]
    [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,

    [parameter(Mandatory=$true, ParameterSetName="DnsName")]
    [ValidateNotNullOrEmpty()]
    [string]$DnsName,

    [parameter(Mandatory=$true, ParameterSetName="Thumbprint")]
    [ValidateNotNullOrEmpty()]
    [string]$Thumbprint,

    [switch]$Renew = $false,

    [string]$Path = $null,

    [alias("Hash")]
    [ValidateSet("sha256", "sha384", "sha512")]
    [string]$HashAlgorithm = "sha256",

    [alias("Bits")]
    [ValidateScript({ $_ -ge 2048 })]
    [int]$KeyLength = 2048,

    [parameter(ParameterSetName="InputObject")]
    [parameter(ParameterSetName="DnsName")]
    [parameter(ParameterSetName="Thumbprint")]
    [UiucCertificateScope]$Scope = [UiucCertificateScope]::CurrentUser
  )

  Begin {
    $machineKeySet = ($Scope -eq [UiucCertificateScope]::LocalMachine) -or ($Scope -eq [UiucCertificateScope]::WebHosting)
  }

  Process {
    $values = If ($Renew) {
      # If we are renewing they values are the cert objects and only
      # process ones we can find.
      Switch ($PSCmdlet.ParameterSetName) {
        InputObject     { Find-UiucCertificate -InputObject $InputObject -Scope $Scope }
        Certificate     { Find-UiucCertificate -Certificate $Certificate }
        DnsName         { Find-UiucCertificate -DnsName $DnsName -Scope $Scope }
        Thumbprint      { Find-UiucCertificate -Thumbprint $Thumbprint -Scope $Scope }
      }
    } Else {
      # We are not renewing, so create a new request with a new key and
      # the values are the Subjects.
      Switch ($PSCmdlet.ParameterSetName) {
        InputObject {
          If ($InputObject -is [System.Security.Cryptography.X509Certificates.X509Certificate]) {
            $InputObject.Subject
          } ElseIf ($InputObject -is [string]) {
            If ($InputObject -match $ThumbprintPattern) {
              Find-UiucCertificate -Thumbprint $InputObject -Scope $Scope | select -First 1 | % { $_.Subject }
            } Else {
              $CertificateSubjectFormat -f $InputObject
            }
          }
        }

        Certificate { $Certificate.Subject }
        Thumbprint  { Find-UiucCertificate -Thumbprint $Thumbprint -Scope $Scope | % { $_.Subject; $_.Dispose() } }
        DnsName     { $CertificateSubjectFormat -f $DnsName }
      }
    }

    $values | % {
      $tmpINF = New-TemporaryFile
      $tmpCSR = New-TemporaryFile

      Write-Verbose "Temporary INF File: $($tmpINF.FullName)"
      Write-Verbose "Temporary CSR File: $($tmpCSR.FullName)"

      Try {
        If ($Renew) {
          $csrDomain = $_.DnsNameList[0].Unicode
          $csrPrefix = '{0}-{1}' -f $csrDomain, $_.Thumbprint
          $csrPolicy = @"
[NewRequest]
Subject = "$($_.Subject)"
RenewalCert = "$($_.Thumbprint)"
UseExistingKeySet = true
HashAlgorithm = $HashAlgorithm
MachineKeySet = $machineKeySet
SMIME = false
Silent = true
"@
        } Else {
          $csrDomain = Select-String -InputObject $_ -Pattern $CertificateSubjectCNPattern | % { $_.Matches.Groups[1].Value }
          $csrPrefix = $csrDomain
          $csrPolicy = @"
[NewRequest]
Subject = "$_"
Exportable = true
ExportableEncrypted = false
HashAlgorithm = $HashAlgorithm
KeyAlgorithm = RSA
KeyLength = $KeyLength
MachineKeySet = $machineKeySet
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
SMIME = false
Silent = true
"@
        }
        $csrPolicy | Set-Content -LiteralPath $tmpINF.FullName
        Write-Debug "CertReq Policy: $csrPolicy"

        $output = certreq -New -f -q $tmpINF.FullName $tmpCSR.FullName
        Write-Debug "CertReq -New output: $output"
        If ($LastExitCode -ne 0) {
          Write-Error "CertReq -New failed for $($_): $LastExitCode"
          Return
        }

        Write-Output ([ordered]@{
          DnsName = $csrDomain
          Subject = If ($_ -is [string]) { $_ } Else { $_.Subject }
          CertificateSigningRequest = ((Get-Content -LiteralPath $tmpCSR.FullName) -join "`n")
        })

        If ($Path) {
          Copy-Item -LiteralPath $tmpCSR.FullName (Join-Path $Path "$csrPrefix-csr.pem")
        }
      } Finally {
        $tmpINF.Delete()
        $tmpCSR.Delete()

        If ($_ -is [IDisposable]) {
          $_.Dispose()
        }
      }
    }
  }
}


<#
.SYNOPSIS
Installs a signed UIUC certificate into the Windows certificate store that was
previously requested.

.INPUTS

System.String. Either the certificate data in PEM format or a filename with
the signed certificate.

.OUTPUTS

System.String. Thumbprint of the certificate.
#>
function Install-UiucCertificate {
  Param(
    [parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$InputObject
  )

  Process {
    $tmpCRT = New-TemporaryFile
    Write-Verbose "Temporary CRT File: $($tmpCRT.FullName)"

    Try {
      If ($InputObject -match '-----BEGIN CERTIFICATE-----') {
        # We were passed a certificate string, not a file path
        $InputObject | Set-Content -LiteralPath $tmpCRT.FullName -Encoding ASCII
      } Else {
        Copy-Item -LiteralPath $InputObject $tmpCRT.FullName
      }

      If ((Select-String -Pattern '-----BEGIN CERTIFICATE-----' -LiteralPath $tmpCRT.FullName -AllMatches).Matches.Count -le 1) {
        # Append the intermediary certificates to the cert
        @'

-----BEGIN CERTIFICATE-----
MIIF+TCCA+GgAwIBAgIQRyDQ+oVGGn4XoWQCkYRjdDANBgkqhkiG9w0BAQwFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQx
MDA2MDAwMDAwWhcNMjQxMDA1MjM1OTU5WjB2MQswCQYDVQQGEwJVUzELMAkGA1UE
CBMCTUkxEjAQBgNVBAcTCUFubiBBcmJvcjESMBAGA1UEChMJSW50ZXJuZXQyMREw
DwYDVQQLEwhJbkNvbW1vbjEfMB0GA1UEAxMWSW5Db21tb24gUlNBIFNlcnZlciBD
QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJwb8bsvf2MYFVFRVA+e
xU5NEFj6MJsXKZDmMwysE1N8VJG06thum4ltuzM+j9INpun5uukNDBqeso7JcC7v
HgV9lestjaKpTbOc5/MZNrun8XzmCB5hJ0R6lvSoNNviQsil2zfVtefkQnI/tBPP
iwckRR6MkYNGuQmm/BijBgLsNI0yZpUn6uGX6Ns1oytW61fo8BBZ321wDGZq0GTl
qKOYMa0dYtX6kuOaQ80tNfvZnjNbRX3EhigsZhLI2w8ZMA0/6fDqSl5AB8f2IHpT
eIFken5FahZv9JNYyWL7KSd9oX8hzudPR9aKVuDjZvjs3YncJowZaDuNi+L7RyML
fzcCAwEAAaOCAW4wggFqMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bL
MB0GA1UdDgQWBBQeBaN3j2yW4luHS6a0hqxxAAznODAOBgNVHQ8BAf8EBAMCAYYw
EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH
AwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAECAjBQBgNVHR8ESTBHMEWgQ6BB
hj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlmaWNh
dGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEEajBoMD8GCCsGAQUFBzAChjNo
dHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQWRkVHJ1c3RDQS5j
cnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZI
hvcNAQEMBQADggIBAC0RBjjW29dYaK+qOGcXjeIT16MUJNkGE+vrkS/fT2ctyNMU
11ZlUp5uH5gIjppIG8GLWZqjV5vbhvhZQPwZsHURKsISNrqOcooGTie3jVgU0W+0
+Wj8mN2knCVANt69F2YrA394gbGAdJ5fOrQmL2pIhDY0jqco74fzYefbZ/VS29fR
5jBxu4uj1P+5ZImem4Gbj1e4ZEzVBhmO55GFfBjRidj26h1oFBHZ7heDH1Bjzw72
hipu47Gkyfr2NEx3KoCGMLCj3Btx7ASn5Ji8FoU+hCazwOU1VX55mKPU1I2250Lo
RCASN18JyfsD5PVldJbtyrmz9gn/TKbRXTr80U2q5JhyvjhLf4lOJo/UzL5WCXED
Smyj4jWG3R7Z8TED9xNNCxGBMXnMete+3PvzdhssvbORDwBZByogQ9xL2LUZFI/i
eoQp0UM/L8zfP527vWjEzuDN5xwxMnhi+vCToh7J159o5ah29mP+aJnvujbXEnGa
nrNxHzu+AGOePV8hwrGGG7hOIcPDQwkuYwzN/xT29iLp/cqf9ZhEtkGcQcIImH3b
oJ8ifsCnSbu0GB9L06Yqh7lcyvKDTEADslIaeSEINxhO2Y1fmcYFX/Fqrrp1WnhH
OjplXuXE0OPa0utaKC25Aplgom88L2Z8mEWcyfoB7zKOfD759AN7JKZWCYwk
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFdzCCBF+gAwIBAgIQE+oocFv07O0MNmMJgGFDNjANBgkqhkiG9w0BAQwFADBv
MQswCQYDVQQGEwJTRTEUMBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFk
ZFRydXN0IEV4dGVybmFsIFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBF
eHRlcm5hbCBDQSBSb290MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFow
gYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtK
ZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYD
VQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgBJlFzYOw9sIs9CsVw127c0n00yt
UINh4qogTQktZAnczomfzD2p7PbPwdzx07HWezcoEStH2jnGvDoZtF+mvX2do2NC
tnbyqTsrkfjib9DsFiCQCT7i6HTJGLSR1GJk23+jBvGIGGqQIjy8/hPwhxR79uQf
jtTkUcYRZ0YIUcuGFFQ/vDP+fmyc/xadGL1RjjWmp2bIcmfbIWax1Jt4A8BQOujM
8Ny8nkz+rwWWNR9XWrf/zvk9tyy29lTdyOcSOk2uTIq3XJq0tyA9yn8iNK5+O2hm
AUTnAU5GU5szYPeUvlM3kHND8zLDU+/bqv50TmnHa4xgk97Exwzf4TKuzJM7UXiV
Z4vuPVb+DNBpDxsP8yUmazNt925H+nND5X4OpWaxKXwyhGNVicQNwZNUMBkTrNN9
N6frXTpsNVzbQdcS2qlJC9/YgIoJk2KOtWbPJYjNhLixP6Q5D9kCnusSTJV882sF
qV4Wg8y4Z+LoE53MW4LTTLPtW//e5XOsIzstAL81VXQJSdhJWBp/kjbmUZIO8yZ9
HE0XvMnsQybQv0FfQKlERPSZ51eHnlAfV1SoPv10Yy+xUGUJ5lhCLkMaTLTwJUdZ
+gQek9QmRkpQgbLevni3/GcV4clXhB4PY9bpYrrWX1Uu6lzGKAgEJTm4Diup8kyX
HAc/DVL17e8vgg8CAwEAAaOB9DCB8TAfBgNVHSMEGDAWgBStvZh6NLQm9/rEJlTv
A73gJMtUGjAdBgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/
BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAGBgRVHSAAMEQGA1Ud
HwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9BZGRUcnVzdEV4
dGVybmFsQ0FSb290LmNybDA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0
dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggEBAJNl9jeD
lQ9ew4IcH9Z35zyKwKoJ8OkLJvHgwmp1ocd5yblSYMgpEg7wrQPWCcR23+WmgZWn
RtqCV6mVksW2jwMibDN3wXsyF24HzloUQToFJBv2FAY7qCUkDrvMKnXduXBBP3zQ
YzYhBx9G/2CkkeFnvN4ffhkUyWNnkepnB2u0j4vAbkN9w6GAbLIevFOFfdyQoaS8
Le9Gclc1Bb+7RrtubTeZtv8jkpHGbkD4jylW6l/VXxRTrPBPYer3IsynVgviuDQf
Jtl7GQVoP7o81DgGotPmjw7jtHFtQELFhLRAlSv0ZaBIefYdgWOWnU914Ph85I6p
0fKtirOMxyHNwu8=
-----END CERTIFICATE-----

'@ | Add-Content -LiteralPath $tmpCRT.FullName
      }
      Get-Content -LiteralPath $tmpCRT.FullName | Write-Debug

      $output = certreq -Accept $tmpCRT.FullName
      Write-Debug "CertReq -Accept output: $output"
      If ($LastExitCode -ne 0) {
        Throw "CertReq -Accept failed: $LastExitCode"
      }

      $thumbprint = $output | Select-String -Pattern 'Thumbprint:\s+([a-f0-9]+)' | select -First 1 | % { $_.Matches.Groups[1].Value }
      If (-not $thumbprint) {
        Throw "CertReq -Accept did not provide a certificate thumbprint"
      }

      Write-Output $thumbprint
    } Finally {
      $tmpCRT.Delete()
    }
  }
}


<#
.SYNOPSIS
Export a signed certificate from the Windows certificate store.

.DESCRIPTION


.INPUTS

object. This can be either an X509Certificate object, a string
thumbprint, or a DNS domain.

.PARAMETER Certificate

X509Certificate object to export.

.PARAMETER Thumbprint

SHA1 hash of a certificate to export.

.PARAMETER DnsName

Primary DNS domain name for the certificate to export. Using this
parameter might generate multiple exports.

.PARAMETER SecurePassword

Password used to encrypt the intermediary PFX file exported. Not all
of the files exported will be protected with this password; some are
left unencrypted.

.PARAMETER Path

Path to save certificate file formats. Each format will be prefixed
with the DNS domain name and thumbprint for that certificate. If this is
not specified then the files are not saved.

.PARAMETER Scope

Where the certificate is stored: CurrentUser, LocalMachine, or
WebHosting. If LocalMachine or WebHosting then the user must be the
Adminsitrator.

.OUTPUTS

@{Thumbprint; DnsName; PrivateKey, Certificate}.
Information about each certificate created. The values are strings in
PEM format.
#>
function Export-UiucCertificate {
  Param(
    [parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true, ParameterSetName="InputObject")]
    [ValidateNotNullOrEmpty()]
    [object]$InputObject,

    [parameter(Mandatory=$true, ParameterSetName="Certificate")]
    [ValidateNotNullOrEmpty()]
    [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,

    [parameter(Mandatory=$true, ParameterSetName="DnsName")]
    [ValidateNotNullOrEmpty()]
    [string]$DnsName,

    [parameter(Mandatory=$true, ParameterSetName="Thumbprint")]
    [ValidateNotNullOrEmpty()]
    [string]$Thumbprint,

    [parameter(Position=1, Mandatory=$true)]
    [alias("Password")]
    [SecureString]$SecurePassword,

    [string]$Path = $null,

    [parameter(ParameterSetName="InputObject")]
    [parameter(ParameterSetName="DnsName")]
    [parameter(ParameterSetName="Thumbprint")]
    [UiucCertificateScope]$Scope = [UiucCertificateScope]::CurrentUser
  )

  Begin {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
  }

  Process {
    $certs = Switch ($PSCmdlet.ParameterSetName) {
      InputObject   { Find-UiucCertificate -InputObject $InputObject -Scope $Scope }
      Certificate   { Find-UiucCertificate -Certificate $Certificate }
      DnsName       { Find-UiucCertificate -DnsName $DnsName -Scope $Scope }
      Thumbprint    { Find-UiucCertificate -Thumbprint $Thumbprint -Scope $Scope }
    }

    $certs | % {
      Write-Debug "Exporting certificate $_"

      $tmpPFX = New-TemporaryFile
      Write-Verbose "Temporary PFX File: $($tmpPFX.FullName)"

      Try {
        Export-PfxCertificate -Cert $_ -FilePath $tmpPFX.FullName -Password $SecurePassword | Write-Debug

        $cert = New-Object Chilkat.Cert
        $cert.LoadPfxFile($tmpPFX.FullName, $PlainPassword)
        $privKey = $cert.ExportPrivateKey()
        If ($privKey -eq $null) {
          Write-Error "Unable to export private key for $_ (error = $($cert.LastErrorText))"
          return
        }

        Write-Output ([ordered]@{
          Thumbprint = $cert.Sha1Thumbprint
          DnsName = $cert.SubjectCN
          PrivateKey = $privKey.GetRsaPem()
          Certificate = $cert.ExportCertPem()
        })

        If ($Path) {
          $prefix = '{0}-{1}' -f $cert.SubjectCN, $cert.Sha1Thumbprint

          Copy-Item -LiteralPath $tmpPFX.FullName (Join-Path $Path "$prefix.pfx")
          $privKey.GetRsaPem() | Set-Content -LiteralPath (Join-Path $Path "$prefix-key.pem") -Encoding ASCII
          $privKey.GetRsaDer() | Set-Content -LiteralPath (Join-Path $Path "$prefix-key.der") -Encoding Byte
          $cert.ExportCertPem() | Set-Content -LiteralPath (Join-Path $Path "$prefix-crt.pem") -Encoding ASCII
          $cert.ExportCertDer() | Set-Content -LiteralPath (Join-Path $Path "$prefix-crt.der") -Encoding Byte
        }
      } Finally {
        $tmpPFX.Delete()
        $_.Dispose()
      }
    }
  }
}
