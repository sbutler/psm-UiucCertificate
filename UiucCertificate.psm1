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

<#
.SYNOPSIS
Request a new private key and certificate signing request (CSR) formatted for
UIUC signing.

.DESCRIPTION


.INPUTS

System.String. Domain name to use as the common name in the CSR.

.PARAMETER Domain

Primary domain name for the certificate, included in the CSR as the Common
Name (CN).

.PARAMETER Path

Path to save the CSR file as "$Domain-csr.pem".If this is not specified
then the CSR is only available on the pipeline.

.PARAMETER HashAlgorithm

Hashing algorithm used for the CSR.

.PARAMETER KeyLength

Length of the private key in bits. This must be 2048 if you will submit
the CSR for signing.

.PARAMETER MachineKeySet

Store the key in the LocalMachine store instead of CurrentUser. Saving to
the MachineKeySet requires Administrator prileges.

.OUTPUTS

@{Domain; CertificateSigningRequest}.
Information about each certificate created. The values are strings in PEM
format.
#>
Function Request-UiucCertificate {
  Param(
    [parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [string]$Path = $null,

    [alias("Hash")]
    [ValidateSet("sha256", "sha384", "sha512")]
    [string]$HashAlgorithm = "sha256",

    [alias("Bits")]
    [ValidateScript({ $_ -ge 2048 })]
    [int]$KeyLength = 2048,

    [switch]$MachineKeySet = $false
  )

  Process {
    $tmpINF = New-TemporaryFile
    $tmpCSR = New-TemporaryFile

    Write-Verbose "Temporary INF File: $($tmpINF.FullName)"
    Write-Verbose "Temporary CSR File: $($tmpCSR.FullName)"

    Try {
      @"
[NewRequest]
Subject = "CN=$Domain, OU=Urbana-Champaign Campus, O=University of Illinois, L=Urbana, S=Illinois, C=US"
Exportable = true
ExportableEncrypted = false
HashAlgorithm = $HashAlgorithm
KeyAlgorithm = RSA
KeyLength = $KeyLength
MachineKeySet = $MachineKeySet
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
SMIME = false
"@ | Set-Content -LiteralPath $tmpINF.FullName
      Get-Content -LiteralPath $tmpINF.FullName | Write-Debug

      $output = certreq -New -f $tmpINF.FullName $tmpCSR.FullName
      Write-Debug "CertReq -New output: $output"
      If ($LastExitCode -ne 0) {
        Throw "CertReq -New failed: $LastExitCode"
      }

      Write-Output [ordered]@{
        Domain = $Domain
        CertificateSigningRequest = ((Get-Content -LiteralPath $tmpCSR.FullName) -join "`n")
      }

      If ($Path) {
        Copy-Item -LiteralPath $tmpCSR.FullName (Join-Path $Path "$Domain-csr.pem")
      }
    } Finally {
      $tmpINF.Delete()
      $tmpCSR.Delete()
    }
  }
}


<#
.SYNOPSIS
Installs a signed UIUC certificate into the Windows certificate store that was
previously requested.

.DESCRIPTION


.INPUTS

System.String. Either the certificate data in PEM format or a filename with
the signed certificate.

.OUTPUTS

System.String. Thumbprint of the certificate.
#>
function Install-UiucCertificate {
  Param(
    [parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true)]
    [alias("Cert")]
    [ValidateNotNullOrEmpty()]
    [string]$Certificate
  )

  Process {
    $tmpCRT = New-TemporaryFile
    Write-Verbose "Temporary CRT File: $($tmpCRT.FullName)"

    Try {
      If ($Certificate -match '-----BEGIN CERTIFICATE-----') {
        # We were passed a certificate string, not a file path
        $Certificate | Set-Content -LiteralPath $tmpCRT.FullName -Encoding ASCII
      } Else {
        Copy-Item -LiteralPath $Certificate $tmpCRT.FullName
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

System.String. Thumbprint of the certificate or domain name. If a domain name
matches multiple certificates in the store then they are all returned.

.PARAMETER Certificate

Thumbprint of the certificate or domain name. If a domain name matches multiple
certificates in the store then they are all returned.

.PARAMETER SecurePassword

Password used to encrypt the intermediary PFX file exported. Not all of the
files exported will be protected with this password; some are left unencrypted.

.PARAMETER Path

Path to save certificate file formats. Each format will be prefixed with the
domain name for that certificate. If this is not specified then the files are
not saved.

.PARAMETER MachineKeySet

Store the key in the LocalMachine store instead of CurrentUser. Saving to
the MachineKeySet requires Administrator prileges.

.OUTPUTS

@{Thumbprint; Domain; PrivateKey, Certificate}.
Information about each certificate created. The values are strings in PEM
format.
#>
function Export-UiucCertificate {
  Param(
    [parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true)]
    [alias("Cert", "Domain", "Thumbprint")]
    [ValidateNotNullOrEmpty()]
    [string]$Certificate,

    [parameter(Position=1, Mandatory=$true)]
    [alias("Password")]
    [SecureString]$SecurePassword,

    [string]$Path = $null,

    [switch]$MachineKeySet = $false
  )

  Begin {
    $CertBase = If ($MachineKeySet) { "Cert:\LocalMachine\My" } Else { "Cert:\CurrentUser\My" }

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
  }

  Process {
    If ($Certificate -match '^[a-f0-9]{40}$') {
      # We got a thumbprint. Add it directly to the list
      $certs = @((Join-Path $CertBase $Certificate))
    } Else {
      # We got a domain. Find all the children with this domain as the CN
      $certs = @(Get-ChildItem $CertBase | ? { $_.Subject -match "(^|[\s,])CN=$([Regex]::Escape($Certificate))(,|`$)" } | % { Join-Path $CertBase $_.Thumbprint })
    }

    $certs | % {
      Write-Debug "Exporting certificate $_"

      $tmpPFX = New-TemporaryFile
      Write-Verbose "Temporary PFX File: $($tmpPFX.FullName)"

      Try {
        Export-PfxCertificate -Cert $_ -FilePath $tmpPFX.FullName -Password $SecurePassword | Write-Debug

        $cert = New-Object Chilkat.Cert
        $cert.LoadPfxFile($tmpPFX.FullName, $PlainPassword)
        $certChain = $cert.GetCertChain()
        $privKey = $cert.ExportPrivateKey()
        If ($privKey -eq $null) {
          Write-Error "Unable to export private key for $_ (error = $($cert.LastErrorText))"
          return
        }

        Write-Output @{
          Thumbprint = $_
          Domain = $cert.SubjectCN
          PrivateKey = $privKey.GetRsaPem()
          Certificate = $cert.ExportCertPem()
        }

        If ($Path) {
          $prefix = $cert.SubjectCN
          If ($certs.Length -gt 1) {
            $prefix += "-$_"
          }

          Copy-Item -LiteralPath $tmpPFX.FullName (Join-Path $Path "$prefix.pfx")
          $privKey.GetRsaPem() | Set-Content -LiteralPath (Join-Path $Path "$prefix-key.pem") -Encoding ASCII
          $privKey.GetRsaDer() | Set-Content -LiteralPath (Join-Path $Path "$prefix-key.der") -Encoding Byte
          $cert.ExportCertPem() | Set-Content -LiteralPath (Join-Path $Path "$prefix-crt.pem") -Encoding ASCII
          $cert.ExportCertDer() | Set-Content -LiteralPath (Join-Path $Path "$prefix-crt.der") -Encoding Byte
        }
      } Finally {
        $tmpPFX.Delete()
      }
    }
  }
}
