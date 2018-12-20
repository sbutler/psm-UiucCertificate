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
Create a new private key and certificate signing request (CSR) formatted for UIUC
signing.

.DESCRIPTION


.INPUTS

System.String. Domain name to use as the common name in the CSR.

.OUTPUTS

@{Domain; CertificateSigningRequest; PrivateKey}. Information about each certificate
created. The values are strings in PEM format.
#>
Function New-UiucCertificate {
  Param(
    [parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true,
      HelpMessage='Primary domain name for the certificate, included in the CSR.')]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [parameter(Position=1, Mandatory=$true,
      HelpMessage='Password used to encrypt the intermediary PFX file exported.')]
    [SecureString]$SecurePassword,

    [parameter(HelpMessage='Path to save certificate file formats.')]
    [string]$Path = $null,

    [parameter(HelpMessage='Hashing algorithm used for the CSR.')]
    [alias("Hash")]
    [ValidateSet("sha256", "sha384", "sha512")]
    [string]$HashAlgorithm = "sha256",

    [parameter(HelpMessage='Length of the private key.')]
    [alias("Bits")]
    [ValidateScript({ $_ -ge 2048 })]
    [int]$KeyLength = 2048,

    [parameter(HelpMessage='Store the key in the LocalMachine store instead of CurrentUser (only used when Keep is true).')]
    [switch]$MachineKeySet = $false,

    [parameter(HelpMessage='Keep the certificate in the Windows certificate stores instead of deleting after finished.')]
    [switch]$Keep = $false
  )

  Begin {
    $CertBase = If ($Keep -and $MachineKeySet) { "Cert:\LocalMachine\My" } Else { "Cert:\CurrentUser\My" }

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
  }

  Process {
    $tmpINF = New-TemporaryFile
    $tmpCSR = New-TemporaryFile
    $tmpPFX = New-TemporaryFile

    Write-Verbose "Temporary INF File: $($tmpINF.FullName)"
    Write-Verbose "Temporary CSR File: $($tmpCSR.FullName)"
    Write-Verbose "Temporary PFX File: $($tmpPFX.FullName)"

    Try {
      @"
[NewRequest]
Subject = "CN=$Domain, OU=Urbana-Champaign Campus, O=University of Illinois, L=Urbana, S=Illinois, C=US"
Exportable = true
ExportableEncrypted = false
HashAlgorithm = $HashAlgorithm
KeyAlgorithm = RSA
KeyLength = $KeyLength
MachineKeySet = $($Keep -and $MachineKeySet)
RequestType = cert
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
SMIME = false
"@ | Set-Content -LiteralPath $tmpINF.FullName
      Get-Content -LiteralPath $tmpINF.FullName | Write-Debug

      $output = certreq -New -f $tmpINF.FullName $tmpCSR.FullName
      Write-Debug "certreq output: $output"
      If ($LastExitCode -ne 0) {
        Throw "CertReq failed: $LastExitCode"
      }

      $thumbprint = $output | Select-String -Pattern 'Thumbprint:\s+([a-f0-9]+)' | select -First 1 | % { $_.Matches.Groups[1].Value }
      If (-not $thumbprint) {
        Throw "CertReq did not provide a certificate thumbprint"
      }
      Write-Debug "Thumbprint: $thumbprint"

      Export-PfxCertificate -Cert (Join-Path $CertBase $thumbprint) -FilePath $tmpPFX.FullName -Password $SecurePassword | Out-Null

      $cert = New-Object Chilkat.Cert
      $cert.LoadPfxFile($tmpPFX.FullName, $PlainPassword)
      $privKey = $cert.ExportPrivateKey()
      If ($privKey -eq $null) {
        Throw "Unable to export private key for $thumbprint (error = $($cert.LastErrorText))"
      }

      $result = [ordered]@{
        Domain = $Domain
        PrivateKey = $privKey.GetRsaPem()
        CertificateSigningRequest = ((Get-Content $tmpCSR.FullName) -join "`n")
      }
      Write-Output $result

      If ($Path) {
        Copy-Item -LiteralPath $tmpCSR.FullName (Join-Path $Path "$Domain-csr.pem")
        Copy-Item -LiteralPath $tmpPFX.FullName (Join-Path $Path "$Domain.pfx")
        $privKey.GetRsaPem() | Set-Content -LiteralPath (Join-Path $Path "$Domain-key.pem") -Encoding ASCII
        $privKey.GetRsaDer() | Set-Content -LiteralPath (Join-Path $Path "$Domain-key.der") -Encoding Byte
      }
    } Finally {
      $tmpINF.Delete()
      $tmpCSR.Delete()
      $tmpPFX.Delete()

      If (-not $Keep -and $thumbprint) {
        Remove-Item -LiteralPath (Join-Path $CertBase $thumbprint)
      }
    }
  }
}
