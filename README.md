## Install

This module requires .Net 4.6 support and PowerShell 5.0 currently.

If you do not already have NuGet installed as a package manager then you will
need to set it up. For example, to install NuGet for the current user:

```powershell
Install-PackageProvider NuGet -Scope CurrentUser
Register-PackageSource nugetRepository -ProviderName NuGet -Location 'http://www.nuget.org/api/v2'
```

Once NuGet is installed and setup, you can use it to install the Chilkat
package.

```powershell
Install-Package chilkat-x64 -Scope CurrentUser
```

## Using

To get the cmdlets you need to import the module:

```powershell
ImportModule c:\path\to\UiucCertificate.psd1
```

This will add these cmdlets: `Request-UiucCertificate`, `Install-UiucCertificate`,
and `Export-UiucCertificate`. You can use `Get-Help` to learn more about these
commands.

```powershell
# Creates an example.illinois.edu-csr.pem file in the current directory.
Request-UiucCertificate example.illinois.edu -Path .\

# Submit to https://go.illinois.edu/sslrequest and wait for the returned
# certificate. Store it in cert.pem. then run:
Install-UiucCertificate .\cert.pem | Export-UiucCertificate -Path .\

# You should now have these files in the current directory:
# example.illinois.edu.pfx: Full private key, certificate, and chain in PKCS12
#   format encrypted with the password.
# example.illinois.edu-key.pem: RSA private key, unencrypted.
# example.illinois.edu-key.der: RSA private key, unencrypted.
# example.illinois.edu-crt.pem: x509 issued certificate.
# example.illinois.edu-crt.der: x509 issued certificate.
```
