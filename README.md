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
ImportModule c:\path\to\UIUCCertificate.psd1
```

This will add the `New-UIUCCertificate` cmdlet. You can use `Get-Help` for more
information on the parameters.
