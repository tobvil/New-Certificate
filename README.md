# New-Certificate

Create certificate with Powershell and OpenSSL from Windows Certificate Authority, using the CA Web Enrollment endpoint Certsrv.

Requires PowerShell and OpenSSL.

Cetsrv must have https enabled in IIS.

Basic authentication must be activated on the Certsrv site in IIS.

The certificate must be based on a certificate template.

The user account authenticating must have Read and Enroll permissions for the certificate template.
