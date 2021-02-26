function New-Certificate {
    [CmdletBinding()]
    param (
        #FQDN of the certificate.
        [string]
        $CommonName,

        [string[]]
        $SubjectAltName,

        #FQDN of CA server
        [string]
        $CAServer,

        #User credentials
        [pscredential]
        $Credential,

        #Password for the PFX file
        [string]
        $PFXPass,

        [string]
        $CertificateTemplate,

        [string]
        $Organization,

        [string]
        $Department,

        [string]
        $CountryCode,

        [string]
        $State,

        [string]
        $City

    )

    $ErrorActionPreference = 'Stop'

    $subject = '/C={0}/ST={1}/L={2}/O={3}/OU={4}/CN={5}' -f $CountryCode, $State, $City, $Organization, $Department, $CommonName

    if ($SubjectAltName) {

        $san = foreach ($s in $SubjectAltName) {
            "DNS:$s"
        }
        $san = ($san -join ',').Insert(0, ',')
    }

    $subject = '/C={0}/ST={1}/L={2}/O={3}/OU={4}/CN={5}' -f $CountryCode, $State, $City, $Organization, $Department, $CommonName

    openssl req -nodes -newkey rsa:2048 -keyout "$FQDN.key" -out "$FQDN.csr" -subj $subject -addext "subjectAltName=DNS:$CommonName$san"

    #put CSR in variable

    $csr = Get-Content "$FQDN.csr" -Raw

    #post CSR to CA

    $requestParams = @{
        Uri                  = "https://$CAServer/certsrv/certfnsh.asp"
        Method               = 'Post'
        ContentType          = 'application/x-www-form-urlencoded'
        Credential           = $Credential
        SkipCertificateCheck = $true
        Authentication       = 'Basic'
        Body                 = @{
            Mode             = 'newreq'
            Certrequest      = $csr
            CertAttrib       = "CertificateTemplate:$CertificateTemplate"
            FriendlyType     = 'Saved-Request Certificate'
            TargetStoreFlags = '0'
            SaveCert         = 'yes'
        }
    }

    $response = Invoke-WebRequest @requestParams

    #Search for request ID in the returned HTML
    $findReqId = $response.Content | Select-String -Pattern 'certnew.cer\?ReqID=(\d+)&'

    $reqId = $findReqId.Matches.Groups[1].Value

    #Download certificate and chain chain
    $responseParams = @{
        Uri                  = "https://$CAServer/certsrv/certnew.p7b?ReqID=$reqId&Enc=b64"
        Method               = 'Get'
        Credential           = $credential
        SkipCertificateCheck = $true
        Authentication       = 'Basic'
    }

    $response = Invoke-WebRequest @responseParams

    #Save response as file
    $response.Content | Set-Content "$FQDN.p7b" -AsByteStream

    #Convert p7b to format thats compatible with PFX
    openssl pkcs7 -print_certs -in "$FQDN.p7b" -out "$FQDN.cer"

    #Export certificates and key to pfx
    openssl pkcs12 -export -in "$FQDN.cer" -inkey "$FQDN.key" -out "$FQDN.pfx" -password "pass:$PFXPass"

    #Cleanup
    Remove-Item "$FQDN.cer"
    Remove-Item "$FQDN.key"
    Remove-Item "$FQDN.p7b"
    Remove-Item "$FQDN.csr"

}
