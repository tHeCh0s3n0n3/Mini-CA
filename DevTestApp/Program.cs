using Org.BouncyCastle.Pkcs;
using System.Text;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;

try {
    string csrPem = @"-----BEGIN CERTIFICATE REQUEST-----
MIIDADCCAegCAQAwezELMAkGA1UEBhMCQUUxDjAMBgNVBAcMBUR1YmFpMSQwIgYD
VQQKDBtXZWJtaW4gV2Vic2VydmVyIG9uIE1lbnBoaXMxEzARBgNVBAMMCjEwLjEw
LjAuMTAxITAfBgkqhkiG9w0BCQEWEmRldkB0YXJla2ZhZGVsLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALg6EC3b4yHnqvsjWdCsRDSSxbbh39y6
A4C0avKE6jS1B8uj+e5SFxydjOIeMFTyKX/nq92xb2I/oAUWr5cVwt7Co18D88H9
07zLn/YqhhEbTihoBjcMPu8nLywp1gRA2vM8RGHbYL6Nl74atoc2rKzHBa+hTeOu
KxRy6LBZnZeY3dPLCYfjZeFKU66cW3w+Tk/lMjXsrWEK6z/RSljOzddoZp+hdebq
VaalO8hB39G5xwS+tQqH/9fliiIH0CZXtnhTZxxVGDU3Xk0SkkqifH9geHYkqD0z
eRszvWZBIhLSqxfxEdAI6RBR2KG19QPyAByWabten8BNqXsARFY0yksCAwEAAaBA
MD4GCSqGSIb3DQEJDjExMC8wFQYDVR0RBA4wDIIKMTAuMTAuMC4xMDAJBgNVHRME
AjAAMAsGA1UdDwQEAwIF4DANBgkqhkiG9w0BAQsFAAOCAQEAKjPRaQvzyxooOr/o
Peq/ZS9MMtiupseoy7hoWwh+1UH1+cdoUnGz5kwXKhz3TNOfSS5ytTYp33QuwM5Z
8rhz/5cW2wBXVYQYHAfyNieJeqqHSNb7LHBDiHLZzgNWbqE7T0SctkEZn1cR0M3m
vQvRNJ1vnq4G3MRZ8sHc3F4E9ouWux+iLDEOjrZ2rZpvaq5rKaQgTuO13sSjXDk/
rkfp+XzRJcEuy00prwVeCAKW+WBl3/KbQ1LgRbNWyRsyO8EBUJMsfr/toFIkefxS
HXhkgfU6Z18B4oLG3RK7qryv2ZiRaSbCCyTMimxrSvy5HRYyWb03aaaBM7XQBT9C
/sqn5Q==
-----END CERTIFICATE REQUEST-----";
    byte[] csrBytes = Encoding.UTF8.GetBytes(csrPem);
    Pkcs10CertificationRequest csr = Common.Certificate.ImportCSR(csrBytes);
    Console.WriteLine("CSR Import successful.");

    string caCertPath = "rootca.crt";
    string caKeyPath = "rootca.key";
    
    X509Certificate caCert = Common.Certificate.ImportCACert(caCertPath);
    Console.WriteLine("CA Cert Import successful.");

    AsymmetricCipherKeyPair caKey = Common.Certificate.ImportCAKey(caKeyPath, null);
    Console.WriteLine("CA Key Import successful.");

    var keyUsages = new List<int> { 
        Org.BouncyCastle.Asn1.X509.KeyUsage.DigitalSignature, 
        Org.BouncyCastle.Asn1.X509.KeyUsage.KeyEncipherment 
    };
    var keyPurposes = new List<Org.BouncyCastle.Asn1.X509.KeyPurposeID> { 
        Org.BouncyCastle.Asn1.X509.KeyPurposeID.IdKPServerAuth 
    };

    X509Certificate signedCert = Common.Certificate.SignCSR(csr, caCert, caKey, 1, keyUsages, keyPurposes);
    Console.WriteLine("CSR Signing successful!");
    Console.WriteLine(Common.Certificate.CertToFile(signedCert));

} catch (Exception ex) {
    Console.WriteLine("Error: " + ex.ToString());
}
