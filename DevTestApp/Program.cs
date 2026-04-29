using Org.BouncyCastle.Pkcs;
using System.Text;

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
    Console.WriteLine("Import successful.");
    var sans = Common.Certificate.GetSANs(csr);
    Console.WriteLine("SANs found: " + string.Join(", ", sans));
} catch (Exception ex) {
    Console.WriteLine("Error: " + ex.ToString());
}
