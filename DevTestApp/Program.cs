// See https://aka.ms/new-console-template for more information

string csrPath = @"C:\Users\Tarek\Nextcloud\Development\Mini CA\Data\menphis2.csr";
string caPath = @"C:\Users\Tarek\Nextcloud\Development\Mini CA\Data\ca.crt";
string caKeyPath = @"C:\Users\Tarek\Nextcloud\Development\Mini CA\Data\ca.key";
string caKeyPasswordPath = @"C:\Users\Tarek\Nextcloud\Development\Mini CA\Data\ca.key.passwd";
string newCertPath = @"C:\Users\Tarek\Nextcloud\Development\Mini CA\Data\newCert.crt";

List<int> keyUsages = new()
{
    Org.BouncyCastle.Asn1.X509.KeyUsage.DigitalSignature
    , Org.BouncyCastle.Asn1.X509.KeyUsage.KeyEncipherment
};

List<Org.BouncyCastle.Asn1.X509.KeyPurposeID> keyPurposeIDs = new()
{
    Org.BouncyCastle.Asn1.X509.KeyPurposeID.IdKPServerAuth
};

// Read the CSR
Console.WriteLine("Reading the CSR...");
var csr = Common.Certificate.ImportCSR(csrPath);

var sans = Common.Certificate.GetSANs(csr);
foreach(var san in sans)
{
    Console.WriteLine(san);
}

// Grab the CA cert and its key
Console.WriteLine("Reading the CA cert and its key...");
var caCert = Common.Certificate.ImportCACert(caPath);
var caKey = Common.Certificate.ImportCAKey(caKeyPath, caKeyPasswordPath);

// Sign the cert
Console.WriteLine("Signing the CSR...");
var signedCert = Common.Certificate.SignCSR(csr, caCert, caKey, 1, keyUsages, keyPurposeIDs);
var newCertFileContents = Common.Certificate.CertToFile(signedCert);

// Save signed cert
Console.WriteLine("Writing the new cert...");
SaveSignedCert(newCertFileContents, newCertPath);

Console.WriteLine("DONE!");

static void SaveSignedCert(string newCertFileContents, string newCertPath)
{
    File.WriteAllText(newCertPath, newCertFileContents);
}