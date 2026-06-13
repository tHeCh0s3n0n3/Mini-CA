using System.IO;
using System;
using System.Text;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Operators;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Common;
public static class Certificate
{
    public static Pkcs10CertificationRequest ImportCSR(string csrPath)
    {
        if (string.IsNullOrWhiteSpace(csrPath))
        {
            throw new ArgumentException($"'{nameof(csrPath)}' cannot be null or whitespace.", nameof(csrPath));
        }

        return ImportCSR(File.ReadAllBytes(csrPath));        
    }

    public static Pkcs10CertificationRequest ImportCSR(byte[] fileContents)
    {
        ArgumentNullException.ThrowIfNull(fileContents);

        using MemoryStream ms = new(fileContents);
        using StreamReader sr = new(ms);
        PemReader csrReader = new(sr);

        if (csrReader.ReadObject()
            is not Pkcs10CertificationRequest csr)
        {
            throw new ArgumentException("Not a CSR file", nameof(fileContents));
        }

        if (!csr.Verify())
        {
            throw new Exception("CSR is not valid.");
        }

        return csr;
    }

    public static X509Certificate ImportCACert(string caPath)
    {
        if (string.IsNullOrEmpty(caPath))
        {
            throw new ArgumentException($"'{nameof(caPath)}' cannot be null or empty.", nameof(caPath));
        }

        return ImportCACert(File.ReadAllBytes(caPath));
    }

    public static X509Certificate ImportCACert(byte[] caCertContents)
    {
        ArgumentNullException.ThrowIfNull(caCertContents);

        using MemoryStream ms = new(caCertContents);
        using StreamReader caSR = new(ms);
        PemReader caReader = new(caSR);

        if (caReader.ReadObject()
            is not X509Certificate caObj)
        {
            Console.WriteLine("Not a certificate file.");
            throw new ArgumentException("Not a certificate file", nameof(caCertContents));
        }
        return caObj;
    }

    public static AsymmetricCipherKeyPair ImportCAKey(string caKeyPath, string? caKeyPasswordPath)
    {
        if (string.IsNullOrEmpty(caKeyPath))
        {
            throw new ArgumentException($"'{nameof(caKeyPath)}' cannot be null or empty.", nameof(caKeyPath));
        }

        return ImportCAKey(File.ReadAllBytes(caKeyPath), caKeyPasswordPath);
    }

    public static AsymmetricCipherKeyPair ImportCAKey(byte[] caKeyContents, string? caKeyPasswordPath)
    {
        ArgumentNullException.ThrowIfNull(caKeyContents);
        string keyHead = Encoding.UTF8.GetString(caKeyContents.Take(Math.Min(caKeyContents.Length, 100)).ToArray());
        bool isEncrypted = keyHead.Contains("ENCRYPTED");
        Console.WriteLine($"Importing CA Key. Encrypted: {isEncrypted}. Header: {keyHead.Replace("\n", " ").Replace("\r", " ")}");

        char[]? password = null;
        if (!string.IsNullOrEmpty(caKeyPasswordPath))
        {
            string absolutePath = Path.GetFullPath(caKeyPasswordPath);
            bool fileExists = File.Exists(absolutePath);
            Console.WriteLine($"Checking for password file at: {absolutePath} (Exists: {fileExists})");
            
            if (fileExists)
            {
                string passText = File.ReadAllText(absolutePath, Encoding.UTF8).Trim();
                password = passText.ToCharArray();
                Console.WriteLine($"Password file loaded. Trimmed length: {passText.Length}");
            }
        }

        if (isEncrypted && password == null)
        {
            Console.WriteLine("CRITICAL: CA key is encrypted but no valid password file was found.");
        }

        // Stage 1: Try with the password (if we found a finder path)
        if (password != null)
        {
            try
            {
                using MemoryStream ms = new(caKeyContents);
                using StreamReader caKeySR = new(ms);
                PemReader caKeyReader = new(caKeySR, new StaticPasswordFinder(password));
                var keyObject = caKeyReader.ReadObject();
                Console.WriteLine($"Stage 1 ReadObject returned: {keyObject?.GetType().Name ?? "null"}");
                var result = WrapKeyObject(keyObject);
                if (result != null) return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Stage 1 (Real Password) failed: {ex.Message}");
            }
        }

        // Stage 2: Try with a Null Password Finder (Empty array)
        try
        {
            using MemoryStream ms = new(caKeyContents);
            using StreamReader caKeySR = new(ms);
            PemReader caKeyReader = new(caKeySR, new NullPasswordFinder());
            var keyObject = caKeyReader.ReadObject();
            Console.WriteLine($"Stage 2 ReadObject returned: {keyObject?.GetType().Name ?? "null"}");
            var result = WrapKeyObject(keyObject);
            if (result != null) return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Stage 2 (Null Finder) failed: {ex.Message}");
        }

        // Stage 3: Final fallback - plain reader
        try
        {
            using MemoryStream ms = new(caKeyContents);
            using StreamReader caKeySR = new(ms);
            PemReader caKeyReader = new(caKeySR);
            var keyObject = caKeyReader.ReadObject();
            Console.WriteLine($"Stage 3 ReadObject returned: {keyObject?.GetType().Name ?? "null"}");
            var result = WrapKeyObject(keyObject);
            if (result != null) return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Stage 3 (Plain Reader) failed: {ex.Message}");
        }

        throw new ArgumentException("Unable to parse CA private key. Ensure the format is supported and the password (if any) is correct.", nameof(caKeyContents));
    }

    private static AsymmetricCipherKeyPair? WrapKeyObject(object? keyObject)
    {
        if (keyObject is AsymmetricCipherKeyPair pair) return pair;
        if (keyObject is AsymmetricKeyParameter privateKey && privateKey.IsPrivate) 
        {
            if (privateKey is Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters rsaPrivate)
            {
                var rsaPublic = new Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters(false, rsaPrivate.Modulus, rsaPrivate.PublicExponent);
                return new AsymmetricCipherKeyPair(rsaPublic, rsaPrivate);
            }
            // For other key types, we might need a different derivation, but RSA is the primary target
            return new AsymmetricCipherKeyPair(null!, privateKey);
        }
        return null;
    }

    private class StaticPasswordFinder(char[] password) : IPasswordFinder
    {
        public char[] GetPassword() => password;
    }

    private class NullPasswordFinder : IPasswordFinder
    {
        public char[] GetPassword() => Array.Empty<char>();
    }

    public static X509Certificate SignCSR(Pkcs10CertificationRequest csr
                                          , X509Certificate caCert
                                          , AsymmetricCipherKeyPair caKey
                                          , int validityYears
                                          , IEnumerable<int> keyUsages
                                          , IEnumerable<KeyPurposeID> keyPurposes
                                          , IEnumerable<(int TagNo, string Name)>? sanList = null)
    {
        ArgumentNullException.ThrowIfNull(csr);
        ArgumentNullException.ThrowIfNull(caCert);
        ArgumentNullException.ThrowIfNull(caKey);
        
        if (!csr.Verify())
        {
            throw new Exception("CSR is invalid.");
        }

        // Generating Random Numbers
        CryptoApiRandomGenerator randomGenerator = new();
        SecureRandom random = new(randomGenerator);

        X509V3CertificateGenerator certGen = new();

        Asn1Set attributes = csr.GetCertificationRequestInfo().Attributes;
        // Collect extensions from CSR
        var requestedExtensions = new Dictionary<DerObjectIdentifier, X509Extension>();
        if (attributes != null)
        {
            for (int i = 0; i != attributes.Count; i++)
            {
                AttributePkcs attr = AttributePkcs.GetInstance(attributes[i]);
                if (attr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                {
                    X509Extensions extensions = X509Extensions.GetInstance(attr.AttrValues[0]);
                    foreach (DerObjectIdentifier oid in extensions.ExtensionOids)
                    {
                        requestedExtensions[oid] = extensions.GetExtension(oid);
                    }
                }
            }
        }

        // Add extensions, prioritizing requested ones but overriding with CA requirements
        // 1. Copy from CSR (excluding ones we will override)
        var overridenExtensions = new HashSet<DerObjectIdentifier> {
            X509Extensions.BasicConstraints,
            X509Extensions.KeyUsage,
            X509Extensions.ExtendedKeyUsage,
            X509Extensions.AuthorityKeyIdentifier,
            X509Extensions.SubjectKeyIdentifier
        };

        if (sanList != null && sanList.Any())
        {
            overridenExtensions.Add(X509Extensions.SubjectAlternativeName);
        }

        foreach (var kvp in requestedExtensions)
        {
            if (!overridenExtensions.Contains(kvp.Key))
            {
                certGen.AddExtension(kvp.Key, kvp.Value.IsCritical, kvp.Value.GetParsedValue());
            }
        }

        if (sanList != null && sanList.Any())
        {
            var gnList = sanList.Select(s => new GeneralName(s.TagNo, s.Name)).ToArray();
            var gns = new GeneralNames(gnList);
            certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, gns);
        }

        // Serial Number
        BigInteger serialNumber
            = BigIntegers.CreateRandomInRange(BigInteger.One
                                              , BigInteger.ValueOf(long.MaxValue)
                                              , random);
        certGen.SetSerialNumber(serialNumber);

        // Issuer and Subject Name
        certGen.SetIssuerDN(caCert.SubjectDN);
        certGen.SetSubjectDN(csr.GetCertificationRequestInfo().Subject);

        // Valid For
        DateTime notBefore = DateTime.UtcNow.Date;
        DateTime notAfter = notBefore.AddYears(validityYears);

        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);

        certGen.SetPublicKey(csr.GetPublicKey());

        // Add CA-mandated extensions
        bool isCA = keyUsages != null && keyUsages.Contains(KeyUsage.KeyCertSign);

        if (isCA)
        {
            // If it's a CA, BasicConstraints MUST be present and MUST be critical
            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        }
        else
        {
            // For end-entities, it's safer/compliant to make it non-critical with cA=False.
            certGen.AddExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(false));
        }
        
        if (keyUsages != null && keyUsages.Any())
        {
            certGen.AddExtension(X509Extensions.KeyUsage
                                 , true
                                 , new KeyUsage(keyUsages.Aggregate(0, (ku, next) => ku |= next)));
        }
        
        if (keyPurposes != null && keyPurposes.Any())
        {
            certGen.AddExtension(X509Extensions.ExtendedKeyUsage
                                 , false
                                 , new ExtendedKeyUsage(keyPurposes.ToArray()));
        }
        
        SubjectPublicKeyInfo spkif
            = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caCert.GetPublicKey());
        certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier
                             , false
                             , new AuthorityKeyIdentifier(spkif));

        // Add Subject Key Identifier
        var ski = new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(csr.GetPublicKey()));
        certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, ski);

        ISignatureFactory signatureFactory
            = new Asn1SignatureFactory("SHA256WITHRSA", caKey.Private, random);

        // Sign certificate
        return certGen.Generate(signatureFactory);
    }

    public static (byte[] CsrPem, byte[] KeyPem) GenerateCSR(string commonName, string org, string ou, string country, string locality, string state, string email, List<(int TagNo, string Value)> sans, List<int> usages, List<KeyPurposeID> purposes)
    {
        // Generate RSA Key Pair
        var kpGen = new Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator();
        kpGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPair = kpGen.GenerateKeyPair();

        // Build Subject DN
        var nameValues = new Dictionary<DerObjectIdentifier, string>
        {
            { X509Name.CN, commonName },
            { X509Name.O, org },
            { X509Name.C, country },
            { X509Name.E, email }
        };
        if (!string.IsNullOrWhiteSpace(ou)) nameValues.Add(X509Name.OU, ou);
        if (!string.IsNullOrWhiteSpace(locality)) nameValues.Add(X509Name.L, locality);
        if (!string.IsNullOrWhiteSpace(state)) nameValues.Add(X509Name.ST, state);

        var subject = new X509Name(nameValues.Keys.Reverse().ToList(), nameValues.Values.Reverse().ToList());

        // Build Extensions
        var extensionsGenerator = new X509ExtensionsGenerator();
        
        if (usages.Any())
        {
            extensionsGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(usages.Aggregate(0, (ku, next) => ku |= next)));
        }

        if (purposes.Any())
        {
            extensionsGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(purposes.ToArray()));
        }

        if (sans.Any())
        {
            var gnList = sans.Select(s => new GeneralName(s.TagNo, s.Value)).ToArray();
            extensionsGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(gnList));
        }

        var attribute = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensionsGenerator.Generate()));
        
        // Create CSR
        var pkcs10 = new Pkcs10CertificationRequest(
            "SHA256WITHRSA",
            subject,
            keyPair.Public,
            new DerSet(attribute),
            keyPair.Private);

        // Export to PEM
        StringBuilder csrSb = new();
        csrSb.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");
        csrSb.AppendLine(Convert.ToBase64String(pkcs10.GetEncoded(), Base64FormattingOptions.InsertLineBreaks));
        csrSb.AppendLine("-----END CERTIFICATE REQUEST-----");

        StringBuilder keySb = new();
        keySb.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
        
        // Export PKCS#1 Private Key
        var privateKeyInfo = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
        var innerKey = privateKeyInfo.ParsePrivateKey();
        keySb.AppendLine(Convert.ToBase64String(innerKey.GetDerEncoded(), Base64FormattingOptions.InsertLineBreaks));
        keySb.AppendLine("-----END RSA PRIVATE KEY-----");

        return (Encoding.UTF8.GetBytes(csrSb.ToString()), Encoding.UTF8.GetBytes(keySb.ToString()));
    }


    public static string CertToFile(X509Certificate signedCert)
    {
        StringBuilder sb = new();
        sb.AppendLine("-----BEGIN CERTIFICATE-----");
        sb.AppendLine(Convert.ToBase64String(signedCert.GetEncoded()
                                             , Base64FormattingOptions.InsertLineBreaks));
        sb.AppendLine("-----END CERTIFICATE-----");

        return sb.ToString();
    }

    public static byte[] CertToP7B(X509Certificate signedCert, X509Certificate caCert)
    {
        var store = new Org.BouncyCastle.X509.Store.X509CollectionStoreParameters(new List<X509Certificate> { signedCert, caCert });
        var storeProvider = Org.BouncyCastle.X509.Store.X509StoreFactory.Create("Certificate/Collection", store);
        
        var gen = new Org.BouncyCastle.Cms.CmsSignedDataGenerator();
        gen.AddCertificates(storeProvider);
        
        var msg = gen.Generate(new Org.BouncyCastle.Cms.CmsProcessableByteArray(Array.Empty<byte>()), false);
        return msg.GetEncoded();
    }

    private static string? GetSanValue(GeneralName gn)
    {
        if (gn.TagNo == GeneralName.IPAddress)
        {
            var octets = Org.BouncyCastle.Asn1.Asn1OctetString.GetInstance(gn.Name).GetOctets();
            try
            {
                return new System.Net.IPAddress(octets).ToString();
            }
            catch
            {
                return gn.Name.ToString();
            }
        }
        return gn.Name.ToString();
    }

    public static IEnumerable<string> GetCertificateSANs(X509Certificate cert)
    {
        List<string> retval = [];
        var extensionValue = cert.GetExtensionValue(X509Extensions.SubjectAlternativeName);
        if (extensionValue != null)
        {
            var gns = GeneralNames.GetInstance(Asn1Object.FromByteArray(extensionValue.GetOctets()));
            foreach (var gn in gns.GetNames())
            {
                string? name = GetSanValue(gn);
                if (name != null)
                {
                    retval.Add(name);
                }
            }
        }
        return retval;
    }

    public static IEnumerable<string> GetCertificateKeyUsages(X509Certificate cert)
    {
        List<string> retval = [];
        var ku = cert.GetKeyUsage();
        if (ku != null)
        {
            // ku is bool[]: [digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, crlSign, encipherOnly, decipherOnly]
            if (ku.Length > 0 && ku[0]) retval.Add("Digital Signature");
            if (ku.Length > 1 && ku[1]) retval.Add("Non-Repudiation");
            if (ku.Length > 2 && ku[2]) retval.Add("Key Encipherment");
            if (ku.Length > 3 && ku[3]) retval.Add("Data Encipherment");
            if (ku.Length > 4 && ku[4]) retval.Add("Key Agreement");
            if (ku.Length > 5 && ku[5]) retval.Add("Key Certificate Signing");
            if (ku.Length > 6 && ku[6]) retval.Add("CRL Signing");
            if (ku.Length > 7 && ku[7]) retval.Add("Encipher Only");
            if (ku.Length > 8 && ku[8]) retval.Add("Decipher Only");
        }
        return retval;
    }

    public static IEnumerable<string> GetCertificatePurposes(X509Certificate cert)
    {
        List<string> retval = [];
        var eku = cert.GetExtendedKeyUsage();
        if (eku != null)
        {
            foreach (DerObjectIdentifier oid in eku)
            {
                if (oid.Equals(KeyPurposeID.AnyExtendedKeyUsage)) retval.Add("All Purposes");
                else if (oid.Equals(KeyPurposeID.IdKPServerAuth)) retval.Add("Server Authentication");
                else if (oid.Equals(KeyPurposeID.IdKPClientAuth)) retval.Add("Client Authentication");
                else if (oid.Equals(KeyPurposeID.IdKPCodeSigning)) retval.Add("Code Signing");
                else if (oid.Equals(KeyPurposeID.IdKPEmailProtection)) retval.Add("E-Mail Protection");
                else if (oid.Equals(KeyPurposeID.IdKPIpsecEndSystem)) retval.Add("IPsec End System");
                else if (oid.Equals(KeyPurposeID.IdKPIpsecTunnel)) retval.Add("IPsec Tunnel");
                else if (oid.Equals(KeyPurposeID.IdKPIpsecUser)) retval.Add("IPsec User");
                else if (oid.Equals(KeyPurposeID.IdKPTimeStamping)) retval.Add("Time Stamping");
                else if (oid.Equals(KeyPurposeID.IdKPOcspSigning)) retval.Add("OCSP Signing");
                else if (oid.Equals(KeyPurposeID.IdKPSmartCardLogon)) retval.Add("Smart Card Log-on");
                else if (oid.Equals(KeyPurposeID.IdKPMacAddress)) retval.Add("MAC Address");
                else retval.Add(oid.Id);
            }
        }
        return retval;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="csr"></param>
    /// <returns></returns>
    public static IEnumerable<(int TagNo, string Name)> GetTypedSANs(Pkcs10CertificationRequest csr)
    {
        List<(int TagNo, string Name)> retval = [];

        Asn1Set attributes = csr.GetCertificationRequestInfo().Attributes;
        if (attributes is not null)
        {
            for (int i = 0; i != attributes.Count; i++)
            {
                AttributePkcs attr = AttributePkcs.GetInstance(attributes[i]);
                if (attr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                {
                    X509Extensions extensions = X509Extensions.GetInstance(attr.AttrValues[0]);
                    foreach (DerObjectIdentifier oid in extensions.ExtensionOids)
                    {
                        if (oid.Equals(X509Extensions.SubjectAlternativeName))
                        {
                            X509Extension ext = extensions.GetExtension(oid);
                            GeneralNames gns = GeneralNames.GetInstance(ext.GetParsedValue());
                            foreach (GeneralName gn in gns.GetNames())
                            {
                                string? name = GetSanValue(gn);
                                if (name != null)
                                {
                                    retval.Add((gn.TagNo, name));
                                }
                            }
                        }
                    }
                }
            }
        }
        
        return retval;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="csr"></param>
    /// <returns></returns>
    public static IEnumerable<string> GetSANs(Pkcs10CertificationRequest csr)
    {
        List<string> retval = [];

        Asn1Set attributes = csr.GetCertificationRequestInfo().Attributes;
        if (attributes is not null)
        {
            for (int i = 0; i != attributes.Count; i++)
            {
                AttributePkcs attr = AttributePkcs.GetInstance(attributes[i]);
                if (attr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                {
                    X509Extensions extensions = X509Extensions.GetInstance(attr.AttrValues[0]);
                    foreach (DerObjectIdentifier oid in extensions.ExtensionOids)
                    {
                        if (oid.Equals(X509Extensions.SubjectAlternativeName))
                        {
                            X509Extension ext = extensions.GetExtension(oid);
                            GeneralNames gns = GeneralNames.GetInstance(ext.GetParsedValue());
                            foreach (GeneralName gn in gns.GetNames())
                            {
                                string? name = GetSanValue(gn);
                                if (name != null)
                                {
                                    retval.Add(name);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        return retval;
    }

    public static int AutoDetectSanType(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return 2; // DNS Name (default)
        }

        value = value.Trim();

        // 1. IP Address
        if (System.Net.IPAddress.TryParse(value, out _))
        {
            return 7; // IP Address
        }

        // 2. Email Address
        if (value.Contains('@') && !value.Contains('/') && !value.Contains(':'))
        {
            return 1; // Email
        }

        // 3. URI
        if (Uri.TryCreate(value, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == "ldap" || uri.Scheme == "ldaps"))
        {
            return 6; // URI
        }

        // 4. Default to DNS Name
        return 2; // DNS Name
    }

    private class CAKeyPasswordFinder(string path) : IPasswordFinder
    {
        public char[] GetPassword()
            => File.ReadAllText(path, Encoding.UTF8)
                   .ToCharArray();
    }
}
