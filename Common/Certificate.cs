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
                                          , IEnumerable<KeyPurposeID> keyPurposes)
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

        foreach (var kvp in requestedExtensions)
        {
            if (!overridenExtensions.Contains(kvp.Key))
            {
                certGen.AddExtension(kvp.Key, kvp.Value.IsCritical, kvp.Value.GetParsedValue());
            }
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
        certGen.AddExtension(X509Extensions.BasicConstraints
                             , true
                             , new BasicConstraints(false));
        
        certGen.AddExtension(X509Extensions.KeyUsage
                             , true
                             , new KeyUsage(keyUsages.Aggregate(0, (ku, next) => ku |= next)));
        
        certGen.AddExtension(X509Extensions.ExtendedKeyUsage
                             , true
                             , new ExtendedKeyUsage(keyPurposes.ToArray()));
        
        SubjectPublicKeyInfo spkif
            = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caCert.GetPublicKey());
        certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier
                             , true
                             , new AuthorityKeyIdentifier(spkif));

        // Add Subject Key Identifier
        var ski = new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(csr.GetPublicKey()));
        certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, ski);

        ISignatureFactory signatureFactory
            = new Asn1SignatureFactory("SHA256WITHRSA", caKey.Private, random);

        // Sign certificate
        return certGen.Generate(signatureFactory);
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
                                string? name = gn.Name?.ToString();
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

    private class CAKeyPasswordFinder(string path) : IPasswordFinder
    {
        public char[] GetPassword()
            => File.ReadAllText(path, Encoding.UTF8)
                   .ToCharArray();
    }
}
