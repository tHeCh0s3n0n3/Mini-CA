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
        if (fileContents is null)
        {
            throw new ArgumentNullException(nameof(fileContents));
        }

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
        if (caCertContents is null)
        {
            throw new ArgumentNullException(nameof(caCertContents));
        }

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

    public static AsymmetricCipherKeyPair ImportCAKey(string caKeyPath, string caKeyPasswordPath)
    {
        if (string.IsNullOrEmpty(caKeyPath))
        {
            throw new ArgumentException($"'{nameof(caKeyPath)}' cannot be null or empty.", nameof(caKeyPath));
        }

        if (string.IsNullOrEmpty(caKeyPasswordPath))
        {
            throw new ArgumentException($"'{nameof(caKeyPasswordPath)}' cannot be null or empty.", nameof(caKeyPasswordPath));
        }

        return ImportCAKey(File.ReadAllBytes(caKeyPath), caKeyPasswordPath);
    }

    public static AsymmetricCipherKeyPair ImportCAKey(byte[] caKeyContents, string caKeyPasswordPath)
    {
        if (caKeyContents is null)
        {
            throw new ArgumentNullException(nameof(caKeyContents));
        }

        if (string.IsNullOrEmpty(caKeyPasswordPath))
        {
            throw new ArgumentException($"'{nameof(caKeyPasswordPath)}' cannot be null or empty.", nameof(caKeyPasswordPath));
        }

        using MemoryStream ms = new(caKeyContents);
        using StreamReader caKeySR = new(ms);
        PemReader caKeyReader = new(caKeySR
                                    , new CAKeyPasswordFinder(caKeyPasswordPath));

        if (caKeyReader.ReadObject()
            is not AsymmetricCipherKeyPair caKeyObj)
        {
            Console.WriteLine("Not a certificate key file.");
            throw new ArgumentException("Not a certificate key file", nameof(caKeyContents));
        }
        return caKeyObj;
    }

    public static X509Certificate SignCSR(Pkcs10CertificationRequest csr
                                          , X509Certificate caCert
                                          , AsymmetricCipherKeyPair caKey
                                          , int validityYears
                                          , IEnumerable<int> keyUsages
                                          , IEnumerable<KeyPurposeID> keyPurposes)
    {
        if (csr is null)
        {
            throw new ArgumentNullException(nameof(csr));
        }

        if (caCert is null)
        {
            throw new ArgumentNullException(nameof(caCert));
        }

        if (caKey is null)
        {
            throw new ArgumentNullException(nameof(caKey));
        }

        if (!csr.Verify())
        {
            throw new Exception("CSR is invalid.");
        }

        // Generating Random Numbers
        CryptoApiRandomGenerator randomGenerator = new();
        SecureRandom random = new(randomGenerator);

        X509V3CertificateGenerator certGen = new();

        Asn1Set attributes = csr.GetCertificationRequestInfo().Attributes;
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
                        X509Extension ext = extensions.GetExtension(oid);
                        certGen.AddExtension(oid, ext.IsCritical, ext.GetParsedValue());
                    }
                }
            }
        }

        // Serial Number
        BigInteger serialNumber
            = BigIntegers.CreateRandomInRange(BigInteger.One
                                              , BigInteger.ValueOf(Int64.MaxValue)
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

        // Add basic constraints
        certGen.AddExtension(X509Extensions.BasicConstraints
                             , true
                             , new BasicConstraints(false));
        int ku = 0;
        foreach(int item in keyUsages)
        {
            ku |= item;
        }
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

    /// <summary>
    /// 
    /// </summary>
    /// <param name="csr"></param>
    /// <returns></returns>
    public static IEnumerable<string> GetSANs(Pkcs10CertificationRequest csr)
    {
        List<string> retval = new();

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
                        X509Extension ext = extensions.GetExtension(oid);
                        var pv = (Asn1Sequence)ext.GetParsedValue();
                        foreach(Asn1TaggedObject obj in pv)
                        {
                            string str = Encoding.UTF8.GetString(obj.GetObject().GetEncoded());
                            retval.Add(new string(str.Where(c => !char.IsControl(c)).ToArray()));
                        }
                    }
                }
            }
        }
        
        return retval;
    }

    private class CAKeyPasswordFinder : IPasswordFinder
    {
        private readonly string _passwordFilePath;

        public CAKeyPasswordFinder(string path)
        {
            _passwordFilePath = path;
        }

        public char[] GetPassword()
        {
            return File.ReadAllText(_passwordFilePath, Encoding.UTF8)
                        .ToCharArray();
        }
    }
}
