using Common;
using DAL.Models;
using Org.BouncyCastle.Asn1.X509;
using System.ComponentModel.DataAnnotations;

namespace Backend.Models;
public class ProcessViewModel
{
    public CSRId OriginalRequestId { get; set; }

    [Display(Name = "Country Code")]
    public string? CountryCode { get; set; }

    [Display(Name = "Organization")]
    public string? Organization { get; set; }

    [Display(Name = "Department")]
    [DisplayFormat(NullDisplayText = "-- not specified --")]
    public string? OrganizationUnitName { get; set; }

    [Display(Name = "Common Name")]
    public string? CommonName { get; set; }

    [Display(Name = "Alternate Names")]
    public List<string> AlternateNames { get; set; } = [];

    [Display(Name = "City")]
    public string? Locality { get; set; }

    [Display(Name = "State/Province")]
    [DisplayFormat(NullDisplayText = "-- not specified --")]
    public string? State { get; set; }

    [Display(Name = "E-Mail Address")]
    public string? EMailAddress { get; set; }

    [Display(Name = "Filename")]
    public string? FileName { get; set; }

    [Display(Name = "File Size")]
    public string? FileSize { get; set; }

    [Display(Name = "Is Signed")]
    public bool? IsSigned { get; set; }

    [Display(Name = "Submitted On")]
    public DateTime? SubmittedOn { get; set; }

    /** Signed CSR Properties **/
    [Display(Name = "Not After")]
    [DataType(DataType.Date)]
    public DateTime ExpieryDate { get; set; } = DateTime.Now.AddYears(1);

    /* Purposes */
    [Display(Name = "All Purposes")]
    public bool PurposeAll { get; set; }

    [Display(Name = "Server Authentication")]
    public bool PurposeServerAuth { get; set; }

    [Display(Name = "Client Authentication")]
    public bool PurposeClientAuth { get; set; }

    [Display(Name = "Code Signing")]
    public bool PurposeCodeSigning { get; set; }

    [Display(Name = "E-Mail Protection")]
    public bool PurposeEMailProtection { get; set; }

    [Display(Name = "IPsec End System")]
    public bool PurposeIPsecEndSystem { get; set; }

    [Display(Name = "IPsec Tunnel")]
    public bool PurposeIPsecTunnel { get; set; }

    [Display(Name = "IPsec User")]
    public bool PurposeIPsecUser { get; set; }

    [Display(Name = "Time Stamping")]
    public bool PurposeTimeStamping { get; set; }

    [Display(Name = "OCSP Signing")]
    public bool PurposeOCSPSigning { get; set; }

    [Display(Name = "Smart Card Log-on")]
    public bool PurposeSmartCardLogon { get; set; }

    [Display(Name = "MAC Address")]
    public bool PurposeMACAddress { get; set; }

    /* Key Usages */
    [Display(Name = "Digital Signing")]
    public bool UsageDigitalSignature { get; set; }

    [Display(Name = "Non Repudiation"
             , Description = "a.k.a. Content Commitment")]
    public bool UsageNonRepudiation { get; set; }

    [Display(Name = "Key Encipherment")]
    public bool UsageKeyEncipherment { get; set; }

    [Display(Name = "Data Encipherment")]
    public bool UsageDataEncipherment { get; set; }

    [Display(Name = "Key Agreement")]
    public bool UsageKeyAgreement { get; set; }

    [Display(Name = "Key Certificate Signing")]
    public bool UsageKeyCertSigning { get; set; }

    [Display(Name = "CRL Signing"
             , Description = "Signing of Certificate Revocation Lists (CRLs)")]
    public bool UsageCRLSigning { get; set; }

    [Display(Name = "Encipherment Only")]
    public bool UsageEncipherOnly { get; set; }

    [Display(Name = "Decipherment Only")]
    public bool UsageDecipherOnly { get; set; }

    public ProcessViewModel() { }

    public ProcessViewModel(CSR csr)
    {
        OriginalRequestId = csr.Id;
        CountryCode = csr.CountryCode;
        Organization = csr.Organization;
        OrganizationUnitName = csr.OrganizationUnitName;
        CommonName = csr.CommonName;
        AlternateNames = csr.AlternateNamesList;
        Locality = csr.Locality;
        State = csr.State;
        EMailAddress = csr.EMailAddress;
        FileName = csr.FileName;
        IsSigned = csr.IsSigned;
        SubmittedOn = csr.SubmittedOn;
        FileSize = csr.FileContents.LongLength.GetReadableBytes();
    }

    public static KeyPurposeID? GetKeyPurpose(string purpose)
        => purpose switch
        {
            nameof(PurposeAll) => KeyPurposeID.AnyExtendedKeyUsage
            , nameof(PurposeServerAuth) => KeyPurposeID.IdKPServerAuth
            , nameof(PurposeClientAuth) => KeyPurposeID.IdKPClientAuth
            , nameof(PurposeCodeSigning) => KeyPurposeID.IdKPCodeSigning
            , nameof(PurposeEMailProtection) => KeyPurposeID.IdKPEmailProtection
            , nameof(PurposeIPsecEndSystem) => KeyPurposeID.IdKPIpsecEndSystem
            , nameof(PurposeIPsecTunnel) => KeyPurposeID.IdKPIpsecTunnel
            , nameof(PurposeIPsecUser) => KeyPurposeID.IdKPIpsecUser
            , nameof(PurposeTimeStamping) => KeyPurposeID.IdKPTimeStamping
            , nameof(PurposeOCSPSigning) => KeyPurposeID.IdKPOcspSigning
            , nameof(PurposeSmartCardLogon) => KeyPurposeID.IdKPSmartCardLogon
            , nameof(PurposeMACAddress) => KeyPurposeID.IdKPMacAddress
            , _ => null
        };

    public static int GetKeyUsage(string keyUsage)
        => keyUsage switch
        {
            nameof(UsageDigitalSignature) => KeyUsage.DigitalSignature
            , nameof(UsageNonRepudiation) => KeyUsage.NonRepudiation
            , nameof(UsageKeyEncipherment) => KeyUsage.KeyEncipherment
            , nameof(UsageDataEncipherment) => KeyUsage.DataEncipherment
            , nameof(UsageKeyAgreement) => KeyUsage.KeyAgreement
            , nameof(UsageKeyCertSigning) => KeyUsage.KeyCertSign
            , nameof(UsageCRLSigning) => KeyUsage.CrlSign
            , nameof(UsageEncipherOnly) => KeyUsage.EncipherOnly
            , nameof(UsageDecipherOnly) => KeyUsage.DecipherOnly
            , _ => -1
        };

    public List<KeyPurposeID> RequestedKeyPurposes
    {
        get
        {
            List<KeyPurposeID> retval = [];

            retval.AddIfNotFalse( PurposeAll, GetKeyPurpose(nameof(PurposeAll)) );
            retval.AddIfNotFalse( PurposeServerAuth, GetKeyPurpose(nameof(PurposeServerAuth)) );
            retval.AddIfNotFalse( PurposeClientAuth, GetKeyPurpose(nameof(PurposeClientAuth)) );
            retval.AddIfNotFalse( PurposeCodeSigning, GetKeyPurpose(nameof(PurposeCodeSigning)) );
            retval.AddIfNotFalse( PurposeEMailProtection, GetKeyPurpose(nameof(PurposeEMailProtection)) );
            retval.AddIfNotFalse( PurposeIPsecEndSystem, GetKeyPurpose(nameof(PurposeIPsecEndSystem)) );
            retval.AddIfNotFalse( PurposeIPsecTunnel, GetKeyPurpose(nameof(PurposeIPsecTunnel)) );
            retval.AddIfNotFalse( PurposeIPsecUser, GetKeyPurpose(nameof(PurposeIPsecUser)) );
            retval.AddIfNotFalse( PurposeTimeStamping, GetKeyPurpose(nameof(PurposeTimeStamping)) );
            retval.AddIfNotFalse( PurposeOCSPSigning, GetKeyPurpose(nameof(PurposeOCSPSigning)) );
            retval.AddIfNotFalse( PurposeSmartCardLogon, GetKeyPurpose(nameof(PurposeSmartCardLogon)) );
            retval.AddIfNotFalse( PurposeMACAddress, GetKeyPurpose(nameof(PurposeMACAddress)) );
            return retval;
        }
    }

    public List<int> RequestedKeyUsages
    {
        get
        {
            List<int> retval = [];

            retval.AddIfNotFalse(UsageDigitalSignature, GetKeyUsage(nameof(UsageDigitalSignature)) );
            retval.AddIfNotFalse(UsageNonRepudiation, GetKeyUsage(nameof(UsageNonRepudiation)) );
            retval.AddIfNotFalse(UsageKeyEncipherment, GetKeyUsage(nameof(UsageKeyEncipherment)) );
            retval.AddIfNotFalse(UsageDataEncipherment, GetKeyUsage(nameof(UsageDataEncipherment)) );
            retval.AddIfNotFalse(UsageKeyAgreement, GetKeyUsage(nameof(UsageKeyAgreement)) );
            retval.AddIfNotFalse(UsageKeyCertSigning, GetKeyUsage(nameof(UsageKeyCertSigning)) );
            retval.AddIfNotFalse(UsageCRLSigning, GetKeyUsage(nameof(UsageCRLSigning)) );
            retval.AddIfNotFalse(UsageEncipherOnly, GetKeyUsage(nameof(UsageEncipherOnly)) );
            retval.AddIfNotFalse(UsageDecipherOnly, GetKeyUsage(nameof(UsageDecipherOnly)) );

            return retval;
        }
    }
}