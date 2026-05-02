using Org.BouncyCastle.Asn1.X509;
using System;

try {
    var gn = new GeneralName(GeneralName.IPAddress, "10.10.0.10");
    Console.WriteLine($"Tag: {gn.TagNo}, Encoded: {BitConverter.ToString(gn.GetEncoded())}");
    
    // Attempt with octets
    byte[] ip = new byte[] { 10, 10, 0, 10 };
    var gnOctets = new GeneralName(GeneralName.IPAddress, new Org.BouncyCastle.Asn1.DerOctetString(ip));
    Console.WriteLine($"Tag: {gnOctets.TagNo}, Encoded: {BitConverter.ToString(gnOctets.GetEncoded())}");

} catch (Exception ex) {
    Console.WriteLine("Error: " + ex.Message);
}
