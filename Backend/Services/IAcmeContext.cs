using OpenCertServer.Acme.Abstractions.Model;

namespace Backend.Services;

public interface IAcmeContext
{
    Account? CurrentAccount { get; set; }
}

public class AcmeContext : IAcmeContext
{
    public Account? CurrentAccount { get; set; }
}
