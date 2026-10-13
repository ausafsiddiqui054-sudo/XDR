using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SecurePulse.Data;

/// <summary>Lets `dotnet ef migrations add` build the model without a running app or database.</summary>
internal sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<SecurePulseDbContext>
{
    public SecurePulseDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<SecurePulseDbContext>()
            .UseNpgsql(Environment.GetEnvironmentVariable("ConnectionStrings__SecurePulse") ?? "Host=localhost;Database=securepulse")
            .Options);
}
