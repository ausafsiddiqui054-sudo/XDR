using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Hasinix.Data;

/// <summary>Lets `dotnet ef migrations add` build the model without a running app or database.</summary>
internal sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<HasinixDbContext>
{
    public HasinixDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<HasinixDbContext>()
            .UseNpgsql(Environment.GetEnvironmentVariable("ConnectionStrings__Hasinix") ?? "Host=localhost;Database=securepulse")
            .Options);
}
