using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using SecurePulse.Data;

namespace SecurePulse.Tests.Data;

/// <summary>
/// Runs only when SECUREPULSE_TEST_POSTGRES holds a connection string (without Database) for a
/// role that can create databases. Otherwise the test is reported as skipped, not passed.
/// </summary>
public sealed class PostgresFactAttribute : FactAttribute
{
    public PostgresFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(PostgresDatabase.ServerConnectionString))
            Skip = "Set SECUREPULSE_TEST_POSTGRES to run PostgreSQL repository tests.";
    }
}

/// <summary>A throwaway, migrated database per test class, dropped afterwards.</summary>
public sealed class PostgresDatabase : IAsyncLifetime
{
    public static string? ServerConnectionString => Environment.GetEnvironmentVariable("SECUREPULSE_TEST_POSTGRES");

    private readonly string _name = $"securepulse_test_{Guid.NewGuid():N}";
    private ServiceProvider? _services;

    public IServiceProvider Services => _services ?? throw new InvalidOperationException("PostgreSQL tests are not configured.");

    public async Task InitializeAsync()
    {
        if (string.IsNullOrWhiteSpace(ServerConnectionString)) return;

        var connectionString = new NpgsqlConnectionStringBuilder(ServerConnectionString) { Database = _name }.ConnectionString;
        _services = new ServiceCollection().AddSecurePulseData(connectionString).BuildServiceProvider();
        await ExecuteOnServerAsync($"CREATE DATABASE \"{_name}\"");
        await _services.MigrateSecurePulseDatabaseAsync();
    }

    public async Task DisposeAsync()
    {
        if (_services is null) return;
        await _services.DisposeAsync();
        NpgsqlConnection.ClearAllPools();
        await ExecuteOnServerAsync($"DROP DATABASE IF EXISTS \"{_name}\" WITH (FORCE)");
    }

    private static async Task ExecuteOnServerAsync(string sql)
    {
        var builder = new NpgsqlConnectionStringBuilder(ServerConnectionString) { Database = "postgres", Pooling = false };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }
}
