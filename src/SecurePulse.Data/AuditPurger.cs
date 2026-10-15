using Npgsql;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Data;

/// <summary>
/// Deletes old audit events with the maintenance connection (<c>ConnectionStrings:AuditMaintenance</c>).
/// Its login is a member of <see cref="PurgeRole"/> and switches to it per batch; the audit_events
/// trigger lets only that role delete, and only rows older than <see cref="AuditRetention.Minimum"/>.
/// </summary>
public sealed class PostgresAuditPurger(NpgsqlDataSource maintenance) : IAuditPurger
{
    public const string PurgeRole = "securepulse_audit_purge";

    // Session advisory lock: one purge at a time across Workers. An arbitrary constant ("SPAUDIT").
    public const long LockKey = 0x5350_4155_4449_54;

    public async Task<long> CountOlderThanAsync(DateTimeOffset cutoff, CancellationToken ct = default)
    {
        await using var connection = await maintenance.OpenConnectionAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(ct);
        await SetRoleAsync(connection, tx, ct);
        await using var count = new NpgsqlCommand("""SELECT count(*) FROM audit_events WHERE "OccurredAt" < $1""", connection, tx);
        count.Parameters.AddWithValue(cutoff.UtcDateTime);
        return (long)(await count.ExecuteScalarAsync(ct))!;
    }

    public async Task<long?> PurgeOlderThanAsync(DateTimeOffset cutoff, int batchSize, CancellationToken ct = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(batchSize, 1);

        await using var connection = await maintenance.OpenConnectionAsync(ct);
        if (!await ScalarAsync<bool>(connection, $"SELECT pg_try_advisory_lock({LockKey})", ct))
            return null;

        long deleted = 0;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                // One short transaction per batch, so a large first purge doesn't hold locks for long.
                await using var tx = await connection.BeginTransactionAsync(ct);
                await SetRoleAsync(connection, tx, ct);
                await using var delete = new NpgsqlCommand("""
                    DELETE FROM audit_events WHERE "Id" IN (
                        SELECT "Id" FROM audit_events WHERE "OccurredAt" < $1 ORDER BY "OccurredAt" LIMIT $2)
                    """, connection, tx);
                delete.Parameters.AddWithValue(cutoff.UtcDateTime);
                delete.Parameters.AddWithValue(batchSize);
                var rows = await delete.ExecuteNonQueryAsync(ct);
                await tx.CommitAsync(ct);
                deleted += rows;
                if (rows < batchSize) break;
            }
            ct.ThrowIfCancellationRequested();
            return deleted;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new AuditPurgeException(deleted, ex);
        }
        catch (OperationCanceledException ex) when (deleted > 0)
        {
            throw new AuditPurgeException(deleted, ex);
        }
        finally
        {
            if (connection.State == System.Data.ConnectionState.Open)
                await ScalarAsync<bool>(connection, $"SELECT pg_advisory_unlock({LockKey})", CancellationToken.None);
        }
    }

    private static async Task SetRoleAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    {
        await using var setRole = new NpgsqlCommand($"SET LOCAL ROLE {PurgeRole}", connection, tx);
        await setRole.ExecuteNonQueryAsync(ct);
    }

    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        return (T)(await command.ExecuteScalarAsync(ct))!;
    }
}
