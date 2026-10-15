using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecurePulse.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAuditExport : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // now() is stable, so existing rows get the migration time without rewriting the table;
            // new rows then get the database's statement time (clock_timestamp()).
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "RecordedAt",
                table: "audit_events",
                type: "timestamp with time zone",
                nullable: false,
                defaultValueSql: "now()");
            migrationBuilder.Sql("""ALTER TABLE audit_events ALTER COLUMN "RecordedAt" SET DEFAULT clock_timestamp();""");

            migrationBuilder.CreateTable(
                name: "audit_export_checkpoints",
                columns: table => new
                {
                    Destination = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    RecordedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastId = table.Column<Guid>(type: "uuid", nullable: true),
                    ExportedCount = table.Column<long>(type: "bigint", nullable: false),
                    LastExportedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastAttemptAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastError = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_export_checkpoints", x => x.Destination);
                });

            migrationBuilder.CreateIndex(
                name: "IX_audit_events_RecordedAt_Id",
                table: "audit_events",
                columns: new[] { "RecordedAt", "Id" });

            // Retention reads the checkpoints so it never deletes events an export hasn't sent.
            migrationBuilder.Sql("""
                DO $$
                BEGIN
                    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'securepulse_audit_purge') THEN
                        GRANT SELECT ON audit_export_checkpoints TO securepulse_audit_purge;
                    END IF;
                END;
                $$;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "audit_export_checkpoints");

            migrationBuilder.DropIndex(
                name: "IX_audit_events_RecordedAt_Id",
                table: "audit_events");

            migrationBuilder.DropColumn(
                name: "RecordedAt",
                table: "audit_events");
        }
    }
}
