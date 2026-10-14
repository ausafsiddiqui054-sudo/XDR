using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecurePulse.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddScanRuns : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "scan_runs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    Engine = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Trigger = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    QueuedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    StartedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CompletedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RequestedBy = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    FindingCount = table.Column<int>(type: "integer", nullable: true),
                    Error = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scan_runs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_scan_runs_tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_scan_runs_active",
                table: "scan_runs",
                columns: new[] { "TenantId", "Engine" },
                unique: true,
                filter: "\"Status\" IN ('Queued', 'Running')");

            migrationBuilder.CreateIndex(
                name: "IX_scan_runs_Status_QueuedAt",
                table: "scan_runs",
                columns: new[] { "Status", "QueuedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_scan_runs_TenantId_Engine_QueuedAt",
                table: "scan_runs",
                columns: new[] { "TenantId", "Engine", "QueuedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "scan_runs");
        }
    }
}
