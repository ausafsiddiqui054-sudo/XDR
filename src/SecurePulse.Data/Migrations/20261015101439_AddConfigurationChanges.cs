using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecurePulse.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddConfigurationChanges : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ConfigurationCredentialReference",
                table: "tenants",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "configuration_changes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    FixId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CheckId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    Reason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    RequestedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    RequestedByUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestedByName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    DecidedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    DecidedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    DecidedByName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    DecidedByRole = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    DecisionNote = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    CancelledAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CancelledBy = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    SentAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CompletedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    Error = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    PolicyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    PlaybookId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_configuration_changes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_configuration_changes_tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "finding_playbooks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FixId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedByUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    UpdatedByName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastRunAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_finding_playbooks", x => x.Id);
                    table.ForeignKey(
                        name: "FK_finding_playbooks_tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_configuration_changes_open",
                table: "configuration_changes",
                columns: new[] { "TenantId", "FixId" },
                unique: true,
                filter: "\"Status\" IN ('PendingApproval', 'Approved', 'Sending')");

            migrationBuilder.CreateIndex(
                name: "IX_configuration_changes_PlaybookId_TenantId_RequestedAt",
                table: "configuration_changes",
                columns: new[] { "PlaybookId", "TenantId", "RequestedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_configuration_changes_Status_DecidedAt",
                table: "configuration_changes",
                columns: new[] { "Status", "DecidedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_finding_playbooks_TenantId",
                table: "finding_playbooks",
                column: "TenantId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "configuration_changes");

            migrationBuilder.DropTable(
                name: "finding_playbooks");

            migrationBuilder.DropColumn(
                name: "ConfigurationCredentialReference",
                table: "tenants");
        }
    }
}
