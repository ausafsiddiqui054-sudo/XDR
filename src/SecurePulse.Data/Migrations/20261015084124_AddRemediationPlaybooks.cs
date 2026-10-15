using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecurePulse.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddRemediationPlaybooks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "PlaybookId",
                table: "device_actions",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "remediation_playbooks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    Trigger = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Days = table.Column<int>(type: "integer", nullable: true),
                    Action = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    MaxPerRun = table.Column<int>(type: "integer", nullable: false),
                    Cooldown = table.Column<TimeSpan>(type: "interval", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedByUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    UpdatedByName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastRunAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_remediation_playbooks", x => x.Id);
                    table.ForeignKey(
                        name: "FK_remediation_playbooks_tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_device_actions_PlaybookId_TenantId_RequestedAt",
                table: "device_actions",
                columns: new[] { "PlaybookId", "TenantId", "RequestedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_remediation_playbooks_TenantId",
                table: "remediation_playbooks",
                column: "TenantId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "remediation_playbooks");

            migrationBuilder.DropIndex(
                name: "IX_device_actions_PlaybookId_TenantId_RequestedAt",
                table: "device_actions");

            migrationBuilder.DropColumn(
                name: "PlaybookId",
                table: "device_actions");
        }
    }
}
