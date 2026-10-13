using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecurePulse.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddOnboarding : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "onboarding_requests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    PrimaryDomain = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    PartnerName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    Industry = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    EntraTenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ConsentReceivedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CompletedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    LastError = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    GrantedPermissions = table.Column<string[]>(type: "text[]", nullable: false),
                    VerificationAttempts = table.Column<int>(type: "integer", nullable: false),
                    StateHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProtectedState = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_onboarding_requests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_onboarding_requests_tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_onboarding_requests_StateHash",
                table: "onboarding_requests",
                column: "StateHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_onboarding_requests_Status_CreatedAt",
                table: "onboarding_requests",
                columns: new[] { "Status", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_onboarding_requests_TenantId",
                table: "onboarding_requests",
                column: "TenantId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "onboarding_requests");
        }
    }
}
