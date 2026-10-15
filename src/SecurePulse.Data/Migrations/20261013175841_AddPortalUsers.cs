using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecurePulse.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPortalUsers : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "StartedBy",
                table: "onboarding_requests",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "portal_users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    EntraTenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    UserPrincipalName = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: false),
                    ObjectId = table.Column<Guid>(type: "uuid", nullable: true),
                    DisplayName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    ClientTenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    LastSignInAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_portal_users", x => x.Id);
                    table.ForeignKey(
                        name: "FK_portal_users_tenants_ClientTenantId",
                        column: x => x.ClientTenantId,
                        principalTable: "tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_portal_users_ClientTenantId",
                table: "portal_users",
                column: "ClientTenantId");

            migrationBuilder.CreateIndex(
                name: "IX_portal_users_EntraTenantId_ObjectId",
                table: "portal_users",
                columns: new[] { "EntraTenantId", "ObjectId" },
                unique: true,
                filter: "\"ObjectId\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_portal_users_EntraTenantId_UserPrincipalName",
                table: "portal_users",
                columns: new[] { "EntraTenantId", "UserPrincipalName" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "portal_users");

            migrationBuilder.DropColumn(
                name: "StartedBy",
                table: "onboarding_requests");
        }
    }
}
