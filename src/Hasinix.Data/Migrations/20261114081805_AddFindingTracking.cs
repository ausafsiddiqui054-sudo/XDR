using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Hasinix.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddFindingTracking : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "finding_tracking",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    FindingId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    FindingTitle = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Owner = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    DueDate = table.Column<DateOnly>(type: "date", nullable: true),
                    Acceptance = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    AcceptanceReason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    AcceptanceExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RequestedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    RequestedByName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    RequestedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    DecidedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    DecidedByName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    DecidedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    DecisionNote = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_finding_tracking", x => new { x.TenantId, x.FindingId });
                    table.ForeignKey(
                        name: "FK_finding_tracking_tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "finding_tracking");
        }
    }
}
