using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Hasinix.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddScoreSnapshots : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "score_snapshots",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    RecordedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Engine = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Score = table.Column<int>(type: "integer", nullable: false),
                    Grade = table.Column<string>(type: "character varying(2)", maxLength: 2, nullable: false),
                    Passed = table.Column<int>(type: "integer", nullable: false),
                    Failed = table.Column<int>(type: "integer", nullable: false),
                    Investigate = table.Column<int>(type: "integer", nullable: false),
                    NotEvaluated = table.Column<int>(type: "integer", nullable: false),
                    FailedCritical = table.Column<int>(type: "integer", nullable: false),
                    FailedHigh = table.Column<int>(type: "integer", nullable: false),
                    FailedMedium = table.Column<int>(type: "integer", nullable: false),
                    FailedLow = table.Column<int>(type: "integer", nullable: false),
                    FailedInfo = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_score_snapshots", x => x.Id);
                    table.ForeignKey(
                        name: "FK_score_snapshots_tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_score_snapshots_RecordedAt",
                table: "score_snapshots",
                column: "RecordedAt");

            migrationBuilder.CreateIndex(
                name: "IX_score_snapshots_TenantId_RecordedAt",
                table: "score_snapshots",
                columns: new[] { "TenantId", "RecordedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "score_snapshots");
        }
    }
}
