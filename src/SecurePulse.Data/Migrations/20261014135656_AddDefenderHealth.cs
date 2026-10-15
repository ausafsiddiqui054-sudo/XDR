using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecurePulse.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddDefenderHealth : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "DefenderDetails",
                table: "managed_devices",
                type: "jsonb",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Warning",
                table: "device_sync_status",
                type: "character varying(2000)",
                maxLength: 2000,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DefenderDetails",
                table: "managed_devices");

            migrationBuilder.DropColumn(
                name: "Warning",
                table: "device_sync_status");
        }
    }
}
