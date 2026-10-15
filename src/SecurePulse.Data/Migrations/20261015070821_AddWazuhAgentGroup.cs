using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecurePulse.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddWazuhAgentGroup : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "WazuhAgentGroup",
                table: "tenants",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_tenants_WazuhAgentGroup",
                table: "tenants",
                column: "WazuhAgentGroup",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_tenants_WazuhAgentGroup",
                table: "tenants");

            migrationBuilder.DropColumn(
                name: "WazuhAgentGroup",
                table: "tenants");
        }
    }
}
