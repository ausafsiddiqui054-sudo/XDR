using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecurePulse.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPlaybookPreApproval : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "DailyAutoLimit",
                table: "remediation_playbooks",
                type: "integer",
                nullable: false,
                defaultValue: 25);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "PreApprovalExpiresAt",
                table: "remediation_playbooks",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "PreApprovedAt",
                table: "remediation_playbooks",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PreApprovedByName",
                table: "remediation_playbooks",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "PreApprovedByUserId",
                table: "remediation_playbooks",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "AutoApproved",
                table: "device_actions",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DailyAutoLimit",
                table: "remediation_playbooks");

            migrationBuilder.DropColumn(
                name: "PreApprovalExpiresAt",
                table: "remediation_playbooks");

            migrationBuilder.DropColumn(
                name: "PreApprovedAt",
                table: "remediation_playbooks");

            migrationBuilder.DropColumn(
                name: "PreApprovedByName",
                table: "remediation_playbooks");

            migrationBuilder.DropColumn(
                name: "PreApprovedByUserId",
                table: "remediation_playbooks");

            migrationBuilder.DropColumn(
                name: "AutoApproved",
                table: "device_actions");
        }
    }
}
