using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecurePulse.Data.Migrations
{
    /// <summary>
    /// Audit retention. audit_events stays append-only for the application's role. One NOLOGIN role,
    /// securepulse_audit_purge, may delete rows, and only rows older than 90 days (the floor in
    /// AuditRetention.Minimum). The Worker's maintenance login is a member and switches to it with
    /// SET LOCAL ROLE for each batch. UPDATE and TRUNCATE stay blocked for everyone.
    /// </summary>
    public partial class AllowAuditRetention : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger
                LANGUAGE plpgsql AS $$
                BEGIN
                    -- Retention only: the purge role, row deletes, rows older than the floor.
                    IF TG_OP = 'DELETE' AND TG_LEVEL = 'ROW'
                       AND current_user = 'securepulse_audit_purge'
                       AND OLD."OccurredAt" < now() - interval '90 days' THEN
                        RETURN OLD;
                    END IF;
                    RAISE EXCEPTION 'audit_events is append-only (% blocked)', TG_OP
                        USING ERRCODE = 'insufficient_privilege';
                END;
                $$;
                """);

            // Roles are cluster-wide and need CREATEROLE, which a managed database's application role
            // usually lacks. Then the role is created by an administrator (see README) and this skips.
            migrationBuilder.Sql("""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'securepulse_audit_purge') THEN
                        BEGIN
                            CREATE ROLE securepulse_audit_purge NOLOGIN;
                        EXCEPTION
                            WHEN insufficient_privilege THEN
                                RAISE NOTICE 'No CREATEROLE: create securepulse_audit_purge manually to enable audit retention.';
                            WHEN duplicate_object OR unique_violation THEN
                                NULL; -- created concurrently by another database's migration
                        END;
                    END IF;
                    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'securepulse_audit_purge') THEN
                        GRANT SELECT, DELETE ON audit_events TO securepulse_audit_purge;
                    END IF;
                END;
                $$;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger
                LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_events is append-only (% blocked)', TG_OP
                        USING ERRCODE = 'insufficient_privilege';
                END;
                $$;

                DO $$
                BEGIN
                    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'securepulse_audit_purge') THEN
                        REVOKE ALL ON audit_events FROM securepulse_audit_purge;
                    END IF;
                END;
                $$;
                """);
        }
    }
}
