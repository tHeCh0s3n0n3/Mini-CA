using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DAL.Migrations
{
    /// <inheritdoc />
    public partial class AddIntermediateCAModel : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "IntermediateCAs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CountryCode = table.Column<string>(type: "TEXT", fixedLength: true, maxLength: 2, nullable: false),
                    Organization = table.Column<string>(type: "TEXT", nullable: false),
                    OrganizationUnitName = table.Column<string>(type: "TEXT", nullable: true),
                    CommonName = table.Column<string>(type: "TEXT", nullable: false),
                    Locality = table.Column<string>(type: "TEXT", nullable: true),
                    State = table.Column<string>(type: "TEXT", nullable: true),
                    EMailAddress = table.Column<string>(type: "TEXT", nullable: false),
                    CsrFileContents = table.Column<byte[]>(type: "BLOB", nullable: false),
                    FileName = table.Column<string>(type: "TEXT", nullable: false),
                    Certificate = table.Column<byte[]>(type: "BLOB", nullable: true),
                    EncryptedPrivateKey = table.Column<string>(type: "TEXT", nullable: true),
                    IsSigned = table.Column<bool>(type: "INTEGER", nullable: false),
                    SubmittedOn = table.Column<DateTime>(type: "TEXT", nullable: false),
                    SignedOn = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NotBefore = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NotAfter = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IntermediateCAs", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "IntermediateCAs");
        }
    }
}
