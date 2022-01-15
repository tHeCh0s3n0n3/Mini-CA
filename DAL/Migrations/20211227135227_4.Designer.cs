﻿// <auto-generated />
using System;
using DAL;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace DAL.Migrations
{
    [DbContext(typeof(DB))]
    [Migration("20211227135227_4")]
    partial class _4
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder.HasAnnotation("ProductVersion", "6.0.1");

            modelBuilder.Entity("DAL.Models.CSR", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<string>("CommonName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("CountryCode")
                        .IsRequired()
                        .HasMaxLength(2)
                        .HasColumnType("TEXT")
                        .IsFixedLength();

                    b.Property<string>("EMailAddress")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<byte[]>("FileContents")
                        .IsRequired()
                        .HasColumnType("BLOB");

                    b.Property<string>("FileName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsSigned")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Locality")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Organization")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("OrganizationUnitName")
                        .HasColumnType("TEXT");

                    b.Property<string>("State")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("CSRs", (string)null);
                });

            modelBuilder.Entity("DAL.Models.SignedCSR", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<byte[]>("Certificate")
                        .IsRequired()
                        .HasColumnType("BLOB");

                    b.Property<DateTime>("NotAfter")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("NotBefore")
                        .HasColumnType("TEXT");

                    b.Property<Guid>("OriginalRequestId")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("SignedOn")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("SignedCSRs");
                });
#pragma warning restore 612, 618
        }
    }
}
