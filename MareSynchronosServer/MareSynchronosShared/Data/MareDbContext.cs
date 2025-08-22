using MareSynchronosShared.Models;
using Microsoft.EntityFrameworkCore;

namespace MareSynchronosShared.Data;

public class MareDbContext : DbContext
{
#if DEBUG
    public MareDbContext() { }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (optionsBuilder.IsConfigured)
        {
            base.OnConfiguring(optionsBuilder);
            return;
        }

        optionsBuilder.UseNpgsql("Host=localhost;Port=5432;Database=mare;Username=postgres", builder =>
        {
            builder.MigrationsHistoryTable("_efmigrationshistory", "public");
            builder.MigrationsAssembly("MareSynchronosShared");
        }).UseSnakeCaseNamingConvention();
        optionsBuilder.EnableThreadSafetyChecks(false);

        base.OnConfiguring(optionsBuilder);
    }
#endif

    public MareDbContext(DbContextOptions<MareDbContext> options) : base(options)
    {
    }

    public DbSet<Auth> Auth { get; set; }
    public DbSet<BannedRegistrations> BannedRegistrations { get; set; }
    public DbSet<Banned> BannedUsers { get; set; }
    public DbSet<ClientPair> ClientPairs { get; set; }
    public DbSet<FileCache> Files { get; set; }
    public DbSet<ForbiddenUploadEntry> ForbiddenUploadEntries { get; set; }
    public DbSet<GroupBan> GroupBans { get; set; }
    public DbSet<GroupPair> GroupPairs { get; set; }
    public DbSet<Group> Groups { get; set; }
    public DbSet<GroupTempInvite> GroupTempInvites { get; set; }
    public DbSet<LodeStoneAuth> LodeStoneAuth { get; set; }
    public DbSet<UserProfileData> UserProfileData { get; set; }
    public DbSet<UserProfileDataReport> UserProfileReports { get; set; }
    public DbSet<User> Users { get; set; }
    public DbSet<CharaData> CharaData { get; set; }
    public DbSet<CharaDataFile> CharaDataFiles { get; set; }
    public DbSet<CharaDataFileSwap> CharaDataFileSwaps { get; set; }
    public DbSet<CharaDataOriginalFile> CharaDataOriginalFiles { get; set; }
    public DbSet<CharaDataPose> CharaDataPoses { get; set; }
    public DbSet<CharaDataAllowance> CharaDataAllowances { get; set; }

    protected override void OnModelCreating(ModelBuilder mb)
    {
        mb.Entity<Auth>().ToTable("auth");
        mb.Entity<User>().ToTable("users");
        mb.Entity<FileCache>().ToTable("file_caches");
        mb.Entity<FileCache>().HasIndex(c => c.UploaderUID);
        mb.Entity<ClientPair>().ToTable("client_pairs");
        mb.Entity<ClientPair>().HasKey(u => new { u.UserUID, u.OtherUserUID });
        mb.Entity<ClientPair>().HasIndex(c => c.UserUID);
        mb.Entity<ClientPair>().HasIndex(c => c.OtherUserUID);
        mb.Entity<ForbiddenUploadEntry>().ToTable("forbidden_upload_entries");
        mb.Entity<Banned>().ToTable("banned_users");
        mb.Entity<LodeStoneAuth>().ToTable("lodestone_auth");
        mb.Entity<BannedRegistrations>().ToTable("banned_registrations");
        mb.Entity<Group>().ToTable("groups");
        mb.Entity<Group>().HasIndex(c => c.OwnerUID);
        mb.Entity<GroupPair>().ToTable("group_pairs");
        mb.Entity<GroupPair>().HasKey(u => new { u.GroupGID, u.GroupUserUID });
        mb.Entity<GroupPair>().HasIndex(c => c.GroupUserUID);
        mb.Entity<GroupPair>().HasIndex(c => c.GroupGID);
        mb.Entity<GroupBan>().ToTable("group_bans");
        mb.Entity<GroupBan>().HasKey(u => new { u.GroupGID, u.BannedUserUID });
        mb.Entity<GroupBan>().HasIndex(c => c.BannedUserUID);
        mb.Entity<GroupBan>().HasIndex(c => c.GroupGID);
        mb.Entity<GroupTempInvite>().ToTable("group_temp_invites");
        mb.Entity<GroupTempInvite>().HasKey(u => new { u.GroupGID, u.Invite });
        mb.Entity<GroupTempInvite>().HasIndex(c => c.GroupGID);
        mb.Entity<GroupTempInvite>().HasIndex(c => c.Invite);
        mb.Entity<UserProfileData>().ToTable("user_profile_data");
        mb.Entity<UserProfileData>().HasKey(c => c.UserUID);
        mb.Entity<UserProfileDataReport>().ToTable("user_profile_data_reports");
        mb.Entity<CharaData>().ToTable("chara_data");
        mb.Entity<CharaData>()
            .HasMany(p => p.Poses)
            .WithOne(c => c.Parent)
            .HasForeignKey(c => new { c.ParentId, c.ParentUploaderUID });
        mb.Entity<CharaData>()
            .HasMany(p => p.Files)
            .WithOne(c => c.Parent)
            .HasForeignKey(c => new { c.ParentId, c.ParentUploaderUID });
        mb.Entity<CharaData>()
            .HasMany(p => p.OriginalFiles)
            .WithOne(p => p.Parent)
            .HasForeignKey(p => new { p.ParentId, p.ParentUploaderUID });
        mb.Entity<CharaData>()
            .HasMany(p => p.AllowedIndividiuals)
            .WithOne(p => p.Parent)
            .HasForeignKey(p => new { p.ParentId, p.ParentUploaderUID });
        mb.Entity<CharaData>()
            .HasMany(p => p.FileSwaps)
            .WithOne(p => p.Parent)
            .HasForeignKey(p => new { p.ParentId, p.ParentUploaderUID });
        mb.Entity<CharaData>().HasKey(p => new { p.Id, p.UploaderUID });
        mb.Entity<CharaData>().HasIndex(p => p.UploaderUID);
        mb.Entity<CharaData>().HasIndex(p => p.Id);
        mb.Entity<CharaDataFile>().ToTable("chara_data_files");
        mb.Entity<CharaDataFile>().HasKey(c => new { c.ParentId, c.ParentUploaderUID, c.GamePath });
        mb.Entity<CharaDataFile>().HasIndex(c => c.ParentId);
        mb.Entity<CharaDataFile>().HasOne(f => f.FileCache).WithMany().HasForeignKey(f => f.FileCacheHash).OnDelete(DeleteBehavior.Cascade);
        mb.Entity<CharaDataFileSwap>().ToTable("chara_data_file_swaps");
        mb.Entity<CharaDataFileSwap>().HasKey(c => new { c.ParentId, c.ParentUploaderUID, c.GamePath });
        mb.Entity<CharaDataFileSwap>().HasIndex(c => c.ParentId);
        mb.Entity<CharaDataPose>().ToTable("chara_data_poses");
        mb.Entity<CharaDataPose>().Property(p => p.Id).ValueGeneratedOnAdd();
        mb.Entity<CharaDataPose>().HasKey(c => new { c.ParentId, c.ParentUploaderUID, c.Id });
        mb.Entity<CharaDataPose>().HasIndex(c => c.ParentId);
        mb.Entity<CharaDataOriginalFile>().ToTable("chara_data_orig_files");
        mb.Entity<CharaDataOriginalFile>().HasKey(c => new { c.ParentId, c.ParentUploaderUID, c.GamePath });
        mb.Entity<CharaDataOriginalFile>().HasIndex(c => c.ParentId);
        mb.Entity<CharaDataAllowance>().ToTable("chara_data_allowance");
        mb.Entity<CharaDataAllowance>().HasKey(c => new { c.ParentId, c.ParentUploaderUID, c.Id });
        mb.Entity<CharaDataAllowance>().Property(p => p.Id).ValueGeneratedOnAdd();
        mb.Entity<CharaDataAllowance>().HasIndex(c => c.ParentId);
        mb.Entity<CharaDataAllowance>().HasOne(u => u.AllowedGroup).WithMany().HasForeignKey(u => u.AllowedGroupGID).OnDelete(DeleteBehavior.Cascade);
        mb.Entity<CharaDataAllowance>().HasOne(u => u.AllowedUser).WithMany().HasForeignKey(u => u.AllowedUserUID).OnDelete(DeleteBehavior.Cascade);
    }
}