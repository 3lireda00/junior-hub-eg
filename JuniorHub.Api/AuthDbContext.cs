using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JuniorHub.Api;

public sealed class AppUser : IdentityUser<Guid>
{
    public string FullName { get; set; } = "";
    public string Role { get; set; } = "";
    public DateOnly? DateOfBirth { get; set; }
    public string? LearningInterest { get; set; }
    public string? GuardianName { get; set; }
    public string? GuardianEmail { get; set; }
    public string? LearnerName { get; set; }
    public DateTimeOffset? TermsAcceptedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options)
    : IdentityDbContext<AppUser, IdentityRole<Guid>, Guid>(options)
{
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<AppUser>(entity =>
        {
            entity.Property(u => u.FullName).HasMaxLength(120).IsRequired();
            entity.Property(u => u.Role).HasMaxLength(20).IsRequired();
            entity.Property(u => u.GuardianName).HasMaxLength(120);
            entity.Property(u => u.GuardianEmail).HasMaxLength(254);
            entity.Property(u => u.LearnerName).HasMaxLength(120);
            entity.Property(u => u.LearningInterest).HasMaxLength(100);
            entity.HasIndex(u => u.Email).IsUnique();
        });
    }
}
