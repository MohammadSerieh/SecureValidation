using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureInputValidation.Web.Data;

var builder = WebApplication.CreateBuilder(args);

// ✅ Connection string
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Server=localhost;Database=SecureAppDb;Trusted_Connection=True;TrustServerCertificate=True;";

// 1) Add DbContext for Identity
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// 2) Add ASP.NET Identity with role support
builder.Services.AddDefaultIdentity<IdentityUser>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
})
.AddRoles<IdentityRole>()
.AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.AddAuthorization();
builder.Services.AddRazorPages();

var app = builder.Build();

// ===== Seed roles & assign roles to specific accounts =====
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

    // Seed roles
    string[] roleNames = { "Admin", "User" };
    foreach (var roleName in roleNames)
    {
        if (!await roleManager.RoleExistsAsync(roleName))
            await roleManager.CreateAsync(new IdentityRole(roleName));
    }

    // Assign Admin role
    var adminEmail = "mohammadbassem44@gmail.com";
    var adminUser = await userManager.FindByEmailAsync(adminEmail);
    if (adminUser != null && !await userManager.IsInRoleAsync(adminUser, "Admin"))
        await userManager.AddToRoleAsync(adminUser, "Admin");

    // Assign User role
    var normalEmail = "ahmed@example.com";
    var normalUser = await userManager.FindByEmailAsync(normalEmail);
    if (normalUser != null && !await userManager.IsInRoleAsync(normalUser, "User"))
        await userManager.AddToRoleAsync(normalUser, "User");
}

// ===== Middleware pipeline =====
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// ===== Role-protected dashboards =====
app.MapGet("/admin-dashboard", [Authorize(Roles = "Admin")] (ClaimsPrincipal user) =>
{
    var name = user.Identity?.Name ?? "unknown";
    return Results.Content($"👑 Welcome Admin {name}!", "text/html");
});

app.MapGet("/user-dashboard", [Authorize(Roles = "User")] (ClaimsPrincipal user) =>
{
    var name = user.Identity?.Name ?? "unknown";
    return Results.Content($"🙌 Welcome User {name}!", "text/html");
});

// ===== Identity Razor Pages =====
app.MapRazorPages();

app.Run();
