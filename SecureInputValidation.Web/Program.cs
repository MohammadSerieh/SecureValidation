using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Data.SqlClient;
using SecureInputValidation.Services;
using SecureInputValidation.Helpers;
using BCrypt.Net; // for password hashing
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureInputValidation.Web.Data;

var builder = WebApplication.CreateBuilder(args);

// ✅ Connection string (TrustServerCertificate for dev)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Server=localhost;Database=SecureAppDb;Trusted_Connection=True;TrustServerCertificate=True;";

// 1) Add DbContext for Identity
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// 2) Add ASP.NET Identity services
builder.Services.AddDefaultIdentity<IdentityUser>(options =>
{
    options.SignIn.RequireConfirmedAccount = false; // set true if you want email confirmation
})
.AddEntityFrameworkStores<ApplicationDbContext>();

// 3) Keep your existing cookie auth for manual endpoints (optional during transition)
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login.html";
        options.LogoutPath = "/logout";
        options.AccessDeniedPath = "/access-denied.html";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    });

builder.Services.AddAuthorization();
builder.Services.AddRazorPages();

var app = builder.Build();

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

// ===== Manual auth services (still available) =====
var loginService = new SecureLoginService(connectionString);
var userService = new UserService(connectionString);

// ===== Manual LOGIN endpoint =====
app.MapPost("/login", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    string username = form["username"];
    string password = form["password"];

    if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        return Results.Content("❌ Username and password are required.", "text/html");

    if (!XssHelpers.IsValidXssInput(username) || !XssHelpers.IsValidXssInput(password))
        return Results.Content("❌ Potential XSS attack detected.", "text/html");

    if (!ValidationHelpers.IsValidInput(username) || !ValidationHelpers.IsValidInput(password, "!@#$%^&*?"))
        return Results.Content("❌ Invalid characters detected in input.", "text/html");

    if (!loginService.LoginUser(username, password))
        return Results.Content("❌ Invalid credentials.", "text/html");

    var userId = userService.FetchUserId(username);
    if (userId <= 0)
        return Results.Content("❌ User not found.", "text/html");

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
        new Claim(ClaimTypes.Name, username)
    };
    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);

    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

    return Results.Redirect("/dashboard");
});

// ===== Manual REGISTRATION endpoint =====
app.MapPost("/register", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    string username = form["username"];
    string password = form["password"];

    if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        return Results.Content("❌ Username and password are required.", "text/html");

    if (!XssHelpers.IsValidXssInput(username) || !XssHelpers.IsValidXssInput(password))
        return Results.Content("❌ Potential XSS attack detected.", "text/html");

    if (!ValidationHelpers.IsValidInput(username) || !ValidationHelpers.IsValidInput(password, "!@#$%^&*?"))
        return Results.Content("❌ Invalid characters detected in input.", "text/html");

    string hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

    const string insertQuery = "INSERT INTO Users (Username, PasswordHash) VALUES (@Username, @PasswordHash)";
    using (var connection = new SqlConnection(connectionString))
    using (var command = new SqlCommand(insertQuery, connection))
    {
        command.Parameters.AddWithValue("@Username", username);
        command.Parameters.AddWithValue("@PasswordHash", hashedPassword);
        connection.Open();
        try
        {
            command.ExecuteNonQuery();
        }
        catch (SqlException ex) when (ex.Number == 2627) // unique constraint violation
        {
            return Results.Content("❌ Username already exists.", "text/html");
        }
    }

    return Results.Content("✅ Registration successful. <a href='/login.html'>Login here</a>", "text/html");
});

// ===== Manual PROTECTED dashboard =====
app.MapGet("/dashboard", [Authorize] (ClaimsPrincipal user) =>
{
    var name = user.Identity?.Name ?? "unknown";
    return Results.Content($"✅ Welcome, {name}! This is a protected dashboard.", "text/html");
}).RequireAuthorization();

// ===== Manual LOGOUT =====
app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login.html");
});

// ===== Identity Razor Pages =====
app.MapRazorPages();

app.Run();
