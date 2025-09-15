using SecureInputValidation.Services;
using SecureInputValidation.Helpers;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Serve static files from wwwroot (your index.html)
app.UseStaticFiles();

string connectionString = "Server=localhost;Database=SecureAppDb;Trusted_Connection=True;";
var loginService = new SecureLoginService(connectionString);
var userService = new UserService(connectionString);

// Handle form POST from index.html
app.MapPost("/login", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    string username = form["username"];
    string password = form["password"];

    // XSS check
    if (!XssHelpers.IsValidXssInput(username) || !XssHelpers.IsValidXssInput(password))
        return Results.Content("❌ Potential XSS attack detected.", "text/html");

    // Whitelist validation
    if (!ValidationHelpers.IsValidInput(username) || !ValidationHelpers.IsValidInput(password, "!@#$%^&*?"))
        return Results.Content("❌ Invalid characters detected in input.", "text/html");

    // Login
    if (loginService.LoginUser(username, password))
    {
        // Fetch user data (modify UserService to return data instead of writing to console)
        var userData = userService.FetchUserDataAsString(username);
        return Results.Content($"✅ Login successful.<br>{userData}", "text/html");
    }
    else
    {
        return Results.Content("❌ Invalid credentials.", "text/html");
    }
});

app.Run();
