using System;
using SecureInputValidation.Services;
using SecureInputValidation.Helpers;

class Program
{
    static void Main()
    {
        string connectionString = "Server=localhost;Database=SecureAppDb;Trusted_Connection=True;";
        var loginService = new SecureLoginService(connectionString);
        var userService = new UserService(connectionString);

        Console.WriteLine("=== Secure Login System ===");
        Console.WriteLine("Type 'exit' at any prompt to quit.\n");

        while (true)
        {
            Console.Write("Username: ");
            var username = Console.ReadLine();

            if (string.Equals(username, "exit", StringComparison.OrdinalIgnoreCase))
                break;

            Console.Write("Password: ");
            var password = Console.ReadLine();

            if (string.Equals(password, "exit", StringComparison.OrdinalIgnoreCase))
                break;


            // ✅ XSS protection
            if (!XssHelpers.IsValidXssInput(username) || !XssHelpers.IsValidXssInput(password))
            {
                Console.WriteLine("❌ Potential XSS attack detected.");
                continue;
            }


            // ✅ Input validation
            if (!ValidationHelpers.IsValidInput(username) ||
                !ValidationHelpers.IsValidInput(password, "!@#$%^&*?"))
            {
                Console.WriteLine("❌ Invalid characters detected in input.");
                continue;
            }


            // ✅ Login attempt
            if (loginService.LoginUser(username, password))
            {
                Console.WriteLine("✅ Login successful.");
                userService.FetchUserData(username);
            }
            else
            {
                Console.WriteLine("❌ Invalid credentials.");
            }
        }

        Console.WriteLine("\n👋 Goodbye!");
    }
}
