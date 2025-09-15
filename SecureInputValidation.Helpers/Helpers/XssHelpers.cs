using System;
using System.Text.RegularExpressions;

namespace SecureInputValidation.Helpers
{
    public static class XssHelpers
    {
        /// <summary>
        /// Checks if input contains common XSS attack patterns.
        /// </summary>
        public static bool IsValidXssInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return true;

            string lower = input.ToLower();

            // Detect <script> or <iframe> tags
            if (lower.Contains("<script") || lower.Contains("<iframe"))
                return false;

            return true;
        }

        /// <summary>
        /// Removes potentially dangerous HTML tags like <script> and <iframe>.
        /// </summary>
        public static string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            // Remove <script>...</script> and <iframe>...</iframe> blocks
            string pattern = @"<script.*?>.*?</script>|<iframe.*?>.*?</iframe>";
            return Regex.Replace(input, pattern, string.Empty, RegexOptions.IgnoreCase | RegexOptions.Singleline);
        }

        /// <summary>
        /// Simple test method for XSS detection.
        /// </summary>
        public static void TestXssInput()
        {
            string maliciousInput = "<script>alert('XSS');</script>";
            bool isValid = IsValidXssInput(maliciousInput);

            Console.WriteLine(isValid ? "XSS Test Failed" : "XSS Test Passed");

            string cleaned = SanitizeInput(maliciousInput);
            Console.WriteLine($"Sanitized Output: {cleaned}");
        }
    }
}
