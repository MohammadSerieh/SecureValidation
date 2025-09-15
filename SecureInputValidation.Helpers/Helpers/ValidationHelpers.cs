using System;
using System.Linq;

namespace SecureInputValidation.Helpers
{
    public static class ValidationHelpers
    {
        /// <summary>
        /// Validates that the input contains only letters, digits, and the specified allowed special characters.
        /// </summary>
        public static bool IsValidInput(string input, string allowedSpecialCharacters = "@#$")
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            var validCharacters = allowedSpecialCharacters.ToHashSet();
            return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
        }
    }
}
