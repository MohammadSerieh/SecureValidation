using System.Data.SqlClient;
using SecureInputValidation.Helpers;

namespace SecureInputValidation.Services
{
    public class SecureLoginService
    {
        private readonly string _connectionString;

        public SecureLoginService(string connectionString)
        {
            _connectionString = connectionString;
        }

        public bool LoginUser(string username, string password)
        {
            string allowedSpecialCharacters = "!@#$%^&*?";

            // Validate input using your helper
            if (!ValidationHelpers.IsValidInput(username) ||
                !ValidationHelpers.IsValidInput(password, allowedSpecialCharacters))
                return false;

            const string query = "SELECT COUNT(1) FROM Users WHERE Username = @Username AND Password = @Password";

            using (var connection = new SqlConnection(_connectionString))
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@Username", username);
                command.Parameters.AddWithValue("@Password", password);

                connection.Open();
                int count = (int)command.ExecuteScalar();
                return count > 0;
            }
        }
    }
}
