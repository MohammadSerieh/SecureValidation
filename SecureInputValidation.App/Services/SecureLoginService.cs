using Microsoft.Data.SqlClient;
using SecureInputValidation.Helpers;
using BCrypt.Net;


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
            const string query = "SELECT PasswordHash FROM Users WHERE Username = @Username";
            using (var connection = new SqlConnection(_connectionString))
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@Username", username);
                connection.Open();
                var result = command.ExecuteScalar();
                if (result == null) return false;

                string storedHash = result.ToString();
                return BCrypt.Net.BCrypt.Verify(password, storedHash);
            }
        }

    }
}
