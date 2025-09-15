using System;
using System.Data.SqlClient;

namespace SecureInputValidation.Services
{
    public class UserService
    {
        private readonly string _connectionString;

        public UserService(string connectionString)
        {
            _connectionString = connectionString;
        }

        public void FetchUserData(string username)
        {
            const string query = "SELECT Id, Username FROM Users WHERE Username = @Username";

            using (var connection = new SqlConnection(_connectionString))
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@Username", username);

                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        int id = (int)reader["Id"];
                        string user = reader["Username"].ToString();

                        Console.WriteLine($"🆔 ID: {id}");
                        Console.WriteLine($"👤 Username: {user}");
                    }
                    else
                    {
                        Console.WriteLine("❌ User not found.");
                    }
                }
            }
        }

        public string FetchUserDataAsString(string username)
        {
            const string query = "SELECT Id, Username FROM Users WHERE Username = @Username";
            using (var connection = new SqlConnection(_connectionString))
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@Username", username);
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        int id = (int)reader["Id"];
                        string user = reader["Username"].ToString();
                        return $"🆔 ID: {id}<br>👤 Username: {user}";
                    }
                    else
                    {
                        return "❌ User not found.";
                    }
                }
            }
        }

    }
}
