using System;
using System.Data.SqlClient;
using System.Security.Cryptography;

public class SafeApp {
    public void QueryUser(SqlConnection conn, int userId) {
        using (var cmd = new SqlCommand("SELECT id, name FROM users WHERE id = @id", conn)) {
            cmd.Parameters.AddWithValue("@id", userId);
            using (var reader = cmd.ExecuteReader()) {
                while (reader.Read()) {
                    Console.WriteLine(reader["name"]);
                }
            }
        }
    }

    public byte[] HashData(byte[] input) {
        using (var sha = SHA256.Create()) {
            return sha.ComputeHash(input);
        }
    }
}
