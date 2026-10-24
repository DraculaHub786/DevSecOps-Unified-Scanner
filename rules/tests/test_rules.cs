using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

public class TestCSharp {
    public void Bad(string input, Stream stream) {
        // ruleid: org-csharp-sql-injection
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + input);

        // ruleid: org-csharp-command-injection
        Process.Start(input);

        // ruleid: org-csharp-unsafe-deserialization
        var bf = new BinaryFormatter();
        bf.Deserialize(stream);

        // ruleid: org-csharp-weak-crypto-md5
        MD5.Create();
    }

    public void Ok(string input) {
        // ok: org-csharp-sql-injection
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id");
        cmd.Parameters.AddWithValue("@id", input);

        // ok: org-csharp-weak-crypto-md5
        SHA256.Create();
    }
}
