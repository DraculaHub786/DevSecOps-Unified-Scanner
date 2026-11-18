import java.io.ObjectInputStream;
import java.sql.Statement;

public class Vuln {
    // TP: SQL injection via concatenation (CWE-89)
    public void findUser(Statement stmt, String id) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    // TP: command injection (CWE-78)
    public void ping(String host) throws Exception {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    // TP: unsafe deserialization (CWE-502)
    public Object loadState(ObjectInputStream stream) throws Exception {
        return stream.readObject();
    }

    // Negative: no concatenation into SQL
    public void findUserSafe(java.sql.PreparedStatement ps, String id) throws Exception {
        ps.setString(1, id);
    }
}
