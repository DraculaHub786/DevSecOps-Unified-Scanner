import java.sql.*;
import java.security.MessageDigest;
import javax.crypto.SecretKeySpec;

public class App {
    // SQLi - string concat
    public void q1(Connection c, String id) throws Exception {
        c.createStatement().executeQuery("SELECT * FROM t WHERE id=" + id);
    }

    // Weak crypto
    public byte[] h(String s) throws Exception {
        return MessageDigest.getInstance("MD5").digest(s.getBytes());
    }

    // Hardcoded key
    private static final String KEY = "1234567890123456";
    public SecretKeySpec k() {
        return new SecretKeySpec(KEY.getBytes(), "AES");
    }

    // XXE
    public void xx() throws Exception {
        javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder().parse("/tmp/x");
    }
}
