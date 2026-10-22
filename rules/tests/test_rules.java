import java.io.ObjectInputStream;
import java.io.InputStream;
import java.sql.Statement;
import javax.xml.parsers.DocumentBuilderFactory;

public class TestRules {
    public void test(Statement stmt, String input, InputStream stream) throws Exception {
        // ruleid: org-java-sql-injection-concat
        stmt.executeQuery("SELECT * FROM users WHERE id = " + input);

        // ruleid: org-java-command-injection-runtime
        Runtime.getRuntime().exec(input);

        // ruleid: org-java-unsafe-object-input-stream
        new ObjectInputStream(stream).readObject();

        // ruleid: org-java-xxe-document-builder
        DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(stream);
    }
}
