import java.io.File;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.sql.Statement;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.directory.DirContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin("*")
public class TestRules {
    public void test(Statement stmt, String input, InputStream stream, HttpServletResponse resp, Cookie cookie, DirContext ctx) throws Exception {
        // ruleid: org-java-sql-injection-concat
        stmt.executeQuery("SELECT * FROM users WHERE id = " + input);

        // ruleid: org-java-command-injection-runtime
        Runtime.getRuntime().exec(input);

        // ruleid: org-java-unsafe-object-input-stream
        new ObjectInputStream(stream).readObject();

        // ruleid: org-java-xxe-document-builder
        DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(stream);

        // ruleid: org-java-spring-cors-wildcard
        // @CrossOrigin("*")

        // ruleid: org-java-jackson-unsafe-deserialization
        mapper.enableDefaultTyping();

        // ruleid: org-java-path-traversal-file
        new File("/base/dir", input);

        // ruleid: org-java-hardcoded-crypto-key
        new SecretKeySpec("hardcoded-key-12".getBytes(), "AES");

        // ruleid: org-java-ldap-injection
        ctx.search("dc=example,dc=com", "(uid=" + input, null);

        // ruleid: org-java-open-redirect
        resp.sendRedirect(input);

        // ruleid: org-java-cookie-missing-httponly-secure
        cookie.setHttpOnly(false);

        // ruleid: org-java-ssti-thymeleaf
        engine.process(input, context);

        // ruleid: org-cors-wildcard-header
        resp.setHeader("Access-Control-Allow-Origin", "*");

        // ruleid: org-jwt-none-algorithm
        Algorithm.none();
    }
}

