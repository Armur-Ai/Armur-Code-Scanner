// Java testdata: intentionally vulnerable patterns for scanner testing.
import java.sql.*;
import java.io.*;

public class Vulnerable {

    // CWE-89: SQL Injection — user input concatenated into query
    public static void sqlInjection(String userId) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        Statement stmt = conn.createStatement();
        // VULNERABLE: direct string concatenation
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }

    // CWE-798: Hardcoded credentials
    private static final String PASSWORD = "admin123";
    private static final String API_KEY = "AKIAIOSFODNN7EXAMPLE";

    // CWE-78: OS command injection
    public static void commandInjection(String filename) throws Exception {
        Runtime.getRuntime().exec("ls " + filename);
    }

    // CWE-22: Path traversal
    public static String readFile(String name) throws Exception {
        File f = new File("/var/data/" + name);
        return new String(new FileInputStream(f).readAllBytes());
    }

    // CWE-327: Use of broken/risky cryptographic algorithm
    public static void weakCrypto() throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES");
    }

    public static void main(String[] args) throws Exception {
        sqlInjection("1 OR 1=1");
        commandInjection("../etc/passwd");
        System.out.println(readFile("../secret"));
        weakCrypto();
    }
}
