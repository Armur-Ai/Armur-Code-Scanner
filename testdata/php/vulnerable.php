<?php
// PHP testdata: intentionally vulnerable patterns for scanner testing.

// CWE-89: SQL Injection
function getUserById($id) {
    $db = new PDO('mysql:host=localhost;dbname=test', 'root', '');
    $result = $db->query("SELECT * FROM users WHERE id = " . $id);
    return $result->fetchAll();
}

// CWE-79: XSS — unsanitized output
function displayName($name) {
    echo "<h1>Hello, " . $name . "!</h1>";
}

// CWE-78: Command injection
function runPing($host) {
    system("ping -c 1 " . $host);
}

// CWE-798: Hardcoded credentials
define('DB_PASSWORD', 'secret123');
$apiKey = 'hardcoded-api-key-value';

// CWE-22: Path traversal
function readConfig($file) {
    return file_get_contents('/var/www/config/' . $file);
}

// CWE-502: Unsafe deserialization
function loadSession($data) {
    return unserialize($data);
}
?>
