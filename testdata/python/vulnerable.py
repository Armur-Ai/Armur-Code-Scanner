"""Intentionally insecure Python code for testing purposes."""
import hashlib
import os
import pickle
import subprocess


# CWE-798: Hardcoded credential
HARDCODED_PASSWORD = "super_secret_password"


def sql_injection(conn, user_input):
    """CWE-89: SQL injection via string formatting."""
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '%s'" % user_input
    cursor.execute(query)
    return cursor.fetchall()


def command_injection(user_input):
    """CWE-78: OS command injection."""
    return subprocess.check_output("ls " + user_input, shell=True)


def weak_hash(password):
    """CWE-327: Use of broken MD5 hash algorithm."""
    return hashlib.md5(password.encode()).hexdigest()


def path_traversal(user_path):
    """CWE-22: Path traversal via unsanitized user input."""
    base = "/var/data/"
    return open(base + user_path).read()


def insecure_deserialization(data):
    """CWE-502: Deserialization of untrusted data."""
    return pickle.loads(data)


def xml_injection(user_input):
    """CWE-611: XML External Entity via lxml without safe parsing."""
    import lxml.etree as ET
    parser = ET.XMLParser(resolve_entities=True)
    return ET.fromstring(user_input, parser)


def no_docstring_function(x, y):
    return x + y
