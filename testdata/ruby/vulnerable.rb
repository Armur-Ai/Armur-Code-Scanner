# Ruby testdata: intentionally vulnerable patterns for scanner testing.

# CWE-89: SQL Injection via string interpolation
def find_user(id)
  ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = #{id}")
end

# CWE-78: OS command injection
def run_command(user_input)
  system("ls #{user_input}")
end

# CWE-798: Hardcoded credentials
PASSWORD = "hunter2"
SECRET_KEY = "abc123verysecret"

# CWE-22: Path traversal
def read_file(filename)
  File.read("/var/data/#{filename}")
end

# CWE-327: Weak cryptographic algorithm (MD5)
require 'digest'
def hash_password(pw)
  Digest::MD5.hexdigest(pw)
end

# CWE-502: Unsafe deserialization
def load_object(data)
  Marshal.load(data)
end
