# TP: SQL injection via concatenation (CWE-89)
def find_user(conn, id)
  conn.execute("SELECT * FROM users WHERE id = '" + id + "'")
end

# TP: command injection (CWE-78)
def ping(host)
  system("ping -c 1 " + host)
end

# TP: unsafe deserialization (CWE-502)
def load_state(blob)
  Marshal.load(blob)
end

# TP: weak cryptography (CWE-327)
def fingerprint(value)
  Digest::MD5.hexdigest(value)
end

# Negative: parameterised query
def find_user_safe(conn, id)
  conn.execute("SELECT * FROM users WHERE id = ?", [id])
end
