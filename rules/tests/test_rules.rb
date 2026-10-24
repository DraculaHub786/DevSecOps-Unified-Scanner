# Test fixture for Ruby security rules
require 'digest'

def bad_ruby(input)
  # ruleid: org-ruby-sql-injection
  ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = " + input)

  # ruleid: org-ruby-command-injection
  system("rm -rf " + input)

  # ruleid: org-ruby-unsafe-deserialization
  Marshal.load(input)

  # ruleid: org-ruby-weak-crypto-md5
  Digest::MD5.hexdigest(input)
end

def ok_ruby(input)
  # ok: org-ruby-sql-injection
  User.where(id: input)

  # ok: org-ruby-command-injection
  system("ls", "-la", input)

  # ok: org-ruby-weak-crypto-md5
  Digest::SHA256.hexdigest(input)
end
