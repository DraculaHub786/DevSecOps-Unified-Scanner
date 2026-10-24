# Safe Ruby application file
require 'digest'

def get_user(user_id)
  User.where(id: user_id.to_i).first
end

def secure_hash(content)
  Digest::SHA256.hexdigest(content)
end
