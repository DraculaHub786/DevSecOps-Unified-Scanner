resource "aws_s3_bucket" "public_bucket" {
  bucket = "vulnerable-company-public-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open_ssh" {
  name        = "open-ssh-sg"
  description = "Security group with open SSH ingress"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
