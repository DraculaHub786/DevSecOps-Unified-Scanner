resource "aws_security_group" "safe" {
  name        = "internal-app"
  description = "Internal service traffic only"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
