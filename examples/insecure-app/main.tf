# DELIBERATELY INSECURE test fixture for VulnSight AI.
resource "aws_s3_bucket" "public_data" {
  bucket = "example-public-data"
  acl    = "public-read"
}

resource "aws_security_group" "open" {
  name = "allow-all"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
