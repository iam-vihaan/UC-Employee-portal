terraform {
  backend "s3" {
    bucket       = "kasi-hcl-bucket-uc8"
    key          = "kasi-bucket/terraform.tftstate"
    region       = "us-east-1"
    use_lockfile = false
  }
}
