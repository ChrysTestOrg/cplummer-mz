terraform {
  backend "s3" {
    bucket       = "chpr-org-terraform-state-us-east-1"
    key          = "solutions/mz/infra-C2"
    region       = "us-east-1"
    use_lockfile = true
    profile      = "org"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  profile = "org"
  region  = "us-east-1"
}

#provider "aws" {
#  alias   = "logs"
#  profile = "logs"
#  region  = "us-east-1"
#}

provider "aws" {
  alias   = "member"
  profile = "member"
}
