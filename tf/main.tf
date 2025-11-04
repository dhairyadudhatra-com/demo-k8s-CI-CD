module "stackgen_0fd32e9d-4d5c-4d8c-b9b7-4102c97743f1" {
  source                = "./modules/aws_ec2"
  ami                   = "ami-0287a05f0ef0e9d9a"
  enable_public_ip      = true
  instance_type         = "t2.micro"
  key_name              = "ec2wordpress"
  root_volume_encrypted = true
  root_volume_size      = 20
  root_volume_type      = "gp2"
  security_group_ids    = ["module.stackgen_66c7e664-ce50-4966-935e-543a1da150fd.security_group_id"]
  subnet_id             = "module.stackgen_bdf2a6ee-bb87-4bb5-8274-d71368bd5649.id"
  tags = {
    createdBy = "Abhishes"
  }
  user_data = "#!/bin/bash # Update system dnf update -y dnf install -y httpd wget php php-mysqlnd mysql  # Start and enable Apache systemctl start httpd systemctl enable httpd  # Install WordPress wget https://wordpress.org/latest.tar.gz tar -xzf latest.tar.gz cp -r wordpress/* /var/www/html/  # Set permissions chown -R apache:apache /var/www/html/ chmod -R 755 /var/www/html/  # Create wp-config.php cd /var/www/html cp wp-config-sample.php wp-config.php  # Update WordPress configuration with hardcoded values sed -i \"s/database_name_here/wordpress/\" wp-config.php sed -i \"s/username_here/wordpress/\" wp-config.php sed -i \"s/password_here/WordPress123\\$#/\" wp-config.php sed -i \"s/localhost/terraform-20250917141927337400000002.c1aeawaso93q.ap-south-1.rds.amazonaws.com/\" wp-config.php  # Restart Apache systemctl restart httpd"
}

module "stackgen_c6cea84b-4743-4633-8675-74c9ebd05d32" {
  source                = "./modules/aws_iam_role"
  assume_role_policy    = "{\n    \"hello\": \"world\"\n}"
  description           = null
  force_detach_policies = true
  inline_policy         = []
  max_session_duration  = null
  name                  = null
  path                  = null
  permissions_boundary  = null
  tags                  = {}
}

