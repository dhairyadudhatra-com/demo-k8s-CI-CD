terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

resource "aws_iam_role" "eks-iam-role" {
  name               = "eks-terraform-iam-role"
  assume_role_policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "eks.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
POLICY

  tags = {
    project = "eks-demo"
  }
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks-iam-role.name
}

#VPC Creation
resource "aws_vpc" "eks-demo-terraform-vpc" {
  cidr_block           = "192.168.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name    = "eks-vpc"
    project = "eks-demo"
  }
}

#Subnets: 1-Public 1-Private
resource "aws_subnet" "eks-demo-terraform-publicSubnet" {
  vpc_id            = aws_vpc.eks-demo-terraform-vpc.id
  cidr_block        = "192.168.1.0/24"
  availability_zone = "us-west-2a"
  map_public_ip_on_launch = true
  tags = {
    Name    = "eks-publicSubnet"
    project = "eks-demo"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "eks-demo-terraform-publicSubnet2" {
  vpc_id            = aws_vpc.eks-demo-terraform-vpc.id
  cidr_block        = "192.168.4.0/24"
  availability_zone = "us-west-2d"
  map_public_ip_on_launch = true
  tags = {
    Name    = "eks-publicSubnet2"
    project = "eks-demo"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "eks-demo-terraform-privateSubnet1" {
  vpc_id            = aws_vpc.eks-demo-terraform-vpc.id
  cidr_block        = "192.168.2.0/24"
  availability_zone = "us-west-2b"
  tags = {
    Name    = "eks-privateSubnet1"
    project = "eks-demo"
  }
}
resource "aws_subnet" "eks-demo-terraform-privateSubnet2" {
  vpc_id            = aws_vpc.eks-demo-terraform-vpc.id
  cidr_block        = "192.168.3.0/24"
  availability_zone = "us-west-2c"
  tags = {
    Name    = "eks-privateSubnet2"
    project = "eks-demo"
  }
}

#Internet Gateway
resource "aws_internet_gateway" "eks-demo-terraform-internetGateway" {
  vpc_id = aws_vpc.eks-demo-terraform-vpc.id
  tags = {
    Name    = "eks-internetGateway"
    project = "eks-demo"
  }
}

resource "aws_eip" "eks-demo-terraform-nat-gateway" {
  vpc = true
  tags = {
    Name    = "eks-nat-gateway"
    project = "eks-demo"
  }
}

#Add NAT gateway
resource "aws_nat_gateway" "eks-demo-terraform-natGateway" {
  allocation_id = aws_eip.eks-demo-terraform-nat-gateway.id
  subnet_id     = aws_subnet.eks-demo-terraform-publicSubnet.id
  tags = {
    Name    = "eks-natGateway"
    project = "eks-demo"
  }
}

#Second route table for public subnet enables internet acces
resource "aws_route_table" "eks-demo-terraform-routeTable2" {
  vpc_id = aws_vpc.eks-demo-terraform-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.eks-demo-terraform-internetGateway.id
  }
  tags = {
    Name    = "eks-routeTable-public"
    project = "eks-demo"
  }
}

#Associate Publc Subnet with Second RouteTable
resource "aws_route_table_association" "eks-demo-terraform-publicSubnet-Association" {
  subnet_id      = aws_subnet.eks-demo-terraform-publicSubnet.id
  route_table_id = aws_route_table.eks-demo-terraform-routeTable2.id
}

#Associate Publc Subnet with Second RouteTable
resource "aws_route_table_association" "eks-demo-terraform-publicSubnet2-Association" {
  subnet_id      = aws_subnet.eks-demo-terraform-publicSubnet2.id
  route_table_id = aws_route_table.eks-demo-terraform-routeTable2.id
}

#Private Subnet Route Table
resource "aws_route_table" "eks-demo-terraform-private-subnet-routeTable1" {
  vpc_id = aws_vpc.eks-demo-terraform-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.eks-demo-terraform-natGateway.id
  }
  tags = {
    Name    = "eks-routeTable-private"
    project = "eks-demo"
  }
}

#Private Subnet Route Table Association
resource "aws_route_table_association" "eks-demo-terraform-privateSubnet1-Association" {
  subnet_id      = aws_subnet.eks-demo-terraform-privateSubnet1.id
  route_table_id = aws_route_table.eks-demo-terraform-private-subnet-routeTable1.id
}

resource "aws_route_table_association" "eks-demo-terraform-privateSubnet2-Association" {
  subnet_id      = aws_subnet.eks-demo-terraform-privateSubnet2.id
  route_table_id = aws_route_table.eks-demo-terraform-private-subnet-routeTable1.id
}

#KMS Creation Symmetric
resource "aws_kms_key" "eks-demo-terraform-kms-key" {
  description         = "This key is used to encrypt demo k8s cluster secrets"
  key_usage           = "ENCRYPT_DECRYPT"
  enable_key_rotation = true
  tags = {
    project = "eks-demo"
  }
}

output "KMS_ARN" {
  value       = aws_kms_key.eks-demo-terraform-kms-key.arn
  description = "KMS key ARN for secrets encryption"
}


resource "aws_eks_cluster" "eks-cluster-devops" {
  name     = "terraform-eks-cluster"
  role_arn = aws_iam_role.eks-iam-role.arn
  version  = "1.30"
  vpc_config {
    subnet_ids              = [aws_subnet.eks-demo-terraform-privateSubnet1.id, aws_subnet.eks-demo-terraform-privateSubnet2.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  access_config {
    authentication_mode = "API_AND_CONFIG_MAP"
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks-demo-terraform-kms-key.arn
    }
  }

  tags = {
    Name    = "terraform-eks-cluster"
    project = "eks-demo"
  }
  depends_on = [
    aws_iam_role.eks-iam-role
  ]
}

data "tls_certificate" "eks" {
  url = aws_eks_cluster.eks-cluster-devops.identity[0].oidc[0].issuer
}

#Creating OIDC Identity Provider
resource "aws_iam_openid_connect_provider" "eks_terraform_demo_OIDC" {
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  client_id_list = ["sts.amazonaws.com"]
  url = aws_eks_cluster.eks-cluster-devops.identity[0].oidc[0].issuer

  tags = {
    project = "eks-demo"
  }
}

# Adding Root as EKS Access Entry
resource "aws_eks_access_entry" "Root_User_Access" {
  cluster_name  = aws_eks_cluster.eks-cluster-devops.name
  principal_arn = "arn:aws:iam::264745370841:root"
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "eks_terraform_root_cluster_admin" {
    cluster_name = aws_eks_cluster.eks-cluster-devops.name
    policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
    principal_arn = "arn:aws:iam::264745370841:root"
    access_scope {
        type = "cluster"
    }
}

# Adding Admin User as EKS Access Entry
resource "aws_eks_access_entry" "Admin_User_Access" {
  cluster_name  = aws_eks_cluster.eks-cluster-devops.name
  principal_arn = "arn:aws:iam::264745370841:user/personalk8s"
  type          = "STANDARD"
}
resource "aws_eks_access_policy_association" "eks_terraform_adminuser_cluster_admin" {
    cluster_name = aws_eks_cluster.eks-cluster-devops.name
    policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
    principal_arn = "arn:aws:iam::264745370841:user/personalk8s"
    access_scope {
        type = "cluster"
    }
}



resource "aws_iam_role" "eks_worker_nodes_role" {
  name               = "eks-worker-nodes-role"
  assume_role_policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_worker_nodes_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_worker_nodes_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_worker_nodes_role.name
}

resource "aws_eks_node_group" "eks-worker-node-group" {
  cluster_name    = aws_eks_cluster.eks-cluster-devops.name
  node_group_name = "eks-worker-node-group"
  node_role_arn   = aws_iam_role.eks_worker_nodes_role.arn
  instance_types  = ["t3.medium"]
  disk_size       = 20
  scaling_config {
    desired_size = 3
    max_size     = 5
    min_size     = 3
  }
  update_config {
    max_unavailable = 1
  }
  ami_type      = "AL2_x86_64"
  capacity_type = "ON_DEMAND"
  subnet_ids    = [aws_subnet.eks-demo-terraform-privateSubnet1.id, aws_subnet.eks-demo-terraform-privateSubnet2.id]
  tags = {
    Name = "terraform-eks-worker-nodes"
  }
  depends_on = [
    aws_iam_role.eks_worker_nodes_role
  ]
}

resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.eks-cluster-devops.name
  addon_name   = "coredns"
  depends_on = [
    aws_eks_node_group.eks-worker-node-group
  ]
}

resource "aws_eks_addon" "kube-proxy" {
  cluster_name = aws_eks_cluster.eks-cluster-devops.name
  addon_name   = "kube-proxy"
  depends_on = [
    aws_eks_node_group.eks-worker-node-group
  ]
}

resource "aws_eks_addon" "vpc-cni" {
  cluster_name = aws_eks_cluster.eks-cluster-devops.name
  addon_name   = "vpc-cni"
  depends_on = [
    aws_eks_node_group.eks-worker-node-group
  ]
}

module "iam_assumable_role_with_oidc" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"

  create_role = true

  role_name = "eks-terraform-EBSdriver-addon-Role"

  tags = {
    Role = "role-with-oidc",
    project = "eks-demo"
  }

  # provider_url = "oidc.eks.eu-west-1.amazonaws.com/id/BA9E170D464AF7B92084EF72A69B9DC8"
  provider_url = aws_eks_cluster.eks-cluster-devops.identity[0].oidc[0].issuer

  role_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  ]
  number_of_role_policy_arns = 1
}

#Create a IAM Custom policy
resource "aws_iam_policy" "eks-terraform-KMS-EBSdriver-policy" {
  name        = "eks-terraform-KMS-EBSdriver-policy"
  path        = "/"
  description = "eks-terraform-KMS-EBSdriver-policy"
  policy      = jsonencode({

  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ]
      "Resource": aws_kms_key.eks-demo-terraform-kms-key.arn
      "Condition": {
        "Bool": {
          "kms:GrantIsForAWSResource": "true"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": aws_kms_key.eks-demo-terraform-kms-key.arn 
    }
  ]
})
}

#Add above policy to a role
resource "aws_iam_role_policy_attachment" "eks-terraform-KMS-EBSdriver-policy-attach" {
  role       = module.iam_assumable_role_with_oidc.iam_role_name
  policy_arn = aws_iam_policy.eks-terraform-KMS-EBSdriver-policy.arn
}

//EBS Driver Addon
resource "aws_eks_addon" "ebs-csi" {
  cluster_name = aws_eks_cluster.eks-cluster-devops.name
  addon_name   = "aws-ebs-csi-driver"
  service_account_role_arn = module.iam_assumable_role_with_oidc.iam_role_arn
  depends_on = [
    aws_eks_node_group.eks-worker-node-group
  ]
}

# module "LB_Controller_IAM_Role" {
#   source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"

#   create_role = true

#   role_name = "eks-terraform-LB-Controller"

#   tags = {
#     Role = "role-with-oidc-lb-controller",
#     project = "eks-demo"
#   }

#   # provider_url = "oidc.eks.eu-west-1.amazonaws.com/id/BA9E170D464AF7B92084EF72A69B9DC8"
#   provider_url = aws_eks_cluster.eks-cluster-devops.identity[0].oidc[0].issuer

#   role_policy_arns = [
#     # "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
#   ]
#   number_of_role_policy_arns = 1
# }

resource "aws_iam_role" "LB_Controller_IAM_Role" {
  name               = "eks-terraform-LB-Controller"
  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": aws_iam_openid_connect_provider.eks_terraform_demo_OIDC.arn
            },
            "Action": "sts:AssumeRoleWithWebIdentity"
        }
    ]
})
}

#Create a IAM Custom policy for LB Controller
resource "aws_iam_policy" "eks-terraform-LB-Controller-policy" {
  name        = "eks-terraform-LB-Controller-policy"
  path        = "/"
  description = "eks-terraform-LB-Controller-policy"
  policy      = jsonencode({

    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateServiceLinkedRole"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:AWSServiceName": "elasticloadbalancing.amazonaws.com"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeAccountAttributes",
                "ec2:DescribeAddresses",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeVpcs",
                "ec2:DescribeVpcPeeringConnections",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeTags",
                "ec2:GetCoipPoolUsage",
                "ec2:DescribeCoipPools",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeListenerCertificates",
                "elasticloadbalancing:DescribeSSLPolicies",
                "elasticloadbalancing:DescribeRules",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetGroupAttributes",
                "elasticloadbalancing:DescribeTargetHealth",
                "elasticloadbalancing:DescribeTags"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "cognito-idp:DescribeUserPoolClient",
                "acm:ListCertificates",
                "acm:DescribeCertificate",
                "iam:ListServerCertificates",
                "iam:GetServerCertificate",
                "waf-regional:GetWebACL",
                "waf-regional:GetWebACLForResource",
                "waf-regional:AssociateWebACL",
                "waf-regional:DisassociateWebACL",
                "wafv2:GetWebACL",
                "wafv2:GetWebACLForResource",
                "wafv2:AssociateWebACL",
                "wafv2:DisassociateWebACL",
                "shield:GetSubscriptionState",
                "shield:DescribeProtection",
                "shield:CreateProtection",
                "shield:DeleteProtection"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateSecurityGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags"
            ],
            "Resource": "arn:aws:ec2:*:*:security-group/*",
            "Condition": {
                "StringEquals": {
                    "ec2:CreateAction": "CreateSecurityGroup"
                },
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags",
                "ec2:DeleteTags"
            ],
            "Resource": "arn:aws:ec2:*:*:security-group/*",
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:DeleteSecurityGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:CreateLoadBalancer",
                "elasticloadbalancing:CreateTargetGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:CreateListener",
                "elasticloadbalancing:DeleteListener",
                "elasticloadbalancing:CreateRule",
                "elasticloadbalancing:DeleteRule"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:AddTags",
                "elasticloadbalancing:RemoveTags"
            ],
            "Resource": [
                "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:AddTags",
                "elasticloadbalancing:RemoveTags"
            ],
            "Resource": [
                "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
                "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
                "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
                "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:ModifyLoadBalancerAttributes",
                "elasticloadbalancing:SetIpAddressType",
                "elasticloadbalancing:SetSecurityGroups",
                "elasticloadbalancing:SetSubnets",
                "elasticloadbalancing:DeleteLoadBalancer",
                "elasticloadbalancing:ModifyTargetGroup",
                "elasticloadbalancing:ModifyTargetGroupAttributes",
                "elasticloadbalancing:DeleteTargetGroup"
            ],
            "Resource": "*",
            "Condition": {
                "Null": {
                    "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:RegisterTargets",
                "elasticloadbalancing:DeregisterTargets"
            ],
            "Resource": "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:SetWebAcl",
                "elasticloadbalancing:ModifyListener",
                "elasticloadbalancing:AddListenerCertificates",
                "elasticloadbalancing:RemoveListenerCertificates",
                "elasticloadbalancing:ModifyRule"
            ],
            "Resource": "*"
        }
    ]
  })
}

#Add above policy to a role
resource "aws_iam_role_policy_attachment" "eks-terraform-LB-Controller-policy-attach" {
  role       = aws_iam_role.LB_Controller_IAM_Role.name
  policy_arn = aws_iam_policy.eks-terraform-LB-Controller-policy.arn
}

output "LB_Controller_Role_ARN" {
  value = aws_iam_role.LB_Controller_IAM_Role.arn
}