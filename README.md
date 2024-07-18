
# About
I implemented this 3 tier architecture on private AWS EKS cluster and made it available to internet using Ingress.

## AWS Architecture Diagram

<img src="https://github.com/dhairyadudhatra-com/demo-k8s-CI-CD/blob/dev/aws_arch_demo_eks.drawio.png" width=700 height=700>

## Kubernetes Architecture

<img src="https://github.com/dhairyadudhatra-com/demo-k8s-CI-CD/blob/dev/3_tier.drawio.png" width=700 height=400>

## Terraform 
I have built a single file main.tf which deploys below resources

1- VPC,

2- Public Subnet, Private Subnets(2)

3- Internet Gateway, NAT Gateway

4- IAM Role for EKS

5- EKS cluster

6- EKS Node Group

7- EKS Addons 

## Jump Server
I have not written code to setup a jump server in Terraform.
But it needs to have below packages and access.

1- AWSCLI v2

2- Kubectl

3- Cluster Admin priviledges

4- Your system should be able to connect to this server.

## Instructions
After running Terraform file,
follow instructions in the files/checkList file.

## Creator
- [@Dhairya Dudhatra](https://github.com/Dhairya-Dudhatra)
