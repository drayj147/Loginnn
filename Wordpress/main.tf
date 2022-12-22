module "vpc" {
  source               = "terraform-aws-modules/vpc/aws"
  name                 = "wordpress"
  cidr                 = "10.0.0.0/16"
  azs                  = ["us-east-1a", "us-east-1b"]
  public_subnets       = ["10.0.0.0/24", "10.0.1.0/24"]
  private_subnets      = ["10.0.2.0/24", "10.0.3.0/24"]
  intra_subnets        = ["10.0.4.0/24", "10.0.5.0/24"]
  database_subnets     = ["10.0.6.0/24", "10.0.7.0/24"]
  enable_nat_gateway   = true
  enable_dns_hostnames = true
}

module "wordpress" {
  source                         = "./modules/wordpress"
  tags                           = var.tags
  ecs_service_subnet_ids         = module.vpc.private_subnets
  ecs_cloudwatch_logs_group_name = var.ecs_cloudwatch_logs_group_name
  ecs_task_definition_family     = var.ecs_task_definition_family
  rds_cluster_master_username    = var.rds_cluster_master_username
  ecs_service_container_name     = var.ecs_service_container_name
  rds_cluster_database_name      = var.rds_cluster_database_name
  ecs_task_definition_cpu        = var.ecs_task_definition_cpu
  ecs_task_definition_memory     = var.ecs_task_definition_memory
  ecs_service_name               = var.ecs_service_name
  ecs_service_desired_count      = var.ecs_service_desired_count
  lb_name                        = var.lb_name
  lb_subnet_ids                  = module.vpc.public_subnets
  db_subnet_group_subnet_ids     = module.vpc.database_subnets
  rds_cluster_master_password    = var.rds_cluster_master_password
}