locals {
  rds_cluster_engine_version     = var.rds_cluster_engine_version == "" ? data.aws_rds_engine_version.rds_engine_version.version : var.rds_cluster_engine_version
  db_subnet_group_name           = var.db_subnet_group_name == "" ? aws_db_subnet_group.db[0].name : var.db_subnet_group_name
  efs_service_security_group_ids = length(var.security_group_ids.efs) == 0 ? aws_security_group.efs_service.*.id : var.security_group_ids.efs
  ecs_service_security_group_ids = length(var.security_group_ids.ecs) == 0 ? aws_security_group.ecs_service.*.id : var.security_group_ids.ecs
  lb_security_group_ids          = length(var.security_group_ids.lb) == 0 ? aws_security_group.lb_service.*.id : var.security_group_ids.lb
  rds_cluster_security_group_ids = length(var.security_group_ids.rds) == 0 ? aws_security_group.rds_cluster.*.id : var.security_group_ids.rds
}