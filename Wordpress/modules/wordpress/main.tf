resource "aws_kms_key" "wordpress" {
  description             = "KMS Key used to encrypt Wordpress related resources"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = var.tags
}

resource "aws_kms_alias" "wordpress" {
  name          = "alias/wordpress"
  target_key_id = aws_kms_key.wordpress.id
}

resource "aws_efs_file_system" "wordpress" {
  creation_token = "wordpress"
  encrypted      = true
  kms_key_id     = aws_kms_key.wordpress.arn
  tags           = var.tags
}

resource "aws_efs_mount_target" "wordpress" {
  count           = length(var.ecs_service_subnet_ids)
  file_system_id  = aws_efs_file_system.wordpress.id
  subnet_id       = var.ecs_service_subnet_ids[count.index]
  security_groups = local.efs_service_security_group_ids
  //local.efs_service_security_group_ids
}

resource "aws_efs_access_point" "wordpress_plugins" {
  file_system_id = aws_efs_file_system.wordpress.id
  posix_user {
    gid = 33
    uid = 33
  }
  root_directory {
    path = "/plugins"
    creation_info {
      owner_gid   = 33
      owner_uid   = 33
      permissions = 755
    }
  }
}

resource "aws_efs_access_point" "wordpress_themes" {
  file_system_id = aws_efs_file_system.wordpress.id
  posix_user {
    gid = 33
    uid = 33
  }
  root_directory {
    path = "/themes"
    creation_info {
      owner_gid   = 33
      owner_uid   = 33
      permissions = 755
    }
  }
}

resource "aws_cloudwatch_log_group" "wordpress" {
  name              = var.ecs_cloudwatch_logs_group_name
  retention_in_days = 14
  kms_key_id        = aws_kms_key.wordpress.arn
  tags              = var.tags
}

resource "aws_ecs_cluster" "wordpress" {
  name = var.ecs_cluster_name
  tags = var.tags
}

resource "aws_ecs_task_definition" "wordpress" {
  family = var.ecs_task_definition_family
  container_definitions = templatefile(
    "${path.module}/wordpress.tpl",
    {
      ecs_service_container_name = var.ecs_service_container_name
      wordpress_db_host          = aws_db_instance.wordpress.endpoint
      wordpress_db_user          = var.rds_cluster_master_username
      wordpress_db_name          = var.rds_cluster_database_name
      aws_region                 = data.aws_region.current.name
      aws_logs_group             = aws_cloudwatch_log_group.wordpress.name
      aws_account_id             = data.aws_caller_identity.current.account_id
      secret_name                = aws_secretsmanager_secret.wordpress.name
      cloudwatch_log_group       = var.ecs_cloudwatch_logs_group_name
    }
  )
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.ecs_task_definition_cpu
  memory                   = var.ecs_task_definition_memory
  execution_role_arn       = aws_iam_role.ecs_task_role.arn
  volume {
    name = "efs-themes"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.wordpress.id
      root_directory     = "/"
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.wordpress_themes.id
      }
    }
  }
  volume {
    name = "efs-plugins"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.wordpress.id
      root_directory     = "/"
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.wordpress_plugins.id
      }
    }
  }
  tags = var.tags
}

resource "aws_ecs_service" "wordpress" {
  name             = var.ecs_service_name
  cluster          = aws_ecs_cluster.wordpress.arn
  task_definition  = aws_ecs_task_definition.wordpress.arn
  desired_count    = var.ecs_service_desired_count
  launch_type      = "FARGATE"
  platform_version = "1.4.0"
  propagate_tags   = "SERVICE"
  network_configuration {
    subnets          = var.ecs_service_subnet_ids
    security_groups  = local.ecs_service_security_group_ids
    assign_public_ip = var.ecs_service_assign_public_ip
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.wordpress_http.arn
    container_name   = var.ecs_service_container_name
    container_port   = "80"
  }
  tags = var.tags
}

resource "aws_lb" "wordpress" {
  name               = var.lb_name
  internal           = var.lb_internal
  load_balancer_type = "application"
  security_groups    = local.lb_security_group_ids
  subnets            = var.lb_subnet_ids
  tags               = var.tags
}

resource "aws_lb_listener" "wordpress_http" {
  load_balancer_arn = aws_lb.wordpress.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress_http.arn
  }
}

resource "aws_lb_listener" "wordpress_https" {
  count             = var.lb_listener_enable_ssl ? 1 : 0
  certificate_arn   = var.lb_listener_certificate_arn
  load_balancer_arn = aws_lb.wordpress.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = var.lb_listener_ssl_policy
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress_http.arn
  }
}

resource "aws_lb_target_group" "wordpress_http" {
  name        = var.lb_target_group_http
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_subnet.ecs_service_subnet_ids.vpc_id
  health_check {
    matcher = "200-499"
  }
  stickiness {
    type            = "lb_cookie"
    cookie_duration = 86400
    enabled         = true
  }
  tags = var.tags
}

resource "aws_db_subnet_group" "db" {
  count      = var.db_subnet_group_name == "" ? 1 : 0
  name       = "wordpress_db_subnet_group"
  subnet_ids = var.db_subnet_group_subnet_ids
  tags       = var.tags
}

resource "aws_db_instance" "wordpress" {
  # cluster_identifier              = var.rds_cluster_identifier
  # backup_retention_period         = var.rds_cluster_backup_retention_period
  # copy_tags_to_snapshot           = true
  # database_name                   = var.rds_cluster_database_name
  # db_subnet_group_name            = local.db_subnet_group_name
  # deletion_protection             = var.rds_cluster_deletion_protection
  # enabled_cloudwatch_logs_exports = var.rds_cluster_enable_cloudwatch_logs_export
  # engine_version                  = local.rds_cluster_engine_version
  # engine                          = "mysql"
  # final_snapshot_identifier       = var.rds_cluster_identifier
  # kms_key_id                      = aws_kms_key.wordpress.arn
  # master_password                 = var.rds_cluster_master_password
  # master_username                 = var.rds_cluster_master_username
  # preferred_backup_window         = var.rds_cluster_preferred_backup_window
  # preferred_maintenance_window    = var.rds_cluster_preferred_maintenance_window
  # storage_encrypted               = true
  # skip_final_snapshot             = var.rds_cluster_skip_final_snapshot
  # vpc_security_group_ids          = local.rds_cluster_security_group_ids
  # tags                            = var.tags
  identifier =var.rds_cluster_identifier
  engine               = "mysql"
  engine_version       = local.rds_cluster_engine_version
  instance_class       = var.rds_cluster_instance_instance_class
  kms_key_id           = aws_kms_key.wordpress.arn
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_encrypted     = true

  name     = var.rds_cluster_database_name
  username = var.rds_cluster_master_username
  password = var.rds_cluster_master_password
  port     = 3306

  multi_az               = false
  db_subnet_group_name   = local.db_subnet_group_name
  vpc_security_group_ids = local.rds_cluster_security_group_ids

  maintenance_window              = var.rds_cluster_preferred_maintenance_window
  backup_window                   = var.rds_cluster_preferred_backup_window
  enabled_cloudwatch_logs_exports = ["general"]

  backup_retention_period = var.rds_cluster_backup_retention_period
  skip_final_snapshot     = true
  deletion_protection     = false
  tags                            = var.tags
}

# resource "aws_rds_cluster_instance" "wordpress" {
#   count                = var.rds_cluster_instance_count
#   identifier           = join("-", [var.rds_cluster_identifier, count.index])
#   cluster_identifier   = aws_rds_cluster.wordpress.id
#   engine               = aws_rds_cluster.wordpress.engine
#   engine_version       = aws_rds_cluster.wordpress.engine_version
#   instance_class       = var.rds_cluster_instance_instance_class
#   db_subnet_group_name = local.db_subnet_group_name
#   tags = var.tags
# }

resource "aws_secretsmanager_secret" "wordpress" {
  name_prefix = var.secrets_manager_name
  description = "Secrets for ECS Wordpress"
  kms_key_id  = aws_kms_key.wordpress.id
  tags        = var.tags
}

resource "aws_secretsmanager_secret_version" "wordpress" {
  secret_id = aws_secretsmanager_secret.wordpress.id
  secret_string = jsonencode({
    WORDPRESS_DB_HOST     = aws_db_instance.wordpress.endpoint
    WORDPRESS_DB_USER     = var.rds_cluster_master_username
    WORDPRESS_DB_PASSWORD = var.rds_cluster_master_password
    WORDPRESS_DB_NAME     = var.rds_cluster_database_name
  })
}
resource "aws_security_group" "efs_service" {
  # count       = length(var.efs_service_security_group_ids) == 0 ? 1 : 0
  count       = length(var.security_group_ids.efs) == 0 ? 1 : 0
  name        = "wordpress-efs-service"
  description = "wordpress-efs-service"
  vpc_id      = data.aws_subnet.ecs_service_subnet_ids.vpc_id
}

resource "aws_security_group_rule" "efs_service_ingress_nfs_tcp" {
  # count                    = length(var.efs_service_security_group_ids) == 0 ? 1 : 0
  count                    = length(var.security_group_ids.efs) == 0 ? 1 : 0
  type                     = "ingress"
  description              = "nfs from efs"
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs_service[0].id
  security_group_id        = aws_security_group.efs_service[0].id
}


resource "aws_security_group" "ecs_service" {
  # count       = length(var.ecs_service_security_group_ids) == 0 ? 1 : 0
  count       = length(var.security_group_ids.ecs) == 0 ? 1 : 0
  name        = "wordpress-ecs-service"
  description = "wordpress ecs service"
  vpc_id      = data.aws_subnet.ecs_service_subnet_ids.vpc_id
}

resource "aws_security_group_rule" "ecs_service_ingress_http" {
  # count                    = length(var.ecs_service_security_group_ids) == 0 ? 1 : 0
  count                    = length(var.security_group_ids.ecs) == 0 ? 1 : 0
  type                     = "ingress"
  description              = "http from load balancer"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.lb_service[0].id
  security_group_id        = aws_security_group.ecs_service[0].id
}

resource "aws_security_group_rule" "ecs_service_ingress_https" {
  # count                    = length(var.ecs_service_security_grop_ids) == 0 ? 1 : 0
  count                    = length(var.security_group_ids.ecs) == 0 ? 1 : 0
  type                     = "ingress"
  description              = "https from load balancer"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.lb_service[0].id
  security_group_id        = aws_security_group.ecs_service[0].id
}

resource "aws_security_group_rule" "ecs_service_egress_http" {
  # count             = length(var.ecs_service_security_group_ids) == 0 ? 1 : 0
  count             = length(var.security_group_ids.ecs) == 0 ? 1 : 0
  type              = "egress"
  description       = "http to internet"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.ecs_service[0].id
}

resource "aws_security_group_rule" "ecs_service_egress_https" {
  # count             = length(var.ecs_service_security_group_ids) == 0 ? 1 : 0
  count             = length(var.security_group_ids.ecs) == 0 ? 1 : 0
  type              = "egress"
  description       = "https to internet"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.ecs_service[0].id
}

resource "aws_security_group_rule" "ecs_service_egress_mysql" {
  # count                    = length(var.ecs_service_security_group_ids) == 0 ? 1 : 0
  count                    = length(var.security_group_ids.ecs) == 0 ? 1 : 0
  type                     = "egress"
  description              = "mysql"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.rds_cluster[0].id
  security_group_id        = aws_security_group.ecs_service[0].id
}

resource "aws_security_group_rule" "ecs_service_egress_efs_tcp" {
  # count                    = length(var.ecs_service_security_group_ids) == 0 ? 1 : 0
  count                    = length(var.security_group_ids.ecs) == 0 ? 1 : 0
  type                     = "egress"
  description              = "efs"
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.efs_service[0].id
  security_group_id        = aws_security_group.ecs_service[0].id
}

resource "aws_security_group" "lb_service" {
  # count       = length(var.lb_security_group_ids) == 0 ? 1 : 0
  count       = length(var.security_group_ids.lb) == 0 ? 1 : 0
  name        = "wordpress-lb-service"
  description = "wordpress lb service"
  vpc_id      = data.aws_subnet.ecs_service_subnet_ids.vpc_id
}

resource "aws_security_group_rule" "lb_service_ingress_http" {
  # count             = length(var.lb_security_group_ids) == 0 ? 1 : 0
  count             = length(var.security_group_ids.lb) == 0 ? 1 : 0
  type              = "ingress"
  description       = "http"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.lb_service[0].id
}

resource "aws_security_group_rule" "lb_service_ingress_https" {
  # count             = length(var.lb_security_group_ids) == 0 ? 1 : 0
  count             = length(var.security_group_ids.lb) == 0 ? 1 : 0
  type              = "ingress"
  description       = "http"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.lb_service[0].id
}

resource "aws_security_group_rule" "lb_service_egress_http" {
  # count                    = length(var.lb_security_group_ids) == 0 ? 1 : 0
  count                    = length(var.security_group_ids.lb) == 0 ? 1 : 0
  type                     = "egress"
  description              = "http"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs_service[0].id
  security_group_id        = aws_security_group.lb_service[0].id
}

resource "aws_security_group_rule" "lb_service_egress_https" {
  # count                    = length(var.lb_security_group_ids) == 0 ? 1 : 0
  count                    = length(var.security_group_ids.lb) == 0 ? 1 : 0
  type                     = "egress"
  description              = "https"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs_service[0].id
  security_group_id        = aws_security_group.lb_service[0].id
}

resource "aws_security_group" "rds_cluster" {
  # count       = length(var.rds_cluster_security_group_ids) == 0 ? 1 : 0
  count       = length(var.security_group_ids.rds) == 0 ? 1 : 0
  name        = "wordpress-rds-service"
  description = "wordpress rds service"
  vpc_id      = data.aws_subnet.ecs_service_subnet_ids.vpc_id
}

resource "aws_security_group_rule" "rds_cluster_ingress_mysql" {
  # count                    = length(var.rds_cluster_security_group_ids) == 0 ? 1 : 0
  count                    = length(var.security_group_ids.rds) == 0 ? 1 : 0
  type                     = "ingress"
  description              = "mysql"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs_service[0].id
  security_group_id        = aws_security_group.rds_cluster[0].id
}
data "aws_iam_policy_document" "ecs_task_trust" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "ecs_task_policy" {
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    effect    = "Allow"
    resources = ["*"]
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    effect    = "Allow"
    resources = [aws_secretsmanager_secret.wordpress.arn]
  }
  statement {
    actions   = ["kms:Decrypt"]
    effect    = "Allow"
    resources = [aws_kms_key.wordpress.arn]
  }
}

resource "aws_iam_role" "ecs_task_role" {
  name               = "wordpressTaskRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

resource "aws_iam_policy" "ecs_task_policy" {
  name   = "wordpressTaskPolicy"
  policy = data.aws_iam_policy_document.ecs_task_policy.json
}

resource "aws_iam_role_policy_attachment" "ecs_role_attachment" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.ecs_task_policy.arn
}
