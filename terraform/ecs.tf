resource "aws_ecs_cluster" "main" {
  name = "${var.project}-cluster"

  tags = {
    Project = var.project
  }
}

resource "aws_ecs_task_definition" "sast" {
  family                   = "${var.project}-sast-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  task_role_arn            = "arn:aws:iam::${var.aws_account_id}:role/LabRole"
  execution_role_arn       = "arn:aws:iam::${var.aws_account_id}:role/LabRole"

  container_definitions = jsonencode([
    {
      name      = "${var.project}-sast"
      image     = "${var.aws_account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.project}-sast:latest"
      essential = true

      portMappings = [
        {
          containerPort = 3000
          protocol      = "tcp"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = "/ecs/${var.project}-sast"
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])

  tags = {
    Project = var.project
  }
}

resource "aws_cloudwatch_log_group" "sast" {
  name              = "/ecs/${var.project}-sast"
  retention_in_days = 7

  tags = {
    Project = var.project
  }
}
