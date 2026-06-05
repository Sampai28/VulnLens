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

resource "aws_ecs_service" "sast" {
  name            = "${var.project}-sast-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.sast.arn
  desired_count   = 0
  launch_type     = "FARGATE"

  # Fargate tasks run in the private subnet — not internet-facing
  network_configuration {
    subnets          = [aws_subnet.private.id]
    security_groups  = [aws_security_group.fargate.id]
    assign_public_ip = false
  }

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
