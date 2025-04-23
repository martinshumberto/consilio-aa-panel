#!/bin/bash

# Docker service manager script
set -e

SERVICE=$1
ACTION=$2

# Display usage if parameters are missing
if [ -z "$SERVICE" ] || [ -z "$ACTION" ]; then
  echo "Usage: $0 SERVICE ACTION"
  echo "Services: mongodb, redis, postgres, all"
  echo "Actions: start, stop, restart, status, logs"
  exit 1
fi

# Load environment variables
if [ -f .env ]; then
  source .env
fi

# Function to manage all services
manage_all() {
  case "$1" in
    start)
      docker-compose up -d
      ;;
    stop)
      docker-compose down
      ;;
    restart)
      docker-compose restart
      ;;
    status)
      docker-compose ps
      ;;
    logs)
      docker-compose logs
      ;;
    *)
      echo "Invalid action for all services"
      exit 1
      ;;
  esac
}

# Function to manage specific service
manage_service() {
  local service=$1
  local action=$2
  
  case "$action" in
    start)
      docker-compose up -d $service
      ;;
    stop)
      docker-compose stop $service
      ;;
    restart)
      docker-compose restart $service
      ;;
    status)
      docker-compose ps $service
      ;;
    logs)
      docker-compose logs $service
      ;;
    *)
      echo "Invalid action for $service"
      exit 1
      ;;
  esac
}

# Main logic
if [ "$SERVICE" = "all" ]; then
  manage_all "$ACTION"
else
  # Check if service exists
  if ! grep -q "$SERVICE:" docker-compose.yaml; then
    echo "Service $SERVICE not found in docker-compose.yaml"
    exit 1
  fi
  manage_service "$SERVICE" "$ACTION"
fi

echo "Done." 