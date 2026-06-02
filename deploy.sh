#!/bin/bash
set -e

# NetScan Deployment Script
# Supports: local dev, Docker Compose, Kubernetes

ENV=${1:-dev}
ACTION=${2:-up}

echo "NetScan Deployment - Environment: $ENV, Action: $ACTION"

case $ENV in
  dev)
    echo "Starting development environment with hot-reload..."
    docker compose up --pull always -d
    docker compose logs -f
    ;;
  
  staging)
    echo "Deploying to staging..."
    docker compose --profile prod -f docker-compose.yml up -d netscan-prod
    docker compose logs netscan-prod
    echo "Staging deployment complete. Access at http://localhost:8080"
    ;;
  
  prod-docker)
    echo "Deploying to production (Docker Compose)..."
    docker compose --profile prod pull
    docker compose --profile prod up -d netscan-prod
    echo "Production deployment complete."
    docker compose --profile prod logs -f netscan-prod
    ;;
  
  prod-k8s)
    if [ "$ACTION" = "up" ]; then
      echo "Deploying to Kubernetes..."
      # Update image reference if needed
      sed -i.bak "s|ghcr.io/your-org/netscan:latest|$NETSCAN_IMAGE|g" k8s-deployment.yaml
      kubectl apply -f k8s-deployment.yaml
      echo "Waiting for deployment to be ready..."
      kubectl rollout status deployment/netscan -n default --timeout=5m
      echo "Deployment complete."
      kubectl get pods -l app=netscan
    elif [ "$ACTION" = "down" ]; then
      echo "Removing Kubernetes deployment..."
      kubectl delete -f k8s-deployment.yaml
      echo "Deployment removed."
    fi
    ;;
  
  *)
    echo "Usage: $0 {dev|staging|prod-docker|prod-k8s} {up|down}"
    echo ""
    echo "Examples:"
    echo "  $0 dev              # Start dev with hot-reload"
    echo "  $0 staging up       # Deploy to staging"
    echo "  $0 prod-docker up   # Deploy to production (Docker)"
    echo "  $0 prod-k8s up      # Deploy to production (Kubernetes)"
    echo "  $0 prod-k8s down    # Remove Kubernetes deployment"
    exit 1
    ;;
esac
