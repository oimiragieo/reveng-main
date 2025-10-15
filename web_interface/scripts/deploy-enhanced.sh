#!/bin/bash
# Enhanced Deployment Script for REVENG Cloud Infrastructure
# ==========================================================

set -e

# Configuration
NAMESPACE="reveng"
REGISTRY="your-registry.com"
VERSION="${VERSION:-latest}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi
    
    # Check docker
    if ! command -v docker &> /dev/null; then
        log_error "docker is not installed"
        exit 1
    fi
    
    # Check cluster connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Build and push Docker images
build_images() {
    log_info "Building Docker images..."
    
    # Build backend image
    log_info "Building backend image..."
    docker build -f Dockerfile.backend -t ${REGISTRY}/reveng-backend:${VERSION} .
    
    # Build frontend image
    log_info "Building frontend image..."
    docker build -f Dockerfile.frontend -t ${REGISTRY}/reveng-frontend:${VERSION} .
    
    # Build worker image
    log_info "Building analysis worker image..."
    docker build -f Dockerfile.worker -t ${REGISTRY}/reveng-analysis-worker:${VERSION} .
    
    # Build AI service image
    log_info "Building AI service image..."
    docker build -f Dockerfile.ai-service -t ${REGISTRY}/reveng-ai-service:${VERSION} .
    
    log_info "Docker images built successfully"
}

# Push images to registry
push_images() {
    log_info "Pushing images to registry..."
    
    docker push ${REGISTRY}/reveng-backend:${VERSION}
    docker push ${REGISTRY}/reveng-frontend:${VERSION}
    docker push ${REGISTRY}/reveng-analysis-worker:${VERSION}
    docker push ${REGISTRY}/reveng-ai-service:${VERSION}
    
    log_info "Images pushed successfully"
}

# Create namespace
create_namespace() {
    log_info "Creating namespace..."
    kubectl apply -f kubernetes/namespace.yaml
}

# Deploy infrastructure components
deploy_infrastructure() {
    log_info "Deploying infrastructure components..."
    
    # Apply persistent volumes
    kubectl apply -f kubernetes/persistent-volumes.yaml
    
    # Apply configuration and secrets
    kubectl apply -f kubernetes/enhanced-config.yaml
    
    # Wait for PVCs to be bound
    log_info "Waiting for persistent volumes to be ready..."
    kubectl wait --for=condition=Bound pvc --all -n ${NAMESPACE} --timeout=300s
}

# Deploy services
deploy_services() {
    log_info "Deploying services..."
    
    # Deploy core services (MongoDB, Redis)
    kubectl apply -f kubernetes/deployment.yaml
    
    # Deploy enhanced services
    kubectl apply -f kubernetes/enhanced-deployment.yaml
    
    # Deploy service definitions
    kubectl apply -f kubernetes/service.yaml
    kubectl apply -f kubernetes/enhanced-services.yaml
    
    log_info "Services deployed"
}

# Deploy API Gateway (Istio)
deploy_gateway() {
    log_info "Deploying API Gateway..."
    
    # Check if Istio is installed
    if kubectl get namespace istio-system &> /dev/null; then
        kubectl apply -f kubernetes/istio-gateway.yaml
        log_info "Istio gateway deployed"
    else
        log_warn "Istio not found, skipping gateway deployment"
    fi
}

# Wait for deployments to be ready
wait_for_deployments() {
    log_info "Waiting for deployments to be ready..."
    
    # Wait for core deployments
    kubectl wait --for=condition=available deployment/mongodb -n ${NAMESPACE} --timeout=300s
    kubectl wait --for=condition=available deployment/redis -n ${NAMESPACE} --timeout=300s
    kubectl wait --for=condition=available deployment/reveng-backend -n ${NAMESPACE} --timeout=300s
    kubectl wait --for=condition=available deployment/reveng-frontend -n ${NAMESPACE} --timeout=300s
    
    # Wait for enhanced deployments
    kubectl wait --for=condition=available deployment/analysis-worker -n ${NAMESPACE} --timeout=300s
    kubectl wait --for=condition=available deployment/ai-service -n ${NAMESPACE} --timeout=300s
    
    log_info "All deployments are ready"
}

# Run health checks
health_checks() {
    log_info "Running health checks..."
    
    # Check pod status
    kubectl get pods -n ${NAMESPACE}
    
    # Check service endpoints
    kubectl get endpoints -n ${NAMESPACE}
    
    # Test backend health
    if kubectl get service reveng-loadbalancer -n ${NAMESPACE} &> /dev/null; then
        EXTERNAL_IP=$(kubectl get service reveng-loadbalancer -n ${NAMESPACE} -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
        if [ ! -z "$EXTERNAL_IP" ]; then
            log_info "Testing external endpoint: http://${EXTERNAL_IP}/api/health"
            # Note: In production, you might want to add actual health check here
        fi
    fi
    
    log_info "Health checks completed"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up resources..."
    
    kubectl delete -f kubernetes/enhanced-deployment.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/deployment.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/enhanced-services.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/service.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/istio-gateway.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/enhanced-config.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/persistent-volumes.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/namespace.yaml --ignore-not-found=true
    
    log_info "Cleanup completed"
}

# Main deployment function
deploy() {
    log_info "Starting REVENG enhanced deployment..."
    
    check_prerequisites
    build_images
    push_images
    create_namespace
    deploy_infrastructure
    deploy_services
    deploy_gateway
    wait_for_deployments
    health_checks
    
    log_info "Deployment completed successfully!"
    log_info "Access the application at: https://reveng.example.com"
}

# Parse command line arguments
case "${1:-deploy}" in
    "deploy")
        deploy
        ;;
    "cleanup")
        cleanup
        ;;
    "build")
        check_prerequisites
        build_images
        ;;
    "push")
        push_images
        ;;
    "health")
        health_checks
        ;;
    *)
        echo "Usage: $0 {deploy|cleanup|build|push|health}"
        exit 1
        ;;
esac