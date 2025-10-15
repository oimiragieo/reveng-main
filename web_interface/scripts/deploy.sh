#!/bin/bash
# REVENG Web Interface Deployment Script
# =======================================

set -e

# Configuration
NAMESPACE="reveng"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-reveng}"
VERSION="${VERSION:-latest}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check if we can connect to Kubernetes cluster
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Build Docker images
build_images() {
    log_info "Building Docker images..."
    
    # Build backend image
    log_info "Building backend image..."
    docker build -f Dockerfile.backend -t ${DOCKER_REGISTRY}/reveng-backend:${VERSION} .
    
    # Build frontend image
    log_info "Building frontend image..."
    docker build -f Dockerfile.frontend -t ${DOCKER_REGISTRY}/reveng-frontend:${VERSION} .
    
    # Build worker image (if exists)
    if [ -f "Dockerfile.worker" ]; then
        log_info "Building worker image..."
        docker build -f Dockerfile.worker -t ${DOCKER_REGISTRY}/reveng-worker:${VERSION} .
    fi
    
    log_success "Docker images built successfully"
}

# Push Docker images
push_images() {
    log_info "Pushing Docker images to registry..."
    
    docker push ${DOCKER_REGISTRY}/reveng-backend:${VERSION}
    docker push ${DOCKER_REGISTRY}/reveng-frontend:${VERSION}
    
    if docker images | grep -q "${DOCKER_REGISTRY}/reveng-worker"; then
        docker push ${DOCKER_REGISTRY}/reveng-worker:${VERSION}
    fi
    
    log_success "Docker images pushed successfully"
}

# Create namespace
create_namespace() {
    log_info "Creating namespace..."
    
    if kubectl get namespace ${NAMESPACE} &> /dev/null; then
        log_warning "Namespace ${NAMESPACE} already exists"
    else
        kubectl apply -f kubernetes/namespace.yaml
        log_success "Namespace ${NAMESPACE} created"
    fi
}

# Create secrets
create_secrets() {
    log_info "Creating secrets..."
    
    # Check if secrets already exist
    if kubectl get secret reveng-secrets -n ${NAMESPACE} &> /dev/null; then
        log_warning "Secrets already exist, skipping creation"
        return
    fi
    
    # Generate random passwords if not provided
    MONGO_USERNAME="${MONGO_USERNAME:-admin}"
    MONGO_PASSWORD="${MONGO_PASSWORD:-$(openssl rand -base64 32)}"
    REDIS_PASSWORD="${REDIS_PASSWORD:-$(openssl rand -base64 32)}"
    JWT_SECRET="${JWT_SECRET:-$(openssl rand -base64 64)}"
    
    # Create secrets
    kubectl create secret generic reveng-secrets \
        --from-literal=mongo-username="${MONGO_USERNAME}" \
        --from-literal=mongo-password="${MONGO_PASSWORD}" \
        --from-literal=redis-password="${REDIS_PASSWORD}" \
        --from-literal=jwt-secret="${JWT_SECRET}" \
        -n ${NAMESPACE}
    
    log_success "Secrets created successfully"
    log_info "MongoDB Username: ${MONGO_USERNAME}"
    log_info "MongoDB Password: ${MONGO_PASSWORD}"
    log_info "Redis Password: ${REDIS_PASSWORD}"
}

# Create TLS certificates
create_tls() {
    log_info "Creating TLS certificates..."
    
    if kubectl get secret reveng-tls -n ${NAMESPACE} &> /dev/null; then
        log_warning "TLS secret already exists, skipping creation"
        return
    fi
    
    # Generate self-signed certificate for development
    if [ "${ENVIRONMENT}" = "development" ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout tls.key -out tls.crt \
            -subj "/CN=reveng.local/O=reveng"
        
        kubectl create secret tls reveng-tls \
            --cert=tls.crt --key=tls.key \
            -n ${NAMESPACE}
        
        rm tls.key tls.crt
        log_success "Self-signed TLS certificate created"
    else
        log_warning "For production, please create TLS certificate manually"
        log_info "kubectl create secret tls reveng-tls --cert=path/to/tls.crt --key=path/to/tls.key -n ${NAMESPACE}"
    fi
}

# Create persistent volumes
create_storage() {
    log_info "Creating persistent volumes..."
    
    kubectl apply -f kubernetes/storage.yaml
    log_success "Persistent volumes created"
}

# Deploy applications
deploy_apps() {
    log_info "Deploying applications..."
    
    # Apply ConfigMaps
    kubectl apply -f kubernetes/configmap.yaml
    
    # Apply Services
    kubectl apply -f kubernetes/service.yaml
    
    # Apply Deployments
    kubectl apply -f kubernetes/deployment.yaml
    
    log_success "Applications deployed successfully"
}

# Wait for deployments
wait_for_deployments() {
    log_info "Waiting for deployments to be ready..."
    
    kubectl wait --for=condition=available --timeout=300s deployment/mongodb -n ${NAMESPACE}
    kubectl wait --for=condition=available --timeout=300s deployment/redis -n ${NAMESPACE}
    kubectl wait --for=condition=available --timeout=300s deployment/reveng-backend -n ${NAMESPACE}
    kubectl wait --for=condition=available --timeout=300s deployment/reveng-frontend -n ${NAMESPACE}
    kubectl wait --for=condition=available --timeout=300s deployment/nginx -n ${NAMESPACE}
    
    log_success "All deployments are ready"
}

# Get service information
get_service_info() {
    log_info "Getting service information..."
    
    echo ""
    echo "=== REVENG Web Interface Deployment Complete ==="
    echo ""
    
    # Get LoadBalancer IP/hostname
    EXTERNAL_IP=$(kubectl get service nginx -n ${NAMESPACE} -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    EXTERNAL_HOSTNAME=$(kubectl get service nginx -n ${NAMESPACE} -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
    
    if [ -n "${EXTERNAL_IP}" ]; then
        echo "External IP: ${EXTERNAL_IP}"
        echo "Access URL: http://${EXTERNAL_IP}"
        echo "Secure URL: https://${EXTERNAL_IP}"
    elif [ -n "${EXTERNAL_HOSTNAME}" ]; then
        echo "External Hostname: ${EXTERNAL_HOSTNAME}"
        echo "Access URL: http://${EXTERNAL_HOSTNAME}"
        echo "Secure URL: https://${EXTERNAL_HOSTNAME}"
    else
        echo "LoadBalancer is still provisioning..."
        echo "Run 'kubectl get service nginx -n ${NAMESPACE}' to check status"
    fi
    
    echo ""
    echo "Namespace: ${NAMESPACE}"
    echo "Version: ${VERSION}"
    echo "Environment: ${ENVIRONMENT}"
    echo ""
    
    # Show pod status
    kubectl get pods -n ${NAMESPACE}
}

# Cleanup function
cleanup() {
    log_info "Cleaning up deployment..."
    
    kubectl delete namespace ${NAMESPACE} --ignore-not-found=true
    log_success "Cleanup completed"
}

# Main deployment function
deploy() {
    log_info "Starting REVENG Web Interface deployment..."
    
    check_prerequisites
    
    if [ "${BUILD_IMAGES}" = "true" ]; then
        build_images
    fi
    
    if [ "${PUSH_IMAGES}" = "true" ]; then
        push_images
    fi
    
    create_namespace
    create_secrets
    create_tls
    create_storage
    deploy_apps
    wait_for_deployments
    get_service_info
    
    log_success "REVENG Web Interface deployed successfully!"
}

# Parse command line arguments
case "${1:-deploy}" in
    "deploy")
        deploy
        ;;
    "build")
        check_prerequisites
        build_images
        ;;
    "push")
        check_prerequisites
        push_images
        ;;
    "cleanup")
        cleanup
        ;;
    "status")
        get_service_info
        ;;
    *)
        echo "Usage: $0 {deploy|build|push|cleanup|status}"
        echo ""
        echo "Commands:"
        echo "  deploy   - Full deployment (default)"
        echo "  build    - Build Docker images only"
        echo "  push     - Push Docker images to registry"
        echo "  cleanup  - Remove all deployed resources"
        echo "  status   - Show deployment status"
        echo ""
        echo "Environment Variables:"
        echo "  DOCKER_REGISTRY - Docker registry prefix (default: reveng)"
        echo "  VERSION         - Image version tag (default: latest)"
        echo "  ENVIRONMENT     - Deployment environment (default: production)"
        echo "  BUILD_IMAGES    - Build images during deploy (default: false)"
        echo "  PUSH_IMAGES     - Push images during deploy (default: false)"
        exit 1
        ;;
esac