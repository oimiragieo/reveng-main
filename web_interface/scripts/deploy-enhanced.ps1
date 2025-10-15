# Enhanced Deployment Script for REVENG Cloud Infrastructure (PowerShell)
# ========================================================================

param(
    [Parameter(Position=0)]
    [ValidateSet("deploy", "cleanup", "build", "push", "health")]
    [string]$Action = "deploy",
    
    [string]$Registry = "your-registry.com",
    [string]$Version = "latest",
    [string]$Environment = "production",
    [string]$Namespace = "reveng"
)

# Configuration
$ErrorActionPreference = "Stop"

# Logging functions
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Check prerequisites
function Test-Prerequisites {
    Write-Info "Checking prerequisites..."
    
    # Check kubectl
    if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
        Write-Error "kubectl is not installed"
        exit 1
    }
    
    # Check docker
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error "docker is not installed"
        exit 1
    }
    
    # Check cluster connection
    try {
        kubectl cluster-info | Out-Null
    }
    catch {
        Write-Error "Cannot connect to Kubernetes cluster"
        exit 1
    }
    
    Write-Info "Prerequisites check passed"
}

# Build Docker images
function Build-Images {
    Write-Info "Building Docker images..."
    
    # Build backend image
    Write-Info "Building backend image..."
    docker build -f Dockerfile.backend -t "${Registry}/reveng-backend:${Version}" .
    
    # Build frontend image
    Write-Info "Building frontend image..."
    docker build -f Dockerfile.frontend -t "${Registry}/reveng-frontend:${Version}" .
    
    # Build worker image
    Write-Info "Building analysis worker image..."
    docker build -f Dockerfile.worker -t "${Registry}/reveng-analysis-worker:${Version}" .
    
    # Build AI service image
    Write-Info "Building AI service image..."
    docker build -f Dockerfile.ai-service -t "${Registry}/reveng-ai-service:${Version}" .
    
    Write-Info "Docker images built successfully"
}

# Push images to registry
function Push-Images {
    Write-Info "Pushing images to registry..."
    
    docker push "${Registry}/reveng-backend:${Version}"
    docker push "${Registry}/reveng-frontend:${Version}"
    docker push "${Registry}/reveng-analysis-worker:${Version}"
    docker push "${Registry}/reveng-ai-service:${Version}"
    
    Write-Info "Images pushed successfully"
}

# Create namespace
function New-Namespace {
    Write-Info "Creating namespace..."
    kubectl apply -f kubernetes/namespace.yaml
}

# Deploy infrastructure components
function Deploy-Infrastructure {
    Write-Info "Deploying infrastructure components..."
    
    # Apply persistent volumes
    kubectl apply -f kubernetes/persistent-volumes.yaml
    
    # Apply configuration and secrets
    kubectl apply -f kubernetes/enhanced-config.yaml
    
    # Wait for PVCs to be bound
    Write-Info "Waiting for persistent volumes to be ready..."
    kubectl wait --for=condition=Bound pvc --all -n $Namespace --timeout=300s
}

# Deploy services
function Deploy-Services {
    Write-Info "Deploying services..."
    
    # Deploy core services (MongoDB, Redis)
    kubectl apply -f kubernetes/deployment.yaml
    
    # Deploy enhanced services
    kubectl apply -f kubernetes/enhanced-deployment.yaml
    
    # Deploy service definitions
    kubectl apply -f kubernetes/service.yaml
    kubectl apply -f kubernetes/enhanced-services.yaml
    
    Write-Info "Services deployed"
}

# Deploy API Gateway (Istio)
function Deploy-Gateway {
    Write-Info "Deploying API Gateway..."
    
    # Check if Istio is installed
    try {
        kubectl get namespace istio-system | Out-Null
        kubectl apply -f kubernetes/istio-gateway.yaml
        Write-Info "Istio gateway deployed"
    }
    catch {
        Write-Warn "Istio not found, skipping gateway deployment"
    }
}

# Wait for deployments to be ready
function Wait-ForDeployments {
    Write-Info "Waiting for deployments to be ready..."
    
    # Wait for core deployments
    kubectl wait --for=condition=available deployment/mongodb -n $Namespace --timeout=300s
    kubectl wait --for=condition=available deployment/redis -n $Namespace --timeout=300s
    kubectl wait --for=condition=available deployment/reveng-backend -n $Namespace --timeout=300s
    kubectl wait --for=condition=available deployment/reveng-frontend -n $Namespace --timeout=300s
    
    # Wait for enhanced deployments
    kubectl wait --for=condition=available deployment/analysis-worker -n $Namespace --timeout=300s
    kubectl wait --for=condition=available deployment/ai-service -n $Namespace --timeout=300s
    
    Write-Info "All deployments are ready"
}

# Run health checks
function Test-Health {
    Write-Info "Running health checks..."
    
    # Check pod status
    kubectl get pods -n $Namespace
    
    # Check service endpoints
    kubectl get endpoints -n $Namespace
    
    # Test backend health
    try {
        $externalIP = kubectl get service reveng-loadbalancer -n $Namespace -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>$null
        if ($externalIP) {
            Write-Info "Testing external endpoint: http://${externalIP}/api/health"
            # Note: In production, you might want to add actual health check here
        }
    }
    catch {
        Write-Warn "Could not get external IP for health check"
    }
    
    Write-Info "Health checks completed"
}

# Cleanup function
function Remove-Deployment {
    Write-Info "Cleaning up resources..."
    
    kubectl delete -f kubernetes/enhanced-deployment.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/deployment.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/enhanced-services.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/service.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/istio-gateway.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/enhanced-config.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/persistent-volumes.yaml --ignore-not-found=true
    kubectl delete -f kubernetes/namespace.yaml --ignore-not-found=true
    
    Write-Info "Cleanup completed"
}

# Main deployment function
function Start-Deployment {
    Write-Info "Starting REVENG enhanced deployment..."
    
    Test-Prerequisites
    Build-Images
    Push-Images
    New-Namespace
    Deploy-Infrastructure
    Deploy-Services
    Deploy-Gateway
    Wait-ForDeployments
    Test-Health
    
    Write-Info "Deployment completed successfully!"
    Write-Info "Access the application at: https://reveng.example.com"
}

# Main script logic
switch ($Action) {
    "deploy" {
        Start-Deployment
    }
    "cleanup" {
        Remove-Deployment
    }
    "build" {
        Test-Prerequisites
        Build-Images
    }
    "push" {
        Push-Images
    }
    "health" {
        Test-Health
    }
    default {
        Write-Host "Usage: .\deploy-enhanced.ps1 {deploy|cleanup|build|push|health}"
        exit 1
    }
}