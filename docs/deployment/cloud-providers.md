# Cloud Provider Deployment Guide

This guide covers deploying REVENG on major cloud platforms.

## AWS

### Amazon ECS

Deploy REVENG as an ECS service:

```bash
# Create ECR repository
aws ecr create-repository --repository-name reveng

# Build and push image
docker build -t reveng:latest .
docker tag reveng:latest $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/reveng:latest
docker push $AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/reveng:latest

# Create ECS cluster and service
aws ecs create-cluster --cluster-name reveng-cluster
aws ecs create-service --cluster reveng-cluster --service-name reveng-mcp ...
```

### Amazon EKS

Deploy on managed Kubernetes:

```bash
# Create EKS cluster
eksctl create cluster --name reveng-cluster --region us-west-2

# Deploy REVENG
kubectl apply -f k8s/deployment.yaml
```

---

## Google Cloud Platform

### Google Kubernetes Engine (GKE)

```bash
# Create GKE cluster
gcloud container clusters create reveng-cluster \
  --zone us-central1-a \
  --num-nodes 3

# Deploy REVENG
kubectl apply -f k8s/deployment.yaml
```

### Cloud Run

For serverless deployment:

```bash
# Build with Cloud Build
gcloud builds submit --tag gcr.io/$PROJECT_ID/reveng

# Deploy to Cloud Run
gcloud run deploy reveng-mcp \
  --image gcr.io/$PROJECT_ID/reveng \
  --port 8080 \
  --set-env-vars GEMINI_API_KEY=$GEMINI_API_KEY
```

---

## Microsoft Azure

### Azure Kubernetes Service (AKS)

```bash
# Create AKS cluster
az aks create \
  --resource-group reveng-rg \
  --name reveng-cluster \
  --node-count 3

# Get credentials
az aks get-credentials --resource-group reveng-rg --name reveng-cluster

# Deploy REVENG
kubectl apply -f k8s/deployment.yaml
```

### Azure Container Instances

For quick deployments:

```bash
az container create \
  --resource-group reveng-rg \
  --name reveng-mcp \
  --image reveng:latest \
  --ports 8080 \
  --environment-variables GEMINI_API_KEY=$GEMINI_API_KEY
```

---

## Common Considerations

### Security

1. **Use managed secrets** (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)
2. **Enable network isolation** with VPCs and security groups
3. **Use private container registries**
4. **Enable audit logging**

### Monitoring

1. **Cloud-native monitoring** (CloudWatch, Cloud Monitoring, Azure Monitor)
2. **Prometheus + Grafana** for custom dashboards
3. **Centralized logging** (CloudWatch Logs, Cloud Logging, Azure Log Analytics)

### Cost Optimization

1. **Use spot/preemptible instances** for batch processing
2. **Right-size resources** based on usage patterns
3. **Enable auto-scaling** for dynamic workloads
4. **Use reserved capacity** for predictable workloads

---

*Cloud deployment guide for REVENG v4.0*
