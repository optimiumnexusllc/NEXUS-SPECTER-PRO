#!/bin/bash
# NEXUS SPECTER PRO — Kubernetes Deployment Script
# by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
set -e

NS="nexus-specter-pro"
echo "⚡ Deploying NEXUS SPECTER PRO to Kubernetes..."
echo "   by OPTIMIUM NEXUS LLC"
echo ""

# 1. Namespace
kubectl apply -f namespace.yaml

# 2. Secrets (edit secret.yaml first!)
echo "⚠️  Ensure you have filled in deployment/kubernetes/secret.yaml with real values"
read -rp "Continue? (y/N): " CONFIRM
[[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] || exit 1

kubectl apply -f secret.yaml
kubectl apply -f configmap.yaml

# 3. Databases
kubectl apply -f postgres.yaml
kubectl apply -f redis.yaml

echo "⏳ Waiting for databases..."
kubectl rollout status statefulset/nsp-postgres -n $NS --timeout=120s
kubectl rollout status deployment/nsp-redis    -n $NS --timeout=60s

# 4. Core engine
kubectl apply -f nsp-core.yaml
kubectl rollout status deployment/nsp-core -n $NS --timeout=180s

# 5. Autoscaling + Ingress
kubectl apply -f hpa.yaml
kubectl apply -f ingress.yaml

echo ""
echo "✅ NEXUS SPECTER PRO deployed successfully!"
echo "   Dashboard: https://nsp.yourdomain.com"
echo "   Namespace: $NS"
kubectl get pods -n $NS
