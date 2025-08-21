# 🐧 WSL Setup Guide for Kubernetes Security Lab

This guide helps you set up the security framework in your WSL environment with Minikube and Docker Desktop.

## 🚀 Quick Start for WSL Users

### Prerequisites Check
```bash
# Verify you're in WSL
grep Microsoft /proc/version

# Check if required tools are installed
which kubectl helm docker git
```

### 1. **Choose Your Kubernetes Environment**

#### Option A: Minikube (Recommended for learning)
```bash
# Start Minikube with adequate resources
minikube start --cpus=4 --memory=4096 --driver=docker

# Enable useful addons
minikube addons enable metrics-server
minikube addons enable ingress

# Verify connection
kubectl get nodes
```

#### Option B: Docker Desktop Kubernetes
```bash
# Make sure Kubernetes is enabled in Docker Desktop
# Settings > Kubernetes > Enable Kubernetes

# Switch to Docker Desktop context
kubectl config use-context docker-desktop

# Verify connection
kubectl get nodes
```

### 2. **Deploy Security Tools (Optimized for Local)**
```bash
# Clone the repository (if not already done)
cd /mnt/c/your/path/to/Cloud-Security-Stack  # Or wherever you have it

# Make scripts executable
chmod +x scripts/*.sh

# Deploy all Phase 1 security tools with local optimizations
./scripts/deploy-phase1-tools-wsl.sh
```

### 3. **Verify Everything is Working**
```bash
# Run comprehensive health check
./scripts/security-health-check-wsl.sh

# Check all security tools are running
kubectl get pods -A | grep -E "(gatekeeper|falco|trivy)"
```

## 🎯 **What Gets Deployed**

### Security Tools (Resource Optimized)
- **OPA Gatekeeper**: Policy enforcement (1 replica, reduced resources)
- **Falco**: Runtime security monitoring (eBPF mode)
- **Trivy Operator**: Vulnerability scanning
- **Test Applications**: Sample apps for testing policies

### Sample Policies
- **Required Labels**: Enforces app labels on deployments
- **Resource Limits**: Ensures pods have resource constraints
- **Security Context**: Basic pod security standards

## 🧪 **Testing Your Security Lab**

### Test 1: Policy Enforcement
```bash
# This should FAIL (missing required label)
kubectl create deployment test-fail --image=nginx -n security-test

# This should SUCCEED
kubectl create deployment test-pass --image=nginx -n security-test
kubectl label deployment test-pass app=test-app -n security-test
```

### Test 2: Vulnerability Scanning
```bash
# Check vulnerability reports
kubectl get vulnerabilityreports -A

# View a specific report
kubectl describe vulnerabilityreport <report-name> -n <namespace>
```

### Test 3: Runtime Security
```bash
# Generate security events (be careful!)
kubectl exec -it deployment/nginx-test -n security-test -- sh
# Inside the pod, try: wget suspicious-site.com

# Check Falco alerts
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50
```

## 🔧 **Common WSL Issues & Solutions**

### Issue: kubectl not found
```bash
# Install kubectl in WSL
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

### Issue: helm not found
```bash
# Install helm in WSL
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

### Issue: Cannot connect to Docker
```bash
# Make sure Docker Desktop is running
# In WSL, you should be able to run:
docker ps

# If not, restart Docker Desktop and ensure WSL integration is enabled
```

### Issue: Minikube won't start
```bash
# Clean start
minikube delete
minikube start --driver=docker --cpus=4 --memory=4096

# If still issues, try:
minikube start --driver=virtualbox  # Alternative driver
```

## 📊 **Resource Requirements**

### Minimum System Requirements
- **RAM**: 8GB total (4GB for Minikube)
- **CPU**: 4 cores (2 for Minikube)
- **Disk**: 20GB free space
- **WSL2**: Latest version

### Optimized for Local Development
```yaml
# All tools are configured with reduced resource requirements:
OPA Gatekeeper:
  CPU: 100m requests, 500m limits
  Memory: 256Mi requests, 512Mi limits

Falco:
  CPU: 100m requests, 500m limits  
  Memory: 256Mi requests, 512Mi limits

Trivy Operator:
  Standard resources (auto-scales)
```

## 🎓 **Learning Exercises**

### Week 1: Basic Setup
1. Deploy all security tools
2. Run health checks
3. Explore Kubernetes security concepts

### Week 2: Policy Development
1. Modify existing OPA policies
2. Create custom Falco rules
3. Test policy enforcement

### Week 3: Advanced Features
1. Implement network policies
2. Set up vulnerability scanning workflows
3. Practice incident response

### Week 4: Integration
1. Integrate with monitoring tools
2. Set up automated alerts
3. Document your security procedures

## 🔄 **Daily Workflow**

### Starting Your Security Lab
```bash
# 1. Start your Kubernetes environment
minikube start  # or ensure Docker Desktop is running

# 2. Verify security tools
./scripts/security-health-check-wsl.sh

# 3. Check for new vulnerabilities
kubectl get vulnerabilityreports -A

# 4. Review security events
kubectl logs -n falco -l app.kubernetes.io/name=falco --since=1h
```

### Experimenting with Security
```bash
# 1. Deploy test applications
kubectl create deployment experiment --image=nginx:latest -n security-test

# 2. Apply new policies
kubectl apply -f configs/gatekeeper/

# 3. Monitor results
kubectl get constraints
kubectl logs -n gatekeeper-system deployment/gatekeeper-controller-manager
```

## 🆘 **Troubleshooting**

### If Deployment Fails
```bash
# Check cluster status
kubectl cluster-info

# Check node resources
kubectl describe nodes

# Check failed pods
kubectl get pods -A | grep -v Running
kubectl describe pod <pod-name> -n <namespace>
```

### If Security Tools Don't Work
```bash
# Reset and redeploy
helm uninstall gatekeeper -n gatekeeper-system
helm uninstall falco -n falco
kubectl delete namespace trivy-system

# Wait a moment, then redeploy
./scripts/deploy-phase1-tools-wsl.sh
```

### Getting Help
```bash
# Check logs for specific components
kubectl logs -n gatekeeper-system deployment/gatekeeper-controller-manager
kubectl logs -n falco daemonset/falco
kubectl logs -n trivy-system deployment/trivy-operator

# Check events
kubectl get events -A --sort-by='.lastTimestamp'
```

This setup provides a complete, locally-running Kubernetes security lab perfect for learning, testing, and developing security policies!
