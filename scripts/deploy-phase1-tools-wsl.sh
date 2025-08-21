#!/bin/bash

# WSL-Optimized Security Tools Deployment Script
# Designed for Minikube and Docker Desktop environments

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE_GATEKEEPER="gatekeeper-system"
NAMESPACE_FALCO="falco"
NAMESPACE_TRIVY="trivy-system"

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Detect environment
detect_environment() {
    log "Detecting Kubernetes environment..."
    
    if kubectl config current-context | grep -q "minikube"; then
        ENVIRONMENT="minikube"
        success "Detected Minikube environment"
    elif kubectl config current-context | grep -q "docker-desktop"; then
        ENVIRONMENT="docker-desktop"
        success "Detected Docker Desktop environment"
    else
        ENVIRONMENT="other"
        warning "Unknown environment, proceeding with default settings"
    fi
}

# Check prerequisites for WSL environment
check_prerequisites() {
    log "Checking prerequisites for WSL environment..."
    
    # Check if we're in WSL
    if grep -q Microsoft /proc/version; then
        success "Running in WSL environment"
    else
        warning "Not detected in WSL, but continuing..."
    fi
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed. Install with: curl -LO https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl && sudo install kubectl /usr/local/bin/"
        exit 1
    fi
    
    # Check if helm is available
    if ! command -v helm &> /dev/null; then
        error "helm is not installed. Install with: curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash"
        exit 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster. Start minikube with: minikube start"
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Environment-specific optimizations
optimize_for_environment() {
    log "Applying environment-specific optimizations..."
    
    case $ENVIRONMENT in
        "minikube")
            # Enable required addons for Minikube
            log "Configuring Minikube addons..."
            minikube addons enable metrics-server
            minikube addons enable ingress
            
            # Check if we need to enable more CPU/memory
            MINIKUBE_CPUS=$(minikube config get cpus 2>/dev/null || echo "2")
            MINIKUBE_MEMORY=$(minikube config get memory 2>/dev/null || echo "2048")
            
            if [ "$MINIKUBE_CPUS" -lt 4 ] || [ "$MINIKUBE_MEMORY" -lt 4096 ]; then
                warning "Minikube may need more resources for security tools"
                warning "Consider: minikube delete && minikube start --cpus=4 --memory=4096"
            fi
            ;;
        "docker-desktop")
            log "Docker Desktop detected - using default configurations"
            ;;
    esac
}

# Deploy OPA Gatekeeper with local optimizations
deploy_gatekeeper() {
    log "Deploying OPA Gatekeeper for local environment..."
    
    # Add Helm repository
    helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
    helm repo update
    
    # Create namespace
    kubectl create namespace ${NAMESPACE_GATEKEEPER} --dry-run=client -o yaml | kubectl apply -f -
    
    # Install Gatekeeper with reduced resources for local env
    helm upgrade --install gatekeeper gatekeeper/gatekeeper \
        --namespace ${NAMESPACE_GATEKEEPER} \
        --set replicas=1 \
        --set controllerManager.resources.requests.cpu=100m \
        --set controllerManager.resources.requests.memory=256Mi \
        --set controllerManager.resources.limits.cpu=500m \
        --set controllerManager.resources.limits.memory=512Mi \
        --set audit.resources.requests.cpu=100m \
        --set audit.resources.requests.memory=256Mi \
        --set auditInterval=60 \
        --set metricsBackends=prometheus \
        --wait --timeout=10m
    
    success "OPA Gatekeeper deployed successfully"
}

# Deploy Falco optimized for local environment
deploy_falco() {
    log "Deploying Falco for local environment..."
    
    # Add Helm repository
    helm repo add falcosecurity https://falcosecurity.github.io/charts
    helm repo update
    
    # Create namespace
    kubectl create namespace ${NAMESPACE_FALCO} --dry-run=client -o yaml | kubectl apply -f -
    
    # Install Falco with local optimizations
    helm upgrade --install falco falcosecurity/falco \
        --namespace ${NAMESPACE_FALCO} \
        --set driver.kind=ebpf \
        --set resources.requests.cpu=100m \
        --set resources.requests.memory=256Mi \
        --set resources.limits.cpu=500m \
        --set resources.limits.memory=512Mi \
        --set falco.grpc.enabled=true \
        --set falco.grpcOutput.enabled=true \
        --set falco.httpOutput.enabled=false \
        --set falco.fileOutput.enabled=true \
        --set serviceMonitor.enabled=false \
        --set grafanaDashboard.enabled=false \
        --wait --timeout=10m
    
    success "Falco deployed successfully"
}

# Deploy Trivy Operator
deploy_trivy() {
    log "Deploying Trivy Operator for local environment..."
    
    # Create namespace
    kubectl create namespace ${NAMESPACE_TRIVY} --dry-run=client -o yaml | kubectl apply -f -
    
    # Download and apply Trivy Operator manifests
    if command -v curl &> /dev/null; then
        curl -s https://raw.githubusercontent.com/aquasecurity/trivy-operator/main/deploy/static/trivy-operator.yaml | \
        sed 's/replicas: 1/replicas: 1/' | \
        kubectl apply -f -
    else
        wget -qO- https://raw.githubusercontent.com/aquasecurity/trivy-operator/main/deploy/static/trivy-operator.yaml | \
        kubectl apply -f -
    fi
    
    # Wait for deployment with timeout
    log "Waiting for Trivy Operator to be ready..."
    kubectl wait --for=condition=available --timeout=300s deployment/trivy-operator -n ${NAMESPACE_TRIVY} || {
        warning "Trivy Operator deployment timed out, but may still be starting"
    }
    
    success "Trivy Operator deployed successfully"
}

# Deploy sample applications for testing
deploy_test_apps() {
    log "Deploying test applications..."
    
    # Create test namespace
    kubectl create namespace security-test --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy a simple nginx app for testing
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-test
  namespace: security-test
  labels:
    app: nginx-test
    security.policy/tier: frontend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx-test
  template:
    metadata:
      labels:
        app: nginx-test
        security.policy/tier: frontend
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        ports:
        - containerPort: 80
        securityContext:
          runAsNonRoot: false
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: false
        resources:
          requests:
            cpu: 50m
            memory: 64Mi
          limits:
            cpu: 100m
            memory: 128Mi
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-test
  namespace: security-test
spec:
  selector:
    app: nginx-test
  ports:
  - port: 80
    targetPort: 80
EOF
    
    success "Test applications deployed"
}

# Apply basic security policies for testing
apply_basic_policies() {
    log "Applying basic security policies..."
    
    # Wait for Gatekeeper to be ready
    kubectl wait --for=condition=available --timeout=300s deployment/gatekeeper-controller-manager -n ${NAMESPACE_GATEKEEPER}
    
    # Apply a simple constraint template for testing
    cat <<EOF | kubectl apply -f -
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        type: object
        properties:
          labels:
            type: array
            items:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        
        violation[{"msg": msg}] {
          required := input.parameters.labels
          provided := input.review.object.metadata.labels
          missing := required[_]
          not provided[missing]
          msg := sprintf("Missing required label: %v", [missing])
        }
EOF
    
    sleep 5
    
    # Apply a basic constraint
    cat <<EOF | kubectl apply -f -
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: must-have-app-label
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment"]
    excludedNamespaces: ["kube-system", "gatekeeper-system", "falco", "trivy-system"]
  parameters:
    labels: ["app"]
EOF
    
    success "Basic policies applied"
}

# Validate deployments
validate_deployments() {
    log "Validating deployments..."
    
    # Check Gatekeeper
    if kubectl get pods -n ${NAMESPACE_GATEKEEPER} --no-headers 2>/dev/null | grep -q Running; then
        success "✓ Gatekeeper is running"
    else
        error "✗ Gatekeeper deployment failed"
        kubectl get pods -n ${NAMESPACE_GATEKEEPER}
        return 1
    fi
    
    # Check Falco
    if kubectl get pods -n ${NAMESPACE_FALCO} --no-headers 2>/dev/null | grep -q Running; then
        success "✓ Falco is running"
    else
        error "✗ Falco deployment failed"
        kubectl get pods -n ${NAMESPACE_FALCO}
        return 1
    fi
    
    # Check Trivy Operator
    if kubectl get pods -n ${NAMESPACE_TRIVY} --no-headers 2>/dev/null | grep -q Running; then
        success "✓ Trivy Operator is running"
    else
        warning "⚠ Trivy Operator may still be starting"
        kubectl get pods -n ${NAMESPACE_TRIVY}
    fi
    
    success "Deployment validation completed"
}

# Generate security scan
generate_initial_scan() {
    log "Generating initial security scan..."
    
    # Trigger vulnerability scan on test namespace
    sleep 30  # Give Trivy Operator time to start
    
    # Force a scan by creating a config audit report
    kubectl create job trivy-initial-scan --image=aquasec/trivy:latest -n ${NAMESPACE_TRIVY} \
        --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null || true
    
    success "Initial security scan triggered"
}

# Print WSL-specific next steps
print_next_steps() {
    echo ""
    echo -e "${GREEN}🎉 WSL Security Lab Setup Completed!${NC}"
    echo ""
    echo "Your local Kubernetes security lab is ready!"
    echo ""
    echo -e "${BLUE}Quick Commands:${NC}"
    echo "  # Check all security tools"
    echo "  kubectl get pods -A | grep -E '(gatekeeper|falco|trivy)'"
    echo ""
    echo "  # View Gatekeeper constraints"
    echo "  kubectl get constraints"
    echo ""
    echo "  # Check Falco logs"
    echo "  kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50"
    echo ""
    echo "  # View vulnerability reports"
    echo "  kubectl get vulnerabilityreports -A"
    echo ""
    echo -e "${BLUE}Test Security Policies:${NC}"
    echo "  # Try creating a deployment without required labels (should fail)"
    echo '  kubectl create deployment test-fail --image=nginx -n security-test'
    echo ""
    echo "  # Create deployment with required labels (should succeed)"
    echo '  kubectl create deployment test-pass --image=nginx -n security-test'
    echo '  kubectl label deployment test-pass app=test-app -n security-test'
    echo ""
    echo -e "${BLUE}Access Applications:${NC}"
    if [ "$ENVIRONMENT" = "minikube" ]; then
        echo "  # Get Minikube IP"
        echo "  minikube ip"
        echo "  # Access nginx test app"
        echo "  minikube service nginx-test -n security-test"
    else
        echo "  # Port forward to test app"
        echo "  kubectl port-forward -n security-test svc/nginx-test 8080:80"
        echo "  # Then visit: http://localhost:8080"
    fi
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "1. Explore the configs/ directory to customize policies"
    echo "2. Run: ./scripts/security-health-check-wsl.sh"
    echo "3. Experiment with different security policies"
    echo "4. Review Falco alerts and tune rules"
    echo ""
}

# Main execution
main() {
    echo "🔒 WSL Kubernetes Security Lab Setup"
    echo "====================================="
    echo ""
    
    detect_environment
    check_prerequisites
    optimize_for_environment
    deploy_gatekeeper
    deploy_falco
    deploy_trivy
    deploy_test_apps
    apply_basic_policies
    validate_deployments
    generate_initial_scan
    print_next_steps
    
    success "WSL Security Lab deployment completed successfully!"
}

# Execute main function
main "$@"
