#!/bin/bash

# Phase 1 Security Tools Deployment Script
# This script deploys the critical security tools for Kubernetes hardening

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

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if helm is available
    if ! command -v helm &> /dev/null; then
        error "helm is not installed or not in PATH"
        exit 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Deploy OPA Gatekeeper
deploy_gatekeeper() {
    log "Deploying OPA Gatekeeper..."
    
    # Add Helm repository
    helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
    helm repo update
    
    # Create namespace
    kubectl create namespace ${NAMESPACE_GATEKEEPER} --dry-run=client -o yaml | kubectl apply -f -
    
    # Install Gatekeeper
    helm upgrade --install gatekeeper gatekeeper/gatekeeper \
        --namespace ${NAMESPACE_GATEKEEPER} \
        --set replicas=3 \
        --set auditInterval=60 \
        --set metricsBackends=prometheus \
        --wait
    
    success "OPA Gatekeeper deployed successfully"
}

# Deploy Falco
deploy_falco() {
    log "Deploying Falco..."
    
    # Add Helm repository
    helm repo add falcosecurity https://falcosecurity.github.io/charts
    helm repo update
    
    # Create namespace
    kubectl create namespace ${NAMESPACE_FALCO} --dry-run=client -o yaml | kubectl apply -f -
    
    # Install Falco
    helm upgrade --install falco falcosecurity/falco \
        --namespace ${NAMESPACE_FALCO} \
        --set driver.kind=ebpf \
        --set falco.grpc.enabled=true \
        --set falco.grpcOutput.enabled=true \
        --set falco.httpOutput.enabled=true \
        --set serviceMonitor.enabled=true \
        --set grafanaDashboard.enabled=true \
        --wait
    
    success "Falco deployed successfully"
}

# Deploy Trivy Operator
deploy_trivy() {
    log "Deploying Trivy Operator..."
    
    # Create namespace
    kubectl create namespace ${NAMESPACE_TRIVY} --dry-run=client -o yaml | kubectl apply -f -
    
    # Install Trivy Operator
    kubectl apply -f https://raw.githubusercontent.com/aquasecurity/trivy-operator/main/deploy/static/trivy-operator.yaml
    
    # Wait for deployment
    kubectl wait --for=condition=available --timeout=300s deployment/trivy-operator -n ${NAMESPACE_TRIVY}
    
    success "Trivy Operator deployed successfully"
}

# Apply basic security policies
apply_basic_policies() {
    log "Applying basic security policies..."
    
    # Wait for Gatekeeper to be ready
    kubectl wait --for=condition=available --timeout=300s deployment/gatekeeper-controller-manager -n ${NAMESPACE_GATEKEEPER}
    
    # Apply policies if config directory exists
    if [ -d "../configs/gatekeeper" ]; then
        warning "Gatekeeper policies not applied - please customize configs/gatekeeper first"
    fi
    
    success "Basic policies setup completed"
}

# Validate deployments
validate_deployments() {
    log "Validating deployments..."
    
    # Check Gatekeeper
    if kubectl get pods -n ${NAMESPACE_GATEKEEPER} | grep -q Running; then
        success "Gatekeeper is running"
    else
        error "Gatekeeper deployment failed"
        return 1
    fi
    
    # Check Falco
    if kubectl get pods -n ${NAMESPACE_FALCO} | grep -q Running; then
        success "Falco is running"
    else
        error "Falco deployment failed"
        return 1
    fi
    
    # Check Trivy Operator
    if kubectl get pods -n ${NAMESPACE_TRIVY} | grep -q Running; then
        success "Trivy Operator is running"
    else
        error "Trivy Operator deployment failed"
        return 1
    fi
    
    success "All deployments validated successfully"
}

# Print next steps
print_next_steps() {
    echo ""
    echo -e "${GREEN}🎉 Phase 1 Security Tools Deployment Completed!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Customize security policies in configs/ directory"
    echo "2. Apply Cilium network policies for your applications"
    echo "3. Configure monitoring and alerting"
    echo "4. Test security policies in development environment"
    echo ""
    echo "Useful commands:"
    echo "  kubectl get pods -A | grep -E '(gatekeeper|falco|trivy)'"
    echo "  kubectl get constraints"
    echo "  kubectl get vulnerabilityreports -A"
    echo ""
}

# Main execution
main() {
    log "Starting Phase 1 Security Tools Deployment"
    
    check_prerequisites
    deploy_gatekeeper
    deploy_falco
    deploy_trivy
    apply_basic_policies
    validate_deployments
    print_next_steps
    
    success "Deployment completed successfully!"
}

# Execute main function
main "$@"
