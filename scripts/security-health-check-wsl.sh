#!/bin/bash

# WSL-Optimized Security Health Check Script
# Designed for Minikube and Docker Desktop environments

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Initialize counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Environment detection
ENVIRONMENT="unknown"

# Logging functions
log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

check_passed() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASSED_CHECKS++))
    ((TOTAL_CHECKS++))
}

check_failed() {
    echo -e "${RED}✗${NC} $1"
    ((FAILED_CHECKS++))
    ((TOTAL_CHECKS++))
}

check_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((WARNING_CHECKS++))
    ((TOTAL_CHECKS++))
}

# Detect environment
detect_environment() {
    if kubectl config current-context 2>/dev/null | grep -q "minikube"; then
        ENVIRONMENT="minikube"
    elif kubectl config current-context 2>/dev/null | grep -q "docker-desktop"; then
        ENVIRONMENT="docker-desktop"
    else
        ENVIRONMENT="other"
    fi
}

# Check WSL environment
check_wsl_environment() {
    log "Checking WSL environment setup..."
    
    # Check if we're in WSL
    if grep -q Microsoft /proc/version 2>/dev/null; then
        check_passed "Running in WSL environment"
    else
        check_warning "Not running in WSL (may be native Linux)"
    fi
    
    # Check kubectl installation
    if command -v kubectl &> /dev/null; then
        KUBECTL_VERSION=$(kubectl version --client --short 2>/dev/null | cut -d' ' -f3 || echo "unknown")
        check_passed "kubectl is installed (version: $KUBECTL_VERSION)"
    else
        check_failed "kubectl is not installed"
    fi
    
    # Check helm installation
    if command -v helm &> /dev/null; then
        HELM_VERSION=$(helm version --short 2>/dev/null | cut -d'+' -f1 || echo "unknown")
        check_passed "helm is installed (version: $HELM_VERSION)"
    else
        check_failed "helm is not installed"
    fi
    
    # Check cluster connectivity
    if kubectl cluster-info &>/dev/null; then
        CLUSTER_CONTEXT=$(kubectl config current-context 2>/dev/null || echo "unknown")
        check_passed "Connected to Kubernetes cluster ($CLUSTER_CONTEXT)"
    else
        check_failed "Cannot connect to Kubernetes cluster"
    fi
}

# Check environment-specific setup
check_environment_setup() {
    log "Checking $ENVIRONMENT environment setup..."
    
    case $ENVIRONMENT in
        "minikube")
            # Check Minikube status
            if command -v minikube &> /dev/null; then
                MINIKUBE_STATUS=$(minikube status --format='{{.Host}}' 2>/dev/null || echo "unknown")
                if [ "$MINIKUBE_STATUS" = "Running" ]; then
                    check_passed "Minikube is running"
                    
                    # Check resources
                    MINIKUBE_CPUS=$(minikube config get cpus 2>/dev/null || echo "unknown")
                    MINIKUBE_MEMORY=$(minikube config get memory 2>/dev/null || echo "unknown")
                    
                    if [ "$MINIKUBE_CPUS" != "unknown" ] && [ "$MINIKUBE_MEMORY" != "unknown" ]; then
                        if [ "$MINIKUBE_CPUS" -ge 4 ] && [ "$MINIKUBE_MEMORY" -ge 4096 ]; then
                            check_passed "Minikube has adequate resources (CPUs: $MINIKUBE_CPUS, Memory: ${MINIKUBE_MEMORY}MB)"
                        else
                            check_warning "Minikube may need more resources (CPUs: $MINIKUBE_CPUS, Memory: ${MINIKUBE_MEMORY}MB)"
                        fi
                    fi
                else
                    check_failed "Minikube is not running (status: $MINIKUBE_STATUS)"
                fi
            else
                check_warning "Minikube command not found"
            fi
            ;;
        "docker-desktop")
            # Check Docker Desktop Kubernetes
            if kubectl get nodes 2>/dev/null | grep -q "docker-desktop"; then
                check_passed "Docker Desktop Kubernetes is running"
            else
                check_warning "Docker Desktop Kubernetes may not be enabled"
            fi
            ;;
        *)
            check_warning "Unknown Kubernetes environment: $ENVIRONMENT"
            ;;
    esac
}

# Check if security tools are deployed
check_security_tools() {
    log "Checking security tools deployment..."
    
    # Check OPA Gatekeeper
    if kubectl get deployment gatekeeper-controller-manager -n gatekeeper-system &>/dev/null; then
        if kubectl get pods -n gatekeeper-system --no-headers 2>/dev/null | grep -q "Running"; then
            GATEKEEPER_PODS=$(kubectl get pods -n gatekeeper-system --no-headers | grep Running | wc -l)
            check_passed "OPA Gatekeeper is deployed and running ($GATEKEEPER_PODS pods)"
        else
            check_failed "OPA Gatekeeper is deployed but not running properly"
        fi
    else
        check_failed "OPA Gatekeeper is not deployed"
    fi
    
    # Check Falco
    if kubectl get daemonset falco -n falco &>/dev/null; then
        running_pods=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
        total_nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
        if [ "$running_pods" -eq "$total_nodes" ]; then
            check_passed "Falco is deployed and running on all nodes ($running_pods/$total_nodes)"
        elif [ "$running_pods" -gt 0 ]; then
            check_warning "Falco is deployed but only running on $running_pods/$total_nodes nodes"
        else
            check_failed "Falco is deployed but not running"
        fi
    else
        check_failed "Falco is not deployed"
    fi
    
    # Check Trivy Operator
    if kubectl get deployment trivy-operator -n trivy-system &>/dev/null; then
        if kubectl get pods -n trivy-system --no-headers 2>/dev/null | grep -q "Running"; then
            check_passed "Trivy Operator is deployed and running"
        else
            check_warning "Trivy Operator is deployed but may still be starting"
        fi
    else
        check_failed "Trivy Operator is not deployed"
    fi
}

# Check Gatekeeper policies (local environment friendly)
check_gatekeeper_policies() {
    log "Checking OPA Gatekeeper policies..."
    
    # Check if constraint templates exist
    templates=$(kubectl get constrainttemplates --no-headers 2>/dev/null | wc -l)
    if [ "$templates" -gt 0 ]; then
        check_passed "Found $templates constraint templates"
        
        # List templates
        template_names=$(kubectl get constrainttemplates --no-headers -o custom-columns=NAME:.metadata.name 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
        log "Templates: $template_names"
    else
        check_warning "No constraint templates found - basic policies not configured"
    fi
    
    # Check if constraints exist
    constraints=$(kubectl get constraints --no-headers 2>/dev/null | wc -l)
    if [ "$constraints" -gt 0 ]; then
        check_passed "Found $constraints active constraints"
    else
        check_warning "No constraints found - policies not enforced"
    fi
    
    # Check for policy violations
    violations=$(kubectl get constraints -o jsonpath='{range .items[*]}{.status.totalViolations}{"\n"}{end}' 2>/dev/null | grep -v "^$" | awk '{sum+=$1} END {print sum+0}')
    if [ "$violations" -eq 0 ]; then
        check_passed "No policy violations detected"
    else
        check_warning "Found $violations policy violations - check constraint status"
    fi
}

# Check test applications
check_test_applications() {
    log "Checking test applications..."
    
    # Check if test namespace exists
    if kubectl get namespace security-test &>/dev/null; then
        check_passed "Test namespace 'security-test' exists"
        
        # Check test applications
        test_apps=$(kubectl get deployments -n security-test --no-headers 2>/dev/null | wc -l)
        if [ "$test_apps" -gt 0 ]; then
            check_passed "Found $test_apps test application(s) in security-test namespace"
            
            # Check if apps are running
            running_apps=$(kubectl get pods -n security-test --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
            if [ "$running_apps" -gt 0 ]; then
                check_passed "$running_apps test application pod(s) are running"
            else
                check_warning "Test applications exist but no pods are running"
            fi
        else
            check_warning "No test applications found in security-test namespace"
        fi
    else
        check_warning "Test namespace 'security-test' not found - run deployment script first"
    fi
}

# Check pod security (simplified for local env)
check_pod_security() {
    log "Checking pod security standards..."
    
    # Check for privileged pods (excluding system namespaces)
    privileged_pods=$(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].securityContext.privileged}{"\n"}{end}' 2>/dev/null | grep -v -E "(kube-system|gatekeeper-system|falco|trivy-system)" | grep -c "true" || echo "0")
    
    if [ "$privileged_pods" -eq 0 ]; then
        check_passed "No privileged pods found in application namespaces"
    else
        check_warning "Found $privileged_pods privileged pods in application namespaces"
    fi
    
    # Check resource limits
    pods_without_limits=$(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].resources.limits}{"\n"}{end}' 2>/dev/null | grep -v -E "(kube-system|gatekeeper-system|falco|trivy-system)" | grep -c "map\[\]" || echo "0")
    
    if [ "$pods_without_limits" -eq 0 ]; then
        check_passed "All application pods have resource limits defined"
    else
        check_warning "Found $pods_without_limits pods without resource limits"
    fi
}

# Check vulnerability scanning
check_vulnerability_scanning() {
    log "Checking vulnerability scanning..."
    
    # Check for vulnerability reports
    vuln_reports=$(kubectl get vulnerabilityreports -A --no-headers 2>/dev/null | wc -l)
    if [ "$vuln_reports" -gt 0 ]; then
        check_passed "Found $vuln_reports vulnerability reports"
        
        # Check for critical vulnerabilities
        critical_vulns=$(kubectl get vulnerabilityreports -A -o jsonpath='{range .items[*]}{.report.summary.criticalCount}{"\n"}{end}' 2>/dev/null | awk '{sum+=$1} END {print sum+0}' || echo "0")
        if [ "$critical_vulns" -eq 0 ]; then
            check_passed "No critical vulnerabilities found"
        else
            check_warning "Found $critical_vulns critical vulnerabilities across all reports"
        fi
        
        # Check high vulnerabilities
        high_vulns=$(kubectl get vulnerabilityreports -A -o jsonpath='{range .items[*]}{.report.summary.highCount}{"\n"}{end}' 2>/dev/null | awk '{sum+=$1} END {print sum+0}' || echo "0")
        if [ "$high_vulns" -eq 0 ]; then
            check_passed "No high-severity vulnerabilities found"
        else
            check_warning "Found $high_vulns high-severity vulnerabilities"
        fi
    else
        check_warning "No vulnerability reports found - scanning may not be active yet"
    fi
    
    # Check config audit reports
    config_reports=$(kubectl get configauditreports -A --no-headers 2>/dev/null | wc -l)
    if [ "$config_reports" -gt 0 ]; then
        check_passed "Found $config_reports configuration audit reports"
    else
        check_warning "No configuration audit reports found"
    fi
}

# Check Falco alerts (local environment)
check_falco_alerts() {
    log "Checking Falco security events..."
    
    if kubectl get pods -n falco -l app.kubernetes.io/name=falco --no-headers 2>/dev/null | grep -q Running; then
        # Check recent Falco logs for events
        recent_events=$(kubectl logs -n falco -l app.kubernetes.io/name=falco --since=10m 2>/dev/null | grep -c "Priority" || echo "0")
        
        if [ "$recent_events" -eq 0 ]; then
            check_passed "No security events detected in last 10 minutes"
        else
            check_warning "Found $recent_events security events in last 10 minutes - review Falco logs"
        fi
        
        # Check if Falco is generating any output
        total_logs=$(kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=100 2>/dev/null | wc -l || echo "0")
        if [ "$total_logs" -gt 10 ]; then
            check_passed "Falco is actively monitoring and logging events"
        else
            check_warning "Falco may not be generating logs - check configuration"
        fi
    else
        check_warning "Falco is not running - cannot check security events"
    fi
}

# Generate local environment summary
generate_local_summary() {
    echo ""
    echo "========================================="
    echo "    WSL SECURITY LAB HEALTH SUMMARY"
    echo "========================================="
    echo ""
    echo -e "Environment: ${BLUE}$ENVIRONMENT${NC}"
    echo -e "Total Checks: ${BLUE}$TOTAL_CHECKS${NC}"
    echo -e "Passed: ${GREEN}$PASSED_CHECKS${NC}"
    echo -e "Warnings: ${YELLOW}$WARNING_CHECKS${NC}"
    echo -e "Failed: ${RED}$FAILED_CHECKS${NC}"
    echo ""
    
    # Calculate percentage
    if [ "$TOTAL_CHECKS" -gt 0 ]; then
        passed_percentage=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
        echo -e "Security Score: ${BLUE}$passed_percentage%${NC}"
    fi
    
    echo ""
    if [ "$FAILED_CHECKS" -eq 0 ]; then
        echo -e "${GREEN}🎉 Excellent! Your WSL security lab is working great!${NC}"
    elif [ "$FAILED_CHECKS" -le 2 ]; then
        echo -e "${YELLOW}⚠️  Good progress! A few items need attention.${NC}"
    else
        echo -e "${RED}🔧 Several issues detected. Check the failed items above.${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}Quick Actions:${NC}"
    
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        echo "1. Address failed checks (see red ✗ items above)"
    fi
    
    if [ "$WARNING_CHECKS" -gt 0 ]; then
        echo "2. Review warnings for potential improvements"
    fi
    
    echo "3. Test security policies:"
    echo "   kubectl create deployment test --image=nginx -n security-test"
    echo ""
    echo "4. View security events:"
    echo "   kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20"
    echo ""
    echo "5. Check vulnerability reports:"
    echo "   kubectl get vulnerabilityreports -A"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "• Experiment with security policies in configs/ directory"
    echo "• Deploy test applications and observe security responses"
    echo "• Customize Falco rules for your specific use cases"
    echo "• Practice incident response procedures"
    echo ""
}

# Main execution
main() {
    echo "🔒 WSL Kubernetes Security Health Check"
    echo "========================================"
    echo ""
    
    detect_environment
    check_wsl_environment
    check_environment_setup
    check_security_tools
    check_gatekeeper_policies
    check_test_applications
    check_pod_security
    check_vulnerability_scanning
    check_falco_alerts
    
    generate_local_summary
}

# Execute main function
main "$@"
