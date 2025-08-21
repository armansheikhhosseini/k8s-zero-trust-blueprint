#!/bin/bash

# Security Health Check Script
# Validates the security posture of your Kubernetes clusters

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

# Check if tools are deployed
check_security_tools() {
    log "Checking security tools deployment..."
    
    # Check OPA Gatekeeper
    if kubectl get deployment gatekeeper-controller-manager -n gatekeeper-system &>/dev/null; then
        if kubectl get pods -n gatekeeper-system | grep -q "Running"; then
            check_passed "OPA Gatekeeper is deployed and running"
        else
            check_failed "OPA Gatekeeper is deployed but not running properly"
        fi
    else
        check_failed "OPA Gatekeeper is not deployed"
    fi
    
    # Check Falco
    if kubectl get daemonset falco -n falco &>/dev/null; then
        running_pods=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco --field-selector=status.phase=Running --no-headers | wc -l)
        total_nodes=$(kubectl get nodes --no-headers | wc -l)
        if [ "$running_pods" -eq "$total_nodes" ]; then
            check_passed "Falco is deployed and running on all nodes ($running_pods/$total_nodes)"
        else
            check_warning "Falco is deployed but only running on $running_pods/$total_nodes nodes"
        fi
    else
        check_failed "Falco is not deployed"
    fi
    
    # Check Trivy Operator
    if kubectl get deployment trivy-operator -n trivy-system &>/dev/null; then
        if kubectl get pods -n trivy-system | grep -q "Running"; then
            check_passed "Trivy Operator is deployed and running"
        else
            check_failed "Trivy Operator is deployed but not running properly"
        fi
    else
        check_failed "Trivy Operator is not deployed"
    fi
}

# Check Gatekeeper policies
check_gatekeeper_policies() {
    log "Checking OPA Gatekeeper policies..."
    
    # Check if constraint templates exist
    templates=$(kubectl get constrainttemplates --no-headers 2>/dev/null | wc -l)
    if [ "$templates" -gt 0 ]; then
        check_passed "Found $templates constraint templates"
    else
        check_warning "No constraint templates found - policies not configured"
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
        check_warning "Found $violations policy violations"
    fi
}

# Check Cilium network policies
check_network_policies() {
    log "Checking network policies..."
    
    # Check if Cilium is running
    if kubectl get daemonset cilium -n kube-system &>/dev/null; then
        check_passed "Cilium CNI is deployed"
    else
        check_warning "Cilium CNI not found - network policies may not work"
    fi
    
    # Check for network policies
    cilium_policies=$(kubectl get ciliumnetworkpolicies -A --no-headers 2>/dev/null | wc -l)
    k8s_policies=$(kubectl get networkpolicies -A --no-headers 2>/dev/null | wc -l)
    
    if [ "$cilium_policies" -gt 0 ] || [ "$k8s_policies" -gt 0 ]; then
        check_passed "Found network policies (Cilium: $cilium_policies, K8s: $k8s_policies)"
    else
        check_failed "No network policies found - cluster is not microsegmented"
    fi
}

# Check pod security standards
check_pod_security() {
    log "Checking pod security standards..."
    
    # Check for privileged pods
    privileged_pods=$(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].securityContext.privileged}{"\n"}{end}' 2>/dev/null | grep -c "true" || echo "0")
    
    if [ "$privileged_pods" -eq 0 ]; then
        check_passed "No privileged pods found"
    else
        check_warning "Found $privileged_pods privileged pods"
    fi
    
    # Check for pods running as root
    root_pods=$(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].securityContext.runAsUser}{"\n"}{end}' 2>/dev/null | grep -E "(^|\s)0(\s|$)" | wc -l)
    
    if [ "$root_pods" -eq 0 ]; then
        check_passed "No pods running as root user"
    else
        check_warning "Found $root_pods pods potentially running as root"
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
        critical_vulns=$(kubectl get vulnerabilityreports -A -o jsonpath='{range .items[*]}{.report.summary.criticalCount}{"\n"}{end}' 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
        if [ "$critical_vulns" -eq 0 ]; then
            check_passed "No critical vulnerabilities found"
        else
            check_failed "Found $critical_vulns critical vulnerabilities"
        fi
    else
        check_warning "No vulnerability reports found - scanning may not be configured"
    fi
}

# Check RBAC configuration
check_rbac() {
    log "Checking RBAC configuration..."
    
    # Check for cluster-admin bindings
    cluster_admin_bindings=$(kubectl get clusterrolebindings -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.metadata.name}{"\n"}{end}' 2>/dev/null | wc -l)
    
    if [ "$cluster_admin_bindings" -le 3 ]; then
        check_passed "Limited cluster-admin bindings found ($cluster_admin_bindings)"
    else
        check_warning "Many cluster-admin bindings found ($cluster_admin_bindings) - review for principle of least privilege"
    fi
    
    # Check for default service account usage
    default_sa_pods=$(kubectl get pods -A -o jsonpath='{range .items[?(@.spec.serviceAccountName=="default" || @.spec.serviceAccountName=="")]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}' 2>/dev/null | wc -l)
    
    if [ "$default_sa_pods" -eq 0 ]; then
        check_passed "No pods using default service account"
    else
        check_warning "Found $default_sa_pods pods using default service account"
    fi
}

# Check secrets and sensitive data
check_secrets() {
    log "Checking secrets management..."
    
    # Check for unencrypted secrets
    secrets_count=$(kubectl get secrets -A --no-headers 2>/dev/null | wc -l)
    check_passed "Found $secrets_count secrets in cluster"
    
    # Check for external secrets operator
    if kubectl get deployment external-secrets -n external-secrets-system &>/dev/null; then
        check_passed "External Secrets Operator is deployed"
    else
        check_warning "External Secrets Operator not found - consider for secret management"
    fi
}

# Generate summary report
generate_summary() {
    echo ""
    echo "========================================="
    echo "         SECURITY HEALTH SUMMARY"
    echo "========================================="
    echo ""
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
        echo -e "${GREEN}🎉 Great job! Your cluster security is in good shape!${NC}"
    elif [ "$FAILED_CHECKS" -le 3 ]; then
        echo -e "${YELLOW}⚠️  Some security improvements needed.${NC}"
    else
        echo -e "${RED}🚨 Critical security issues detected. Immediate action required!${NC}"
    fi
    
    echo ""
    echo "Recommendations:"
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        echo "1. Address failed security checks immediately"
    fi
    if [ "$WARNING_CHECKS" -gt 0 ]; then
        echo "2. Review and improve warning items"
    fi
    echo "3. Run this check regularly to maintain security posture"
    echo "4. Consider implementing additional security tools from Phase 2"
    echo ""
}

# Main execution
main() {
    echo "🔒 Kubernetes Security Health Check"
    echo "===================================="
    echo ""
    
    check_security_tools
    check_gatekeeper_policies
    check_network_policies
    check_pod_security
    check_vulnerability_scanning
    check_rbac
    check_secrets
    
    generate_summary
}

# Execute main function
main "$@"
