# Trivy Operator Configurations

This directory contains configurations for Trivy Operator to implement continuous security scanning.

## Files Structure

```
trivy/
├── operator/
│   ├── trivy-operator.yaml           # Operator deployment config
│   ├── configmap.yaml                # Scanner configuration
│   └── rbac.yaml                     # RBAC permissions
├── policies/
│   ├── vulnerability-policies.yaml   # Vulnerability scanning policies
│   ├── compliance-policies.yaml      # Compliance scanning config
│   └── sbom-policies.yaml            # SBOM generation config
├── integration/
│   ├── harbor-secret.yaml            # Harbor registry credentials
│   ├── opa-integration.yaml          # OPA Gatekeeper integration
│   └── prometheus-rules.yaml         # Alerting rules
└── README.md
```

## Installation

```bash
# Install Trivy Operator
kubectl apply -f operator/

# Configure Harbor integration
kubectl apply -f integration/harbor-secret.yaml

# Apply scanning policies
kubectl apply -f policies/
```

## Features

- **Vulnerability Scanning**: Continuous image vulnerability assessment
- **Compliance Scanning**: CIS benchmarks and security standards
- **SBOM Generation**: Software Bill of Materials creation
- **Harbor Integration**: Seamless integration with existing registry
- **Policy Enforcement**: Block deployments with critical vulnerabilities

## Monitoring

View scan results:

```bash
# Check vulnerability reports
kubectl get vulnerabilityreports -A

# Check compliance reports
kubectl get configauditreports -A

# View specific report
kubectl describe vulnerabilityreport <report-name>
```
