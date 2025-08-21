# OPA Gatekeeper Configurations

This directory contains OPA Gatekeeper constraint templates and constraints for implementing security policies.

## Files Structure

```
gatekeeper/
├── templates/
│   ├── required-labels.yaml          # Enforce required labels
│   ├── allowed-registries.yaml       # Container registry restrictions
│   ├── pod-security-standards.yaml   # Pod security policies
│   ├── resource-limits.yaml          # Resource quotas enforcement
│   └── network-policies.yaml         # Network policy requirements
├── constraints/
│   ├── security-labels.yaml          # Security labeling constraints
│   ├── harbor-registry.yaml          # Harbor registry enforcement
│   ├── baseline-security.yaml        # Baseline pod security
│   └── production-limits.yaml        # Production resource limits
└── README.md
```

## Usage

1. Apply constraint templates first:
```bash
kubectl apply -f templates/
```

2. Apply constraints:
```bash
kubectl apply -f constraints/
```

3. Verify policies are working:
```bash
kubectl get constraints
```

## Integration with ArgoCD

These policies can be deployed using ArgoCD for GitOps workflow:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: gatekeeper-policies
spec:
  project: default
  source:
    repoURL: https://github.com/armansheikhhosseini/Cloud-Security-Stack
    path: configs/gatekeeper
    targetRevision: main
  destination:
    server: https://kubernetes.default.svc
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```
