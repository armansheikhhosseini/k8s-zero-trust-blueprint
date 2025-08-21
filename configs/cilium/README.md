# Cilium Network Policies

This directory contains Cilium network policies for implementing microsegmentation and zero trust networking.

## Files Structure

```
cilium/
├── base-policies/
│   ├── default-deny.yaml             # Default deny all traffic
│   ├── allow-dns.yaml                # Allow DNS resolution
│   ├── allow-system.yaml             # Allow system traffic
│   └── ingress-controller.yaml       # Ingress controller policies
├── application-policies/
│   ├── arzdigital-prod.yaml          # Arzdigital production policies
│   ├── prime-prod.yaml               # Prime production policies
│   ├── ata-prod.yaml                 # ATA production policies
│   └── cross-namespace.yaml          # Cross-namespace communication
├── l7-policies/
│   ├── http-api-policies.yaml        # HTTP/API layer policies
│   ├── database-policies.yaml        # Database access policies
│   └── kafka-policies.yaml           # Kafka communication policies
└── README.md
```

## Implementation Strategy

1. **Default Deny**: Start with deny-all policies
2. **Essential Services**: Allow DNS, system services
3. **Application Traffic**: Add specific application rules
4. **Cross-Namespace**: Configure inter-service communication
5. **L7 Policies**: Implement application-layer filtering

## Deployment Order

```bash
# 1. Apply base policies (start with development clusters)
kubectl apply -f base-policies/ -n voyager

# 2. Apply application-specific policies
kubectl apply -f application-policies/

# 3. Apply L7 policies (after testing L3/L4)
kubectl apply -f l7-policies/
```

## Testing and Validation

Use Cilium CLI for testing:

```bash
# Test connectivity
cilium connectivity test

# Monitor network policies
cilium monitor --type policy-verdict

# Check policy status
kubectl get cnp -A
```
