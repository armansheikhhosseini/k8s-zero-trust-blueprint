# Falco Security Rules

This directory contains custom Falco rules for your Kubernetes environment.

## Files Structure

```
falco/
├── rules/
│   ├── custom-rules.yaml             # Custom security rules
│   ├── kubernetes-audit.yaml         # Kubernetes API audit rules
│   ├── application-security.yaml     # Application-specific rules
│   └── network-security.yaml         # Network monitoring rules
├── config/
│   ├── falco.yaml                    # Main Falco configuration
│   ├── falco-sidekick.yaml          # Sidekick configuration
│   └── webhook-config.yaml          # Webhook integration config
└── README.md
```

## Installation

Deploy Falco using Helm:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --values config/falco.yaml
```

## Custom Rules

The custom rules are tailored for your specific environment:

- **Container Security**: Privilege escalation detection
- **Network Monitoring**: Suspicious connections
- **Kubernetes Events**: API abuse detection
- **Application Security**: File modifications, process execution

## Integration

- **Wazuh SIEM**: Security events forwarding
- **Grafana**: Dashboards and visualization
- **Telegram**: Real-time alerts
- **Prometheus**: Metrics collection
