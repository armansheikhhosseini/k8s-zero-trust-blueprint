# 🚀 Phase 1 Implementation Guide: Critical Security Tools

## Overview
This guide provides step-by-step implementation instructions for the most critical security tools identified in the security blueprint. These tools address immediate security gaps and provide foundation for zero trust architecture.

## 🎯 Phase 1 Tools Priority

1. **OPA Gatekeeper** - Policy enforcement and admission control
2. **Falco** - Runtime threat detection and monitoring  
3. **Enhanced Cilium Network Policies** - Microsegmentation
4. **Trivy Operator** - Continuous security scanning

---

## 🔐 1. OPA Gatekeeper Implementation

### Prerequisites
- Kubernetes cluster with admission controllers enabled
- Helm 3.x installed
- Cluster admin permissions

### Installation

```bash
# Add Gatekeeper Helm repository
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo update

# Create namespace
kubectl create namespace gatekeeper-system

# Install Gatekeeper
helm install gatekeeper gatekeeper/gatekeeper \
  --namespace gatekeeper-system \
  --set replicas=3 \
  --set auditInterval=60 \
  --set metricsBackends=prometheus \
  --set violations.allowedUsers="admin@your-domain.com"
```

### Basic Policy Templates

#### 1. Required Labels Policy
```yaml
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
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: must-have-security-labels
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment", "ReplicaSet"]
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    labels: ["app.kubernetes.io/name", "app.kubernetes.io/version", "security.policy/tier"]
```

#### 2. Image Registry Restriction
```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8sallowedrepos
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedRepos
      validation:
        type: object
        properties:
          repos:
            type: array
            items:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sallowedrepos
        
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
          not any(satisfied)
          msg := sprintf("Container <%v> uses disallowed image <%v>", [container.name, container.image])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata:
  name: repo-must-be-harbor
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment"]
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system", "gatekeeper-system"]
  parameters:
    repos:
      - "harbor.your-domain.com/"
      - "ghcr.io/your-org/"
```

#### 3. Pod Security Standards
```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8spodsecuritystandards
spec:
  crd:
    spec:
      names:
        kind: K8sPodSecurityStandards
      validation:
        type: object
        properties:
          runAsNonRoot:
            type: boolean
          allowPrivilegeEscalation:
            type: boolean
          readOnlyRootFilesystem:
            type: boolean
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spodsecuritystandards
        
        violation[{"msg": msg}] {
          input.parameters.runAsNonRoot == true
          container := input.review.object.spec.containers[_]
          container.securityContext.runAsNonRoot != true
          msg := sprintf("Container <%v> must run as non-root user", [container.name])
        }
        
        violation[{"msg": msg}] {
          input.parameters.allowPrivilegeEscalation == false
          container := input.review.object.spec.containers[_]
          container.securityContext.allowPrivilegeEscalation != false
          msg := sprintf("Container <%v> must not allow privilege escalation", [container.name])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPodSecurityStandards
metadata:
  name: pod-security-baseline
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system", "gatekeeper-system"]
  parameters:
    runAsNonRoot: true
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
```

### Integration with ArgoCD
```yaml
# Create ArgoCD Application for Gatekeeper policies
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: gatekeeper-policies
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/k8s-security-policies
    path: gatekeeper
    targetRevision: main
  destination:
    server: https://kubernetes.default.svc
    namespace: gatekeeper-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

---

## 🛡️ 2. Falco Implementation

### Installation via Helm

```bash
# Add Falco Helm repository
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Create namespace
kubectl create namespace falco

# Install Falco
helm install falco falcosecurity/falco \
  --namespace falco \
  --set driver.kind=ebpf \
  --set falco.grpc.enabled=true \
  --set falco.grpcOutput.enabled=true \
  --set falco.httpOutput.enabled=true \
  --set falco.httpOutput.url=http://webhook-receiver:8080/falco \
  --set serviceMonitor.enabled=true \
  --set grafanaDashboard.enabled=true
```

### Custom Falco Rules for Your Environment

#### Container Security Rules
```yaml
# /etc/falco/rules.d/custom_rules.yaml
- rule: Unexpected Container Privilege Escalation
  desc: Detect privilege escalation in containers
  condition: >
    spawned_process and container and
    (proc.name in (sudo, su, doas) or
     (proc.name=sh and proc.args contains "-p") or
     (proc.name=bash and proc.args contains "-p"))
  output: >
    Privilege escalation attempt in container 
    (user=%user.name command=%proc.cmdline container=%container.name image=%container.image.repository)
  priority: WARNING
  tags: [container, privilege_escalation]

- rule: Unexpected Network Tool in Container
  desc: Detect network reconnaissance tools
  condition: >
    spawned_process and container and
    proc.name in (nmap, nc, netcat, ncat, wget, curl) and
    not proc.args contains "localhost"
  output: >
    Network tool executed in container 
    (user=%user.name command=%proc.cmdline container=%container.name image=%container.image.repository)
  priority: WARNING
  tags: [container, network, recon]

- rule: Kubernetes Secret Access
  desc: Detect access to Kubernetes secrets
  condition: >
    open_read and fd.filename startswith /var/run/secrets/kubernetes.io/ and
    not proc.name in (kubelet, kube-proxy)
  output: >
    Kubernetes secret accessed 
    (file=%fd.name proc=%proc.name container=%container.name)
  priority: WARNING
  tags: [kubernetes, secrets]
```

#### Application-Specific Rules
```yaml
# Rules for your application namespaces
- rule: Suspicious Database Connection
  desc: Detect unusual database connections
  condition: >
    spawned_process and container and
    k8s.ns.name in (arzdigital-prod, prime-prod, ata-prod) and
    proc.name in (psql, mysql, mongo) and
    not proc.args contains "localhost"
  output: >
    Suspicious database connection from application 
    (namespace=%k8s.ns.name pod=%k8s.pod.name command=%proc.cmdline)
  priority: HIGH
  tags: [database, suspicious_connection]

- rule: Unauthorized File Modification in App
  desc: Detect file modifications in application directories
  condition: >
    open_write and container and
    k8s.ns.name in (arzdigital-prod, prime-prod, ata-prod) and
    fd.filename startswith /app/ and
    not proc.name in (node, java, python, php-fpm)
  output: >
    Unauthorized file modification 
    (file=%fd.name namespace=%k8s.ns.name pod=%k8s.pod.name proc=%proc.name)
  priority: HIGH
  tags: [file_modification, application]
```

### Falco Integration with Wazuh SIEM

#### Webhook Configuration
```yaml
# falco-webhook-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-webhook-config
  namespace: falco
data:
  config.yaml: |
    webhook:
      address: "http://wazuh-manager.wazuh:55000/security_events/falco"
      headers:
        Authorization: "Bearer your-wazuh-token"
        Content-Type: "application/json"
```

#### Falco Sidekick for Enhanced Alerting
```bash
# Install Falco Sidekick for multiple output targets
helm install falco-sidekick falcosecurity/falco-sidekick \
  --namespace falco \
  --set config.webhook.address=http://wazuh-webhook:8080 \
  --set config.prometheus.address=http://prometheus:9090 \
  --set config.grafana.hostport=grafana:3000 \
  --set config.telegram.token="your-telegram-bot-token" \
  --set config.telegram.chatid="your-chat-id"
```

---

## 🌐 3. Enhanced Cilium Network Policies

### Prerequisites
- Cilium CNI already installed (✅ You have this)
- Cilium CLI installed
- Network policy enforcement enabled

### Enable Cilium Network Policy Enforcement

```bash
# Check current Cilium configuration
kubectl get configmap cilium-config -n kube-system -o yaml

# Enable network policy enforcement if not already enabled
kubectl patch configmap cilium-config -n kube-system --type merge -p '{"data":{"enable-policy":"true"}}'

# Restart Cilium agents
kubectl rollout restart daemonset cilium -n kube-system
```

### Default Deny Network Policies

#### Namespace-Level Default Deny
```yaml
# Apply to each application namespace
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: default-deny-all
  namespace: arzdigital-prod
spec:
  endpointSelector: {}
  ingress: []
  egress: []
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-dns
  namespace: arzdigital-prod
spec:
  endpointSelector: {}
  egress:
  - toEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: kube-system
        k8s:app: coredns
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
      - port: "53"
        protocol: TCP
```

### Application-Specific Network Policies

#### Web Application to Database
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: web-to-db-policy
  namespace: arzdigital-prod
spec:
  endpointSelector:
    matchLabels:
      app: arz-appserver-prod
  egress:
  - toEndpoints:
    - matchLabels:
        app: postgresql
    toPorts:
    - ports:
      - port: "5432"
        protocol: TCP
  - toEndpoints:
    - matchLabels:
        app: redis
    toPorts:
    - ports:
      - port: "6379"
        protocol: TCP
```

#### API Gateway Policies
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: api-gateway-policy
  namespace: arzdigital-prod
spec:
  endpointSelector:
    matchLabels:
      app: api-gateway
  ingress:
  - fromEntities:
    - "world"
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
      - port: "443" 
        protocol: TCP
  egress:
  - toEndpoints:
    - matchLabels:
        tier: backend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
```

#### Cross-Namespace Communication
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-cross-namespace
  namespace: arzdigital-prod
spec:
  endpointSelector:
    matchLabels:
      app: arz-appserver-prod
  egress:
  - toEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: setabr
        app: kafka
    toPorts:
    - ports:
      - port: "9092"
        protocol: TCP
```

### L7 HTTP Policies
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: api-l7-policy
  namespace: arzdigital-prod
spec:
  endpointSelector:
    matchLabels:
      app: api-backend
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
      rules:
        http:
        - method: "GET"
          path: "/api/v1/.*"
        - method: "POST"
          path: "/api/v1/users"
        - method: "PUT"
          path: "/api/v1/users/.*"
```

---

## 🔍 4. Trivy Operator Implementation

### Installation

```bash
# Install Trivy Operator
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/trivy-operator/main/deploy/static/trivy-operator.yaml

# Or via Helm
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm install trivy-operator aqua/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --set="trivy.ignoreUnfixed=true" \
  --set="operator.scanJobTimeout=10m"
```

### Configuration for Your Harbor Registry

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: trivy-operator-config
  namespace: trivy-system
data:
  trivy.repository: "harbor.your-domain.com/trivy"
  trivy.tag: "latest"
  trivy.severity: "CRITICAL,HIGH,MEDIUM"
  trivy.ignoreUnfixed: "true"
  scanJob.podTemplateName: "trivy-scan-job"
---
apiVersion: v1
kind: Secret
metadata:
  name: trivy-operator-harbor-secret
  namespace: trivy-system
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: <base64-encoded-harbor-credentials>
```

### Vulnerability Scanning Policies

#### Auto-scan New Deployments
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: trivy-operator-config
  namespace: trivy-system
data:
  vulnerabilityReports.scanner: "Trivy"
  configAuditReports.scanner: "Trivy"
  exposedSecretReports.scanner: "Trivy"
  scanJob.scanOnlyCurrentRevision: "true"
  scanJob.compressLogs: "true"
```

### Integration with OPA Gatekeeper

#### Block Deployments with Critical Vulnerabilities
```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8svulnerabilitypolicy
spec:
  crd:
    spec:
      names:
        kind: K8sVulnerabilityPolicy
      validation:
        type: object
        properties:
          maxCritical:
            type: integer
          maxHigh:
            type: integer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8svulnerabilitypolicy
        
        violation[{"msg": msg}] {
          # Check if vulnerability report exists
          input.review.object.kind == "Deployment"
          
          # This would require a more complex implementation
          # connecting to Trivy Operator APIs
          msg := "Deployment blocked due to critical vulnerabilities"
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sVulnerabilityPolicy
metadata:
  name: vulnerability-gate
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment"]
  parameters:
    maxCritical: 0
    maxHigh: 5
```

---

## 📊 Monitoring and Alerting Integration

### Prometheus Metrics Collection

#### ServiceMonitor for Falco
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: falco
  namespace: falco
spec:
  selector:
    matchLabels:
      app: falco
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

#### Grafana Dashboard Import
```bash
# Import Falco dashboard
curl -X POST \
  http://grafana:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer your-grafana-token' \
  -d '{
    "dashboard": {
      "id": null,
      "title": "Falco Security Events",
      "tags": ["security", "falco"],
      "timezone": "browser"
    }
  }'
```

### Alerting Rules

#### Critical Security Alerts
```yaml
# prometheus-security-rules.yaml
groups:
- name: security.rules
  rules:
  - alert: FalcoSecurityEvent
    expr: increase(falco_events_total[5m]) > 0
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: "Falco security event detected"
      description: "Security event detected by Falco: {{ $labels.rule }}"

  - alert: GatekeeperPolicyViolation
    expr: increase(gatekeeper_violations_total[5m]) > 0
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: "Gatekeeper policy violation"
      description: "Policy violation: {{ $labels.policy }}"

  - alert: CriticalVulnerabilityDetected
    expr: trivy_vulnerability_count{severity="CRITICAL"} > 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Critical vulnerability detected"
      description: "Critical vulnerability found in {{ $labels.image }}"
```

---

## ✅ Phase 1 Validation Checklist

### OPA Gatekeeper Validation
- [ ] Gatekeeper pods running in gatekeeper-system namespace
- [ ] Basic constraint templates applied
- [ ] Policy violations being detected and blocked
- [ ] Metrics exposed for Prometheus
- [ ] Integration with ArgoCD working

### Falco Validation  
- [ ] Falco pods running on all nodes
- [ ] Custom rules loaded and active
- [ ] Security events being generated
- [ ] Alerts forwarding to Wazuh/Telegram
- [ ] Prometheus metrics available

### Cilium Network Policies
- [ ] Network policy enforcement enabled
- [ ] Default deny policies applied
- [ ] Application-specific policies working
- [ ] DNS resolution still functional
- [ ] Cross-namespace communication controlled

### Trivy Operator
- [ ] Operator pods running in trivy-system
- [ ] Vulnerability reports being generated
- [ ] Critical vulnerabilities identified
- [ ] Integration with Harbor registry
- [ ] Reports accessible via kubectl

### Overall Security Posture
- [ ] Security events flowing to SIEM
- [ ] Dashboards showing security metrics
- [ ] Alert notifications working
- [ ] Policy violations being prevented
- [ ] Security scanning automated

---

## 🔄 Next Steps for Phase 2

After Phase 1 implementation and validation:

1. **SPIFFE/SPIRE Implementation** - Service identity framework
2. **Linkerd Service Mesh** - mTLS and advanced networking
3. **Cosign Integration** - Container image signing  
4. **OpenTelemetry** - Enhanced observability

This completes the critical security foundation for your zero trust architecture. Each tool should be thoroughly tested in a development environment before production deployment.
