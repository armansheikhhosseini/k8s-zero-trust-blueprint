# 🏗️ Kubernetes Technology Stack by Service Layer

## 🏢 Infrastructure as a Service (IaaS)

### 💻 Compute Resources

* Hetzner BMS (Bare Metal Servers)  
* OpenNebula (Virtualization Platform)

### ⚙️ Configuration Management

* Ansible  
* AWX (Ansible Web Interface)

### 💾 Storage

* Longhorn (Distributed Storage)  
* MinIO Operator (S3-compatible Storage)

### 🔄 Backup & Disaster Recovery

* Velero  
* Rclone

## 🧩 Platform as a Service (PaaS)

### ☸️ Kubernetes Platform

* K3s (Lightweight Kubernetes)

### 🌐 Networking

* Cilium (CNI)  
* Kube-VIP  
* CoreDNS  
* Traefik (Ingress Controller)  
* MetalLB (Load Balancer)

### 🚀 Cluster & Application Management

* ArgoCD (GitOps)  
* Helm (Package Management)  
* Rancher (Cluster Management)  
* Backstage (Developer Portal)  
* Harbor Registry (Container Registry)  
* ArgoCD Image Updater

### ☁️ Kubernetes Operators

* ECK Operator (Elastic Cloud on Kubernetes)  
* Dragonfly Operator

### 🗄️ Database Platforms

* MongoDB  
* PostgreSQL (via CNPG Operator)  
* Redis  
* MySQL (Percona Operator)  
* PSMDB Operator

### 📨 Message Broker Platforms

* Stellar Kafka

### 👨‍💻 Developer Tools

* JupyterHub  
* External Secret Operator  
* Secret Migration

### 🔄 Data Processing

* Airbyte (Data integration platform)

### ⏱️ Workflow Engines

* n8n  
* Airflow

### 🔌 API Management

* API Gateway (APISIX)  
* Kong API Gateway

## 📱 Software as a Service (SaaS)

### 🔐 Identity & Security Services

* Keycloak (Identity Provider)  
* HashiCorp Vault (Secrets Management)  
* DefectDojo (Vulnerability Management)  
* Wazuh (SIEM)  
* Harbor Trivy (Container Image Scanner)  
* cert-manager

### 📊 Monitoring & Observability

* Graylog (Log Management)  
* Grafana (Visualization)  
* Prometheus (Metrics)  
* Kubecost Analyzer (Cost Management)  
* Telegram Alerting  
* Events Exporter  
* Logging System

### 📈 Analytics Services

* Metabase (Business Intelligence)  
* SonarSource (Code Quality)  
* Sentry (Error Tracking)

### 🧰 Application Services

* Centrifugo (Real-time Messaging)  
* Adminer (Database Management)  
* imgproxy (Image Processing)  
* Typesense (Search Engine)  
* Varnish ROI



# 🚀 Products Service Layers Cluster

## Clusters Overview

| Cluster Name | Purpose | Namespaces |
| :---- | :---- | :---- |
| **Nebula** | Infrastructure Management | Core Infrastructure Services |
| **Uranus** | Production Environment | arzdigital-prod, prime-prod, ata-prod |
| **Voyager** | Development Environment | arzdigital-dev |
| **Ranger** | Development Environment | prime-dev |
| **Apollo** | Development Environment | ata-dev |
| **Messaging** | Message Broker Services | Kafka for all products |

## 🌌 Nebula Cluster (Infrastructure)

Main cluster management platforms:

* **Rancher** (Kubernetes Cluster Management)  
* **ArgoCD** (GitOps Deployment)

Infrastructure management services including:

* ArgoCD Image Updater  
* Backstage  
* CNPG Operator  
* DefectDojo  
* ECK Operator  
* Events Exporter  
* Graylog  
* Harbor Registry  
* HashiCorp Vault  
* Keycloak  
* Kubecost Analyzer  
* Longhorn  
* MinIO Operator  
* Infra n8n  
* PSMDB Operator  
* Redis  
* Sentry  
* SonarSource  
* Telegram Alerting  
* Velero

## 🪐 Uranus Cluster (Production)

### Arzdigital Production (arzdigital-prod)

* arz-appserver-prod  
* arz-argus-alert-prod & seeder-prod  
* arz-automate-breaking-news-service-prod  
* arz-crypto-pulse-prod  
* arz-discourse-controller-prod  
* arz-dispatcher-prod  
* arz-fides-loyalty-program-prod  
* arz-heimdall-prod  
* arz-hermes-prod  
* arz-hr-landing-prod  
* arz-ideas-prod  
* arz-lahze-service-prod & web-prod  
* arz-market-alert-prod  
* Multiple MA (Mini App) services:  
  * account-api-prod & admin-api-prod  
  * airdrop-services-prod  
  * price-services-prod  
  * task-services-prod  
  * telegram-api-prod  
  * visit-services-prod  
  * warehouse-prod  
* arz-mini-app-components-prod  
* arz-morpheus-story-prod  
* arz-nexus-prod  
* arz-notification-dispatch-service-prod  
* arz-revive-ads-prod & controller-prod  
* arz-social-news-delivery-prod  
* arz-subvia-prod  
* arz-telegram-dispatcher-prod  
* arz-trends-prod

### Prime Production (prime-prod)

* prime-airflow-prod  
* prime-assets-manager-prod  
* prime-clickhouse-prod  
* prime-exchange-historical-data-prod  
* prime-exchanges-last-ticker-prod  
* prime-highvolumewritetest-prod  
* prime-muninn-prod  
* prime-odin-prod  
* prime-price-collector-prod  
* prime-socket-prod  
* prime-web-client-prod  
* prime-ws-exchange-demo-prod  
* prime-sentinel-prod

### ATA Production (ata-prod)

* ata-alerts-prod  
* ata-bots-prod  
* ata-cron-job-prod  
* ata-dashboard-api-prod  
* ata-dashboard-prod  
* ata-markets-prod  
* ata-matches-prod  
* ata-proxy-prod  
* ata-report-prod  
* ata-wordpress-prod  
* tradesk-wordpress-prod

### SSO (Production)

* sso-anubis-prod

### Supporting Services for Production

* Airbyte  
* API Gateway (APISIX)  
* Centrifugo  
* Clickhouse Operator  
* CNPG Operator  
* Dragonfly Operator  
* Events Exporter  
* External Secret Operator  
* Image Proxy services  
* JupyterHub  
* Kubecost Analyzer  
* Logging System  
* Longhorn  
* Metabase  
* MinIO Operator  
* MongoDB  
* MySQL Percona Operator  
* n8n Workflows  
* PostgreSQL  
* PSMDB Operator  
* Redis  
* Secret Migration  
* Telegram Alerting  
* Typesense services  
* Velero

## 🔭 Voyager Cluster (Arzdigital Development)

### Arzdigital Development (arzdigital-dev)

* arz-appserver-dev  
* arz-argus-alert-dev & seeder-dev  
* arz-automate-breaking-news-service-dev  
* arz-crypto-pulse-dev  
* arz-discourse-controller-dev  
* arz-dispatcher-dev  
* arz-fides-loyalty-program-dev  
* arz-heimdall-dev  
* arz-hermes-dev  
* arz-hr-landing-dev  
* arz-ideas-dev  
* arz-lahze-service-dev & web-dev  
* arz-market-alert-dev  
* Multiple MA (Mini App) services:  
  * account-api-dev & admin-api-dev  
  * airdrop-services-dev  
  * price-services-dev  
  * task-services-dev  
  * telegram-api-dev  
  * visit-services-dev  
  * warehouse-dev  
* arz-mini-app-components-dev  
* arz-morpheus-story-dev  
* arz-nexus-dev  
* arz-notification-dispatch-service-dev  
* arz-revive-ads-dev & controller-dev  
* arz-social-news-delivery-dev  
* arz-subvia-dev  
* arz-telegram-dispatcher-dev  
* arz-trends-dev  
* arz-aurora-dev

### SSO (Development)

* sso-anubis-dev

### Infrastructure Services for Arzdigital Development

* Adminer  
* Airbyte  
* CNPG Operator  
* Events Exporter  
* Logging System  
* Longhorn  
* Metabase  
* MinIO Operator  
* MongoDB  
* PSMDB Operator  
* Telegram Alerting  
* Varnish ROI  
* Velero

## 🌟 Ranger Cluster (Prime Development)

### Prime Development (prime-dev)

* prime-assets-manager-dev  
* prime-clickhouse-dev  
* prime-exchange-historical-data-dev  
* prime-exchanges-last-ticker-dev  
* prime-highvolumewritetest-dev  
* prime-market-api-dev  
* prime-muninn-dev  
* prime-odin-dev  
* prime-price-collector-dev  
* prime-quota-dev & metrics-dev  
* prime-sentinel-dev  
* prime-socket-dev  
* prime-web-client-dev  
* prime-ws-exchange-demo-dev  
* prime-airflow-dev  
* ranger-api-gw-apisix

### Infrastructure Services for Prime Development

* Adminer  
* Airflow  
* Centrifugo  
* Clickhouse Operator  
* CNPG Operator  
* Dragonfly Operator  
* Events Exporter  
* Logging System  
* Longhorn  
* MinIO Operator  
* MongoDB  
* n8n Workflow for Prime  
* PSMDB Operator  
* Telegram Alerting  
* Velero

## 🚀 Apollo Cluster (ATA Development)

### ATA Development (ata-dev)

* ata-alerts-dev  
* ata-bots-dev  
* ata-cron-job-dev  
* ata-dashboard-api-dev  
* ata-dashboard-dev & test  
* ata-markets-dev  
* ata-matches-dev  
* ata-proxy-dev  
* ata-report-dev  
* ata-wordpress-dev  
* tradesk-wordpress-dev

### Infrastructure Services for ATA Development

* apollo-events-exporter  
* apollo-logging-system  
* apollo-longhorn  
* apollo-minio-operator  
* apollo-telegram-alerting  
* apollo-velero

## 📨 Messaging Cluster (Message Brokers)

Dedicated to message broker services:

* Stellar Kafka
