#!/bin/bash

# EKS Node Group User Data Script
# This script configures EC2 instances to join the EKS cluster

set -o xtrace

# Update system packages
yum update -y

# Install additional packages
yum install -y \
    amazon-cloudwatch-agent \
    aws-cli \
    htop \
    jq

# Configure CloudWatch agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
    "agent": {
        "metrics_collection_interval": 60,
        "run_as_user": "cwagent"
    },
    "metrics": {
        "namespace": "EKS/NodeGroup",
        "metrics_collected": {
            "cpu": {
                "measurement": [
                    "cpu_usage_idle",
                    "cpu_usage_iowait",
                    "cpu_usage_user",
                    "cpu_usage_system"
                ],
                "metrics_collection_interval": 60
            },
            "disk": {
                "measurement": [
                    "used_percent"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "diskio": {
                "measurement": [
                    "io_time"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "mem": {
                "measurement": [
                    "mem_used_percent"
                ],
                "metrics_collection_interval": 60
            }
        }
    },
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/var/log/messages",
                        "log_group_name": "/aws/eks/${cluster_name}/node-logs",
                        "log_stream_name": "{instance_id}/messages"
                    },
                    {
                        "file_path": "/var/log/dmesg",
                        "log_group_name": "/aws/eks/${cluster_name}/node-logs",
                        "log_stream_name": "{instance_id}/dmesg"
                    }
                ]
            }
        }
    }
}
EOF

# Start CloudWatch agent
systemctl enable amazon-cloudwatch-agent
systemctl start amazon-cloudwatch-agent

# Bootstrap the node to join the EKS cluster
/etc/eks/bootstrap.sh ${cluster_name} ${bootstrap_arguments}

# Configure kubelet with additional arguments
echo 'KUBELET_EXTRA_ARGS=--node-labels=workload-type=backend,node-type=ec2' >> /etc/kubernetes/kubelet/kubelet-config.json

# Restart kubelet to apply changes
systemctl restart kubelet

# Install additional monitoring tools
curl -L -o /usr/local/bin/kubectl https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubectl
chmod +x /usr/local/bin/kubectl

# Configure log rotation for container logs
cat > /etc/logrotate.d/docker-containers << 'EOF'
/var/lib/docker/containers/*/*.log {
    rotate 5
    daily
    compress
    size=10M
    missingok
    delaycompress
    copytruncate
}
EOF

# Signal completion (removed the problematic CloudFormation signal)
echo "Node configuration completed successfully"
