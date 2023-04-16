# ALB Ingress Controller ACM Provisioner

This Controller watches for Ingress objects with a specific annotation and creates a certificate in ACM with DNS Validation

## Annotation

"aws.acm.kubernetes.io/create"

## Limitations

- One host per ingress
- The Route53 Zone must be in the same account
