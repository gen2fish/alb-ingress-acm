# ALB Ingress Controller ACM Provisioner

This Controller watches for Ingress objects with a specific annotation, creates a certificate in ACM with DNS Validation, and adds the new certificate ARN to the annotation for ALB Ingress Controller to use

## Annotation

"aws.acm.kubernetes.io/create"

## Limitations

- One host per ingress
- The Route53 Zone must be in the same account
- This assumes all zones that match a domain name are setup
