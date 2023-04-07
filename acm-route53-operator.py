import kopf
import boto3
import base64
import time
from os import environ
from kubernetes import client, config

config.load_kube_config()
k8s_client = client.CoreV1Api()
if environ.get("LOCALSTACK_URL"):
  print("LOCALSTACK")
  acm_client = boto3.client("acm", endpoint_url=environ.get("LOCALSTACK_URL") )
  route53_client = boto3.client("route53", endpoint_url=environ.get("LOCALSTACK_URL"))
else:
  acm_client = boto3.client("acm")
  route53_client = boto3.client("route53")

INGRESS_RESOURCE_GROUP = "networking.k8s.io"
INGRESS_RESOURCE_VERSION = "v1"
INGRESS_RESOURCE_PLURAL = "ingresses"

ACM_ANNOTATION = "aws.acm.kubernetes.io/create"


def create_acm_certificate(domain_name):
    print(f"Creating Certificate for {domain_name}")

    response = acm_client.request_certificate(
      DomainName=domain_name,
      ValidationMethod="DNS",
      IdempotencyToken=base64.urlsafe_b64encode(domain_name.encode()).decode()[:32]
    )
    return response["CertificateArn"]


def create_route53_validation_records(certificate_arn, hosted_zone_id):
    response = acm_client.describe_certificate(CertificateArn=certificate_arn)
    validation_records = response["Certificate"]["DomainValidationOptions"]

    for record in validation_records:
        route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": record["ResourceRecord"]["Name"],
                            "Type": record["ResourceRecord"]["Type"],
                            "TTL": 300,
                            "ResourceRecords": [{"Value": record["ResourceRecord"]["Value"]}],
                        },
                    }
                ],
            },
        )

def domain_split(domain, zones):
  if domain == "":
    return None
  elif domain in zones:
    return domain
  else:
    return domain_split( '.'.join(domain.split('.')[1:]), zones )

def find_hosted_zone_id(domain_name):
    hosted_zones = route53_client.list_hosted_zones()["HostedZones"]
    hosted_zone_id = None

    zones = { zone["Name"].rstrip("."): zone["Id"] for zone in hosted_zones}

    matching_zone = domain_split(domain_name, zones)

    if matching_zone is None:
        raise ValueError(f"Hosted zone for domain '{domain_name}' not found")
    return zones[matching_zone]


@kopf.on.update('ingresses')
@kopf.on.create('ingresses')
def ingress_created(body, **kwargs):
    print(body)
    ingress = body["metadata"]
    ingress_name = ingress["name"]
    annotations = ingress.get("annotations", {})

    if annotations.get(ACM_ANNOTATION) == "true":
        validation_domains = [rule["host"] for rule in body["spec"]["rules"]]
        for domain in validation_domains:
          print(f"Ingess {ingress_name} has domain {domain}, processing")
          hosted_zone_id = find_hosted_zone_id(domain)
          certificate_arn = create_acm_certificate(domain)
          create_route53_validation_records(certificate_arn, hosted_zone_id)
          print(f"Ingress {ingress_name} has been processed with ACM certificate {certificate_arn}")




if __name__ == "__main__":
    kopf.run()
