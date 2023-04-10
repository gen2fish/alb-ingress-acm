import kopf
import boto3
import base64
import time
from os import environ
from kubernetes import client, config

config.load_kube_config()
k8s_client = client.CoreV1Api()
AWS_REGION = environ.get("AWS_REGION", "us-east-1")

if environ.get("LOCALSTACK_URL"):
  print("LOCALSTACK")
  acm_client = boto3.client("acm", endpoint_url=environ.get("LOCALSTACK_URL") )
  route53_client = boto3.client("route53", endpoint_url=environ.get("LOCALSTACK_URL"))
else:
  acm_client = boto3.client("acm", region=AWS_REGION)
  route53_client = boto3.client("route53")

INGRESS_RESOURCE_GROUP = "networking.k8s.io"
INGRESS_RESOURCE_VERSION = "v1"
INGRESS_RESOURCE_PLURAL = "ingresses"
hosted_zones = route53_client.list_hosted_zones()["HostedZones"]
ACM_ANNOTATION = "aws.acm.kubernetes.io/create"

def get_existing_certificate(domain_name, ingress_name, namespace):
    response = acm_client.list_certificates(
        CertificateStatuses=["PENDING_VALIDATION", "ISSUED", "INACTIVE", "EXPIRED", "VALIDATION_TIMED_OUT"]
    )

    for certificate in response["CertificateSummaryList"]:
        certificate_arn = certificate["CertificateArn"]
        tags = acm_client.list_tags_for_certificate(CertificateArn=certificate_arn)["Tags"]

        tags_dict = {tag["Key"]: tag["Value"] for tag in tags}

        if certificate["DomainName"] == domain_name:
            return certificate_arn

    return None


def create_acm_certificate(domain_name, ingress_name, namespace):
    print(f"Creating Certificate for {domain_name}")

    response = acm_client.request_certificate(
      DomainName=domain_name,
      ValidationMethod="DNS",
      IdempotencyToken=base64.urlsafe_b64encode(domain_name.encode()).decode()[:32]
    )

    acm_client.add_tags_to_certificate(
        CertificateArn=response["CertificateArn"],
        Tags=[
            {"Key": "IngressName", "Value": ingress_name},
            {"Key": "Namespace", "Value": namespace},
        ],
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
    namespace = ingress["namespace"]
    annotations = ingress.get("annotations", {})

    if annotations.get(ACM_ANNOTATION) == "true":
        domain = body["spec"]["rules"][0]["host"]
        print(f"Ingess {ingress_name} has domain {domain}, processing")
        hosted_zone_id = find_hosted_zone_id(domain)
        certificate_arn = create_acm_certificate(domain, ingress_name, namespace)
        create_route53_validation_records(certificate_arn, hosted_zone_id)

        patch = {
            "metadata": {
                "annotations": {
                    "aws.acm.kubernetes.io/certificate-arn": certificate_arn,
                    "aws.route53.kubernetes.io/hosted-zone": hosted_zone_id
                }
            }
        }

        k8s_client.patch_namespaced_ingress(
            name=ingress_name,
            namespace=namespace,
            body=patch,
        )

        print(f"Ingress {ingress_name} has been processed with ACM certificate {certificate_arn}")

def delete_acm_certificate(certificate_arn):
    acm_client.delete_certificate(CertificateArn=certificate_arn)


def delete_route53_validation_records(certificate_arn, hosted_zone_id):
    response = acm_client.describe_certificate(CertificateArn=certificate_arn)
    validation_records = response["Certificate"]["DomainValidationOptions"]

    for record in validation_records:
        route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "DELETE",
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


@kopf.on.delete('ingresses')
def ingress_deleted(body, **kwargs):
    ingress = body["metadata"]
    ingress_name = ingress["name"]
    namespace = ingress["namespace"]
    annotations = ingress.get("annotations", {})

    if annotations.get(ACM_ANNOTATION) == "true":

      certificate_arn = annotations.get("aws.acm.kubernetes.io/certificate-arn")
      hosted_zone_id = annotations.get("aws.route53.kubernetes.io/hosted-zone")

      if certificate_arn:
        domain_name = body["spec"]["rules"][0]["host"]

        delete_route53_validation_records(certificate_arn, hosted_zone_id)
        delete_acm_certificate(certificate_arn)

        kopf.info(f"Ingress {ingress_name} has been deleted with ACM certificate {certificate_arn}")



if __name__ == "__main__":
    kopf.run()
