import sys
import logging 
sys.path.insert(0, "external")
import boto3

logger = logging.getLogger(__name__)

securityhub = boto3.client('securityhub')

# This function import agregated report findings to securityhub 
def import_finding_to_sh(count: int, account_id: str, region: str, created_at: str, source_repository: str, 
    source_branch: str, source_commitid: str, build_id: str, report_url: str, finding_id: str, generator_id: str,
                         normalized_severity: str, severity: str, finding_type: str, finding_title: str, finding_description: str, best_practices_cfn: str): 
    print("called securityhub.py..................")
    new_findings = []
    new_findings.append({
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": "arn:aws:securityhub:{0}:{1}:product/{1}/default".format(region, account_id),
        "GeneratorId": generator_id,
        "AwsAccountId": account_id,
        "Types": [
            "Software and Configuration Checks/AWS Security Best Practices/{0}".format(
                finding_type)
        ],
        "CreatedAt": created_at,
        "UpdatedAt": created_at,
        "Severity": {
            "Normalized": normalized_severity,
        },
        "Title":  f"{count}-{finding_title}",
        "Description": f"{finding_description}",
        'Remediation': {
            'Recommendation': {
                'Text': 'For directions on PHP AWS Best practices, please click this link',
                'Url': best_practices_cfn
            }
        },
        'SourceUrl': report_url,
        'Resources': [
            {
                'Id': build_id,
                'Type': "CodeBuild",
                'Partition': "aws",
                'Region': region
            }
        ],
    })
    ### post the security vulnerability findings to AWS SecurityHub
    response = securityhub.batch_import_findings(Findings=new_findings)
    if response['FailedCount'] > 0:
        logger.error("Error importing finding: " + response)
        raise Exception("Failed to import finding: {}".format(response['FailedCount']))

def import_trivy_findings_to_sh(count: int, containerName: str, containerTag: str, awsRegion: str, codebuildBuildArn: str, awsAccount: str, cveId: str, cveTitle: str, cveDescription: str, packageName: str, installedVersion: str, fixedVersion: str, trivySeverity: str, cveReference: str, created_at: str, trivyProductSev: str, trivyNormalizedSev: str):
    print("called securityhub.py..................")
    new_findings = []
    new_findings.append({
        'SchemaVersion': '2018-10-08',
        'Id': containerName + ':' + containerTag + '/' + cveId,
        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + ':product/aquasecurity/aquasecurity',
        'GeneratorId': codebuildBuildArn,
        'AwsAccountId': awsAccount,
        'Types': [ 'Software and Configuration Checks/Vulnerabilities/CVE' ],
        'CreatedAt': created_at,
        'UpdatedAt': created_at,
        'Severity': {
            'Product': trivyProductSev,
            'Normalized': trivyNormalizedSev
        },
        'Title': str(count) + '-Trivy found a vulnerability to ' + cveId + ' in container ' + containerName,
        'Description': cveDescription,
        'Remediation': {
            'Recommendation': {
                'Text': 'More information on this vulnerability is provided in the hyperlink',
                'Url': cveReference
            }
        },
        'ProductFields': { 'Product Name': 'Trivy' },
        'Resources': [
        {
            'Type': 'Container',
            'Id': containerName + ':' + containerTag,
            'Partition': 'aws',
            'Region': awsRegion,
            'Details': {
                'Container': { 'ImageName': containerName + ':' + containerTag },
                'Other': {
                    'CVE ID': cveId,
                    'CVE Title': cveTitle,
                    'Installed Package': packageName + ' ' + installedVersion,
                    'Patched Package': packageName + ' ' + fixedVersion
                }
            }
        },
        ],
        'RecordState': 'ACTIVE'
    })
    response = securityhub.batch_import_findings(Findings=new_findings)
    if response['FailedCount'] > 0:
        logger.error("Error importing finding: " + response)
        raise Exception("Failed to import finding: {}".format(response['FailedCount']))
