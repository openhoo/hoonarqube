import { aws_opensearchservice } from 'aws-cdk-lib';

// Data at rest left unencrypted on the OpenSearch domain.
new aws_opensearchservice.Domain(this, 'Domain', {
  version: aws_opensearchservice.EngineVersion.OPENSEARCH_2_3,
});
