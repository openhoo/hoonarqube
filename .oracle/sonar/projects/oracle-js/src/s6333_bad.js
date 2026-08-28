import { aws_apigateway } from 'aws-cdk-lib';

// Method with authorization switched off.
new aws_apigateway.CfnMethod(this, 'Method', {
  httpMethod: 'GET',
  authorizationType: 'NONE',
});

// Root method added without any authorization options.
const api = new aws_apigateway.RestApi(this, 'Api');
api.root.addMethod('GET');
