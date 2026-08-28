const command = new CreateBucketCommand({
  Bucket: "reports",
  ServerSideEncryptionConfiguration: { Rules: [] },
});
