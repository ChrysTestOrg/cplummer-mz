# Automated Account Governance and Security Baseline

## Overview
Terraform configuration that implements a governance and security configuration baseline for an AWS account within an AWS organization.

## Controls implemented from AWS Organizations management account

### Security Control Policies
[Deny all regions except us-east-1 and us-west-2](policy/scp-restrict-regions.json)
- *Policy*: Ensure that AWS resources in the regulated account can only be deployed and accessed from approved regions.
- *Rationale*: Restricting use to specific regions helps to control costs, comply with data residency requirements, and ensure that resources cannot be created or accessed from regions where compliance controls are not configured.

### Centralized CloudTrail log bucket
- *Policy*: CloudTrail logs for management events in the regulated account should be written to a centralized S3 bucket in a separate AWS account. This bucket must be configured to allow access by the CloudTrail service principal in order for cross-account logging to succeed.
- *Rationale*: Saving audit data to a separate account prevents an attacker who gains control of the regulated account from deleting log data to cover their tracks or avoid detection.


## Controls implemented from AWS member account

### CloudTrail multi-region trail
- *Policy*: A multi-region CloudTrail trail should be enabled to log management plane events to the centralized CloudTrail bucket defined above. Events for global services (such as IAM) should be included, and log file validation should be enabled. Log files should be encrypted using a customer-managed KMS key.
- *Rationale*: Saving audit data to a separate account prevents an attacker who gains control of the regulated account from covering their tracks to avoid detection. Enabling log file validation ensures that log integrity is maintained when they are written. Utilizing a customer-managed KMS key in the regulated account to encrypt the CloudTrail logs adds an additional layer of protection to prevent the logs from being read by an unauthorized user or service principal, even if they have permission to read objects in the centralized log bucket itself.


#### KMS customer-managed key
- *Policy*: A customer-managed KMS key should be used to encrypt CloudTrail logs. This key must be configured to allow access by the CloudTrail service principal, but only when accessed using the expected encryption context and source ARN of the configured trail. IAM users/roles within the regulated account may also be permitted to decrypt logs using this KMS key, if allowed by a corresponding identity-based permissions policy.
- *Rationale*: Utilizing a customer-managed KMS key in the regulated account to encrypt the CloudTrail logs adds an additional layer of protection to prevent the logs from being read by an unauthorized user or service principal, even if they have permission to read objects in the centralized log bucket itself.


### AWS Config recording and detection of non-compliance

#### SSM QuickSetup
- *Policy*: AWS Config delivery channels and configuration recorders should be enabled in all approved regions. The AWS Systems Manager (SSM) Quick Setup Configuration Manager enables automatic deployment of these required components to multiple target regions.
- *Rationale*: As a regional service, it is necessary to setup AWS Config separately in each region where resources need to be monitored. Utilizing SSM Quick Setup simplifies the deployment and configuration of an AWS Config configuration recorder and delivery channel to all approved regions, and enables easy onboarding of additional regions in the future as needed.

#### AWS-managed Config Rules

##### Rules enforcing audit logging and credential management standards

[ACCESS_KEYS_ROTATED](https://docs.aws.amazon.com/config/latest/developerguide/access-keys-rotated.html) (global)
- *Policy*: All IAM access keys should be rotated at least once every 90 days.
- *Rationale*: Access keys are long-lived, single-factor credentials which are often used for programmatic access, creating an increased risk of accidental exposure. Regular rotation protects an old access key from being used in an attack.
- *Optional Parameters*: 
  - `maxAccessKeyAge` - (int) maximum number of days without key rotation

[IAM_PASSWORD_POLICY](https://docs.aws.amazon.com/config/latest/developerguide/iam-password-policy.html) (global)
- *Policy*: An IAM password policy should be in place to enforce password complexity, aging, and re-use requirements. Default behavior for this rule requires passwords to: 
  - have a minimum length of 14 characters
  - contain a mixture of character types, including at least one each of uppercase, lowercase, numeric, and symbols
  - be changed at least once every 90 days
  - not to match one of the last 24 previously used passwords
- *Rationale*: Complexity requirements reduce the likelihood of passwords being guessed or cracked by an attacker. Maximum age and re-use limitations reduce the threat if an exposed credential is ever included in a password dump or incorporated into a dictionary-based attack.
- *Optional Parameters*:
  - `MinimumPasswordLength` (int) - minimum number of characters required in password (default: 14)
  - `RequireUppercaseCharacters` (boolean) - whether an uppercase letter is required (default: true)
  - `RequireLowercaseCharacters` (boolean) - whether a lowercase letter is required (default: true)
  - `RequireSymbols` (boolean) - whether a symbol character is required (default: true)
  - `RequireNumbers` (boolean) - whether a number character is required (default: true)
  - `MaxPasswordAge` (int) - number of days before password expires (default: 90)
  - `PasswordReusePrevention` (int) - number of passwords before allowing reuse (default: 24)

[IAM_ROOT_ACCESS_KEY_CHECK](https://docs.aws.amazon.com/config/latest/developerguide/iam-root-access-key-check.html) (global)
- *Policy*: The root user should not have an access key configured.
- *Rationale*: The root user is highly privileged, and should not be used for day-to-day operations. Access keys are single-factor long-lived credentials which are often used for programmatic access, creating an increased risk of accidental exposure. Root access keys provide unrestricted account control; removing them eliminates a high‑value target for credential theft.

[ROOT_ACCOUNT_MFA_ENABLED](https://docs.aws.amazon.com/config/latest/developerguide/root-account-mfa-enabled.html) (global)
- *Policy*: Root user should have Multi‑Factor Authentication (MFA) enabled for AWS management console logon.
- *Rationale*: MFA adds a second authentication factor, dramatically lowering the risk of unauthorized root access even if the password is compromised.

[CLOUDTRAIL_SECURITY_TRAIL_ENABLED](https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-security-trail-enabled.html) (regional)
- *Policy*: At least one CloudTrail trail should be active and configured according to security best practices, including:
  - is a multi-region trail
  - records global service events (e.g. IAM)
  - records all management events
  - has log file validation enabled
  - is encrypted with a KMS key
- *Rationale*: Continuous audit logging captures administrative actions, enabling detection of suspicious activity and supporting forensic investigations.

##### Rules to detect publicly accessible resources:

[EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK](https://docs.aws.amazon.com/config/latest/developerguide/ebs-snapshot-public-restorable-check.html) (regional)
- *Policy*: EBS snapshots should not be shared publicly.
- *Rationale*: Publicly accessible snapshots expose raw disk data, potentially leaking sensitive information or proprietary code.

[EFS_MOUNT_TARGET_PUBLIC_ACCESSIBLE](https://docs.aws.amazon.com/config/latest/developerguide/efs-mount-target-public-accessible.html) (regional)
- *Policy*: EFS mount targets should not be associated with any subnet that is configured to assign public IP addresses on launch.
- *Rationale*: Public NFS access can be exploited to read or write file system data, leading to data leakage or tampering.

[LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED](https://docs.aws.amazon.com/config/latest/developerguide/lambda-function-public-access-prohibited.html) (regional)
- *Policy*: Lambda functions should not have resource‑based policies that grant `lambda:InvokeFunction` to `*` (any principal), or to an AWS service principal (e.g. `s3.amazonaws.com`) without including a condition to limit public access (e.g. based on `aws:SourceAccount`).
- *Rationale*: Public invocation permissions allow anyone to trigger the function, potentially leading to abuse, data exfiltration, or unintended charges.

[RDS_INSTANCE_PUBLIC_ACCESS_CHECK](https://docs.aws.amazon.com/config/latest/developerguide/rds-instance-public-access-check.html) (regional)
- *Policy*: RDS instances should not be publicly accessible (`PubliclyAccessible` = false).
- *Rationale*: Publicly reachable databases are exposed to the internet, increasing the attack surface for brute‑force, exploitation, and data theft.

[RDS_INSTANCE_SUBNET_IGW_CHECK](https://docs.aws.amazon.com/config/latest/developerguide/rds-instance-public-access-check.html) (regional)
- *Policy*: RDS instances should not be deployed in a public subnet (i.e. a subnet with a route to an internet gateway).
- *Rationale*: Publicly reachable databases are exposed to the internet, increasing the attack surface for brute‑force, exploitation, and data theft.

[RDS_SNAPSHOTS_PUBLIC_PROHIBITED](https://docs.aws.amazon.com/config/latest/developerguide/rds-snapshots-public-prohibited.html) (regional)
- *Policy*: RDS snapshots should not be shared publicly.
- *Rationale*: Public snapshot sharing can leak entire database contents, including sensitive customer or business data.

##### Rules to detect resources with unencrypted data at rest

[EC2_EBS_ENCRYPTION_BY_DEFAULT](https://docs.aws.amazon.com/config/latest/developerguide/ec2-ebs-encryption-by-default.html) (regional)
- *Policy*: The account‑level setting “EBS encryption by default” should be enabled, ensuring all newly created EBS volumes are encrypted at rest.
- *Rationale*: Default encryption protects data at rest without requiring per‑volume configuration, reducing the chance of unencrypted storage.

[EFS_FILESYSTEM_CT_ENCRYPTED](https://docs.aws.amazon.com/config/latest/developerguide/efs-filesystem-ct-encrypted.html) (regional)
- *Policy*: All Amazon EFS file systems should have encryption at rest enabled.
- *Rationale*: Encrypted file systems safeguard stored data against unauthorized access if the underlying storage media is compromised.
- *Optional Parameters*:
  - `kmsKeyArns` (string CSV) - list of ARNs of KMS keys that are allowed for EFS encryption

[RDS_CLUSTER_ENCRYPTED_AT_REST](https://docs.aws.amazon.com/config/latest/developerguide/rds-cluster-encrypted-at-rest.html) (regional)
- *Policy*: All Amazon RDS clusters should have encryption at rest enabled.
- *Rationale*: Encryption at rest protects data from disclosure if the underlying storage is accessed outside of AWS controls.

[RDS_SNAPSHOT_ENCRYPTED](https://docs.aws.amazon.com/config/latest/developerguide/rds-snapshot-encrypted.html) (regional)
- *Policy*: All automated and manual RDS snapshots should be encrypted.
- *Rationale*: Encrypted snapshots ensure that backup data remains confidential even if the snapshot is copied or stored outside the originating account.

[RDS_STORAGE_ENCRYPTED](https://docs.aws.amazon.com/config/latest/developerguide/rds-storage-encrypted.html) (regional)
- *Policy*: The `StorageEncrypted` flag should be set to true for every RDS instance.
- *Rationale*: Encryption of the underlying storage protects data at rest and satisfies compliance requirements for many regulated workloads.

[REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK](https://docs.aws.amazon.com/config/latest/developerguide/redshift-cluster-public-access-check.html) (regional)
- *Policy*: Redshift clusters should have `PubliclyAccessible` set to false.
- *Rationale*: Prevents the cluster from being reachable from the internet, reducing exposure to unauthorized queries and data exfiltration.

[S3_ACCESS_POINT_PUBLIC_ACCESS_BLOCKS] (https://docs.aws.amazon.com/config/latest/developerguide/s3-access-point-public-access-blocks.html) (regional)
- *Policy*: All S3 access points should be restricted from public access.
- *Rationale*: Blocking public access prevents accidental data exposure, a common cause of data breaches in cloud storage.
- *Optional Parameters*: 
  - `excludedAccessPoints` - (CSV) list of allowed public S3 access point names

[S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-level-public-access-prohibited.html) (regional)
- *Policy*: All S3 buckets should be restricted from public access.
- *Rationale*: Blocking public access prevents accidental data exposure, a common cause of data breaches in cloud storage.
- *Optional Parameters*: 
  - `excludedAccessPoints` - (CSV) list of allowed public S3 bucket names

##### Optional Rules to enforce MFA and encryption in transit (not currently enabled):

[IAM_USER_MFA_ENABLED](https://docs.aws.amazon.com/config/latest/developerguide/iam-user-mfa-enabled.html) (global)
- *Policy*: All IAM users with password-based access to the AWS management console should have MFA enabled.
- *Rationale*: MFA requires an additional factor when logging in, which reduces the risk of exposure even if a password is accidentally leaked.

[RDS_MARIADB_INSTANCE_ENCRYPTED_IN_TRANSIT](https://docs.aws.amazon.com/config/latest/developerguide/rds-mariadb-instance-encrypted-in-transit.html) (regional)
- *Policy*: All MariaDB RDS instances should require encrypted access.
- *Rationale*: Encryption in transit for SQL clients prevents exposure of data while it traverses the network.

[RDS_MYSQL_INSTANCE_ENCRYPTED_IN_TRANSIT](https://docs.aws.amazon.com/config/latest/developerguide/rds-mysql-instance-encrypted-in-transit.html) (regional)
- *Policy*: All MySQL RDS instances should require encrypted access.
- *Rationale*: Encryption in transit for SQL clients prevents exposure of data while it traverses the network.

[RDS_POSTGRES_INSTANCE_ENCRYPTED_IN_TRANSIT](https://docs.aws.amazon.com/config/latest/developerguide/rds-postgres-instance-encrypted-in-transit.html) (regional)
- *Policy*: All PostgreSQL RDS instances should require encrypted access.
- *Rationale*: Encryption in transit for SQL clients prevents exposure of data while it traverses the network.

[RDS_SQLSERVER_INSTANCE_ENCRYPTED_IN_TRANSIT](https://docs.aws.amazon.com/config/latest/developerguide/rds-sqlserver-encrypted-in-transit.html) (regional)
- *Policy*: All Microsoft SQLServer RDS instances should require encrypted access.
- *Rationale*: Encryption in transit for SQL clients prevents exposure of data while it traverses the network.

[REDSHIFT_REQUIRE_TLS_SSL](https://docs.aws.amazon.com/config/latest/developerguide/redshift-require-tls-ssl.html) (regional)
- *Policy*: Redshift clusters should have `require_SSL` parameter set to true.
- *Rationale*: Encryption in transit for SQL clients prevents exposure of data while it traverses the network.

[S3_BUCKET_SSL_REQUESTS_ONLY] (https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-ssl-requests-only.html) (regional)
- *Policy*: S3 buckets should have policies to prevent access via unencrypted (i.e. HTTP) connections.
- *Rationale*: Encryption in transit prevents exposure of data while it traverses the network.

### Baseline IAM roles and policies

#### Role: Read-only administrator
Description: Grants read-only access to all resources and data in the account. *NOTE: this role includes access to read ALL data objects and resources, including secrets and keys.*

- Trust Policy (custom): [`iam-trust-mfa-users`](iam-trust-mfa-users.json) - This role may be assumed by IAM users in the same account who have successfully authenticated to the AWS management console with MFA, and have an identity-based policy granting `sts:AssumeRole` permission.
- Permissions Policy (AWS-managed): [ReadOnlyAccess](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html#awsmp_readonlyaccess)

#### Role: Database administrator
Description: Grants access typically required by database administrators to AWS services and resources in the account. *NOTE: this role includes broad access to S3 in addition to DynamoDB, ElastiCache, RDS, and Redshift. It also permits `iam:PassRole` with roles that match specific naming conventions for RDS monitoring and Lambda access. However, since none of the baseline roles grant access to create IAM roles, an administrator would need to create a properly named role that the DatabaseAdministrator is allowed to pass.*

- Trust Policy (custom): [`iam-trust-mfa-users`](iam-trust-mfa-users.json) - This role may be assumed by IAM users in the same account who have successfully authenticated to the AWS management console with MFA, and have an identity-based policy granting `sts:AssumeRole` permission.
- Permissions Policy (AWS-managed): [DatabaseAdministrator](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html#jf_database-administrator)

#### Role: Developer
Description: Grants broad "power user" access typically required by developers to AWS services and resources in the account, including **Administrator-Level** access to most services (excluding IAM, Organizations, and Account Management). *NOTE: this role includes access to read all data objects, including secrets and keys, but ONLY if the resource being accessed has an `env` tag whose value matches the value of the `env` tag on the role itself (currently `env=dev`).*

- Trust Policy (custom): [`iam-trust-mfa-users`](iam-trust-mfa-users.json) - This role may be assumed by IAM users in the same account who have successfully authenticated to the AWS management console with MFA, and have an identity-based policy granting `sts:AssumeRole` permission.
- Permissions Policy (AWS-managed): [PowerUserAccess](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html#jf_developer-power-user)
- Permissions Policy (AWS-managed): [ReadOnlyAccess](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html#awsmp_readonlyaccess)
- Permissions Policy (customer-managed): [`allow-iam-readonly`](policy/iam-allow-iam-readonly.json)
- Permissions Policy (customer-managed): [`deny-iam-unless-tags-match`](policy/iam-deny-unless-tags-match.json)
