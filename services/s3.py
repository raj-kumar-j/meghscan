
# This file contains constants related to aws s3 test cases

total_checks = 11
impacted_buckets = [[] for i in range(0,total_checks)]

check1Title = "S3 Bucket Public/Authenticated Users 'FULL_CONTROL/READ/WRITE/READ_ACP/WRITE_ACP' Access"

check1Impact = "Very High"

check1Desc = """
Ensure there aren't any publicly accessible S3 buckets available in your AWS account in order to protect your S3 data from loss and unauthorized access. A publicly accessible S3 bucket allows FULL_CONTROL access to everyone (i.e. anonymous users) to LIST (READ) the objects within the bucket, UPLOAD/DELETE (WRITE) objects, VIEW (READ_ACP) object permissions and EDIT (WRITE_ACP) object permissions. Cloud Conformity strongly recommends against using all these permissions for the “Everyone” ACL predefined group in production.

This rule can help you work with the AWS Well-Architected Framework.
"""

check1Reference = "https://www.cloudconformity.com/knowledge-base/aws/S3/s3-bucket-public-full-control-access.html"
#----------------------------------------------------------------------------------------------------------------------------------------

check2Title = "S3 Bucket Public Access Via Policy"

check2Impact = "Very High"

check2Desc = """
Ensure that your AWS S3 buckets are not publicly accessible via bucket policies in order to protect against unauthorized access. Allowing unrestricted access through bucket policies gives everyone the ability to list the objects within the bucket (ListBucket), download objects (GetObject), upload/delete objects (PutObject, DeleteObject), view objects permissions (GetBucketAcl), edit objects permissions (PutBucketAcl) and more. Cloud Conformity strongly recommends using bucket policies to limit the access to a particular AWS account (friendly account) instead of providing public access to everyone on the Internet.

Granting public access to your S3 buckets via bucket policies can allow malicious users to view, get, upload, modify and delete S3 objects, actions that can lead to data loss and unexpected charges on your AWS bill.

This rule can help you work with the AWS Well-Architected Framework.
"""

check2Reference = "https://www.cloudconformity.com/knowledge-base/aws/S3/s3-bucket-public-access-via-policy.html"
#----------------------------------------------------------------------------------------------------------------------------------------

check3Title = "S3 Bucket Default Encryption"

check3Impact = "Very High"

check3Desc = """
Ensure that default encryption is enabled at the bucket level to automatically encrypt all objects when stored in Amazon S3. The S3 objects are encrypted during the upload process using Server-Side Encryption with either AWS S3-managed keys (SSE-S3) or AWS KMS-managed keys (SSE-KMS).

This rule can help you work with the AWS Well-Architected Framework.

S3 default encryption will enable Amazon to encrypt your S3 data at the bucket level instead of object level in order to protect it from attackers or unauthorized personnel. Without S3 default encryption, to encrypt all objects stored in a bucket, you must include encryption information (i.e. "x-amz-server-side-encryption" header) with every object storage request, as described by the Server Side Encryption (SSE) conformity rule. Also, to encrypt S3 objects without default encryption, you must set up a bucket policy to deny storage requests that don`t include the encryption information.
"""

check3Reference = "https://www.cloudconformity.com/knowledge-base/aws/S3/bucket-default-encryption.html"
#----------------------------------------------------------------------------------------------------------------------------------------

check4Title = "S3 Cross Account Access"

check4Impact = "High"

check4Desc = """
Ensure that all your AWS S3 buckets are configured to allow access only to trusted AWS accounts in order to protect against unauthorized cross account access.

Allowing untrustworthy cross account access to your S3 buckets via bucket policies can lead to unauthorized actions such as viewing, uploading, modifying or deleting S3 objects. To prevent S3 data exposure, data loss and/or unexpected charges on your AWS bill, you need to grant access only to trusted entities by implementing the appropriate access policies recommended in this conformity rule.

This rule can help you work with the AWS Well-Architected Framework.
"""

check4Reference = "https://www.cloudconformity.com/knowledge-base/aws/S3/s3-cross-account-access.html"
#----------------------------------------------------------------------------------------------------------------------------------------

check5Title = "S3 Bucket Logging Enabled"

check5Impact = "Medium"

check5Desc = """
Ensure that AWS S3 Server Access Logging feature is enabled in order to record access requests useful for security audits. By default, server access logging is not enabled for S3 buckets.

With Server Access Logging feature enabled for your S3 buckets you can track any requests made to access the buckets and use the log data to take measures in order to protect them against unauthorized user access.

This rule can help you work with the AWS Well-Architected Framework.
"""

check5Reference = "https://www.cloudconformity.com/knowledge-base/aws/S3/s3-bucket-logging-enabled.html"
#----------------------------------------------------------------------------------------------------------------------------------------

check6Title = "S3 Secure Transport"

check6Impact = "Medium"

check6Desc = """
Ensure that your AWS S3 buckets enforce encryption of data over the network (as it travels to and from Amazon S3) using Secure Sockets Layer (SSL).

When S3 buckets are not configured to strictly require SSL connections, the communication between the clients (users, applications) and these buckets is vulnerable to eavesdropping and man-in-the-middle (MITM) attacks. Cloud Conformity strongly recommends enforcing SSL-only access by denying all regular, unencrypted HTTP requests to your buckets when dealing with sensitive or private data.

This rule can help you work with the AWS Well-Architected Framework.
"""

check6Reference = "https://www.cloudconformity.com/knowledge-base/aws/S3/secure-transport.html"
#----------------------------------------------------------------------------------------------------------------------------------------

check7Title = "S3 Buckets with Website Configuration Enabled"

check7Impact = "Medium"

check7Desc = """
Ensure that your Amazon S3 buckets with website configuration enabled are regularly reviewed for security purposes.By regularly reviewing these S3 buckets you make sure that only the desired buckets are accessible from the website endpoint.

This rule can help you work with the AWS Well-Architected Framework.
"""

check7Reference = "https://www.cloudconformity.com/knowledge-base/aws/S3/buckets-with-website-configurations.html"
#----------------------------------------------------------------------------------------------------------------------------------------

check8Title = "S3 Server Side Encryption"

check8Impact = "Medium"

check8Desc = """
Ensure that your AWS S3 buckets are protecting their sensitive data at rest by enforcing Server-Side Encryption.

When dealing with sensitive data that is crucial to your business, it is highly recommended to implement encryption in order to protect it from attackers or unauthorized personnel. Using S3 Server-Side Encryption (SSE) will enable Amazon to encrypt your data at the object level as it writes it to disks and decrypts it transparently for you when you access it.

Note: Server-Side Encryption (SSE) utilizes one of the strongest block ciphers available, 256-bit Advanced Encryption Standard (AES-256), to encrypt your S3 objects.

This rule can help you work with the AWS Well-Architected Framework.
"""

check8Reference = "https://www.cloudconformity.com/knowledge-base/aws/S3/server-side-encryption.html"
#----------------------------------------------------------------------------------------------------------------------------------------

check9Title = "S3 Bucket MFA Delete Enabled"

check9Impact = "Low"

check9Desc = """
Ensure that your AWS S3 buckets are using Multi-Factor Authentication (MFA) Delete feature in order to prevent the deletion of any versioned S3 objects (files).

Using MFA-protected S3 buckets will enable an extra layer of protection to ensure that the S3 objects (files) cannot be accidentally or intentionally deleted by the AWS users that have access to the buckets.

Note: Only the bucket owner that is logged in as AWS root account can enable MFA Delete feature and perform DELETE actions on S3 buckets.

This rule can help you work with the AWS Well-Architected Framework.
"""

check9Reference = "https://www.cloudconformity.com/knowledge-base/aws/S3/s3-bucket-mfa-delete-enabled.html"
#----------------------------------------------------------------------------------------------------------------------------------------

check10Title = "S3 Buckets Lifecycle Configuration"

check10Impact = "Low"

check10Desc = """
Ensure that your AWS S3 buckets utilize lifecycle configurations to manage S3 objects during their lifetime. An S3 lifecycle configuration is a set of one or more rules, where each rule defines an action (transition or expiration action) for Amazon S3 to apply to a group of objects.

Using AWS S3 lifecycle configuration, you can enable Amazon S3 to downgrade the storage class for your objects, archive or delete S3 objects during their lifecycle. For example, you can define S3 lifecycle configuration rules to achieve compliance (with the law, with your organization standards or business requirements) by automatically transitioning your S3 objects to Infrequent Access (IA) using STANDARD_IA storage class one month after creation or archive S3 objects with AWS Glacier using GLACIER storage class one year after creation. You can also implement lifecycle configuration rules to expire (delete) objects based on your retention requirements or clean up incomplete multipart uploads in order to optimize your AWS S3 costs.

This rule can help you work with the AWS Well-Architected Framework.
"""

check10Reference = "https://www.cloudconformity.com/knowledge-base/aws/S3/lifecycle-configuration.html"
#----------------------------------------------------------------------------------------------------------------------------------------

check11Title = "S3 Object Lock"

check11Impact = "Low"

check11Desc = """
Ensure that your Amazon S3 buckets have Object Lock feature enabled in order to prevent the objects they store from being deleted. Object Lock is an Amazon S3 feature that blocks object version deletion during a user-defined retention period, to enforce retention policies as an additional layer of data protection and/or for strict regulatory compliance. The feature provides two ways to manage object retention: retention periods and legal holds. A retention period specifies a fixed time frame during which an S3 object remains locked, meaning that it can't be overwritten or deleted. You can configure the retention period for the available retention modes in the rule settings, on your Cloud Conformity account dashboard. A legal hold implements the same protection as a retention period, but without an expiration date. Instead, a legal hold remains active until you explicitly remove it.

Used in combination with versioning, which protects objects from being overwritten, AWS S3 Object Lock enables you to store your S3 objects in an immutable form, providing an additional layer of protection against object changes and deletion. S3 Object Lock feature can also help you meet regulatory requirements within your organization when it comes to data protection.

This rule can help you work with the AWS Well-Architected Framework.
"""

check11Reference = "https://www.cloudconformity.com/knowledge-base/aws/S3/object-lock.html"
#----------------------------------------------------------------------------------------------------------------------------------------
