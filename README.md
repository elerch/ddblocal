DDB Local
=========

This project presents itself as [Amazon
DynamoDB](https://aws.amazon.com/dynamodb/), but uses Sqlite for data storage
only supports a handful of operations, and even then not with full fidelity:

* CreateTable
* BatchGetItem
* BatchWriteItem

UpdateItem, PutItem and GetItem should be trivial to implement. Project name
mostly mirrors [DynamoDB Local](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html),
but doesn't have the overhead of a full Java VM, etc. On small data sets, this
executable will use <10MB of resident memory.
                    ^^^ TODO: New measurement

Security
--------

This uses typical IAM authentication, but does not have authorization
implemented yet. This provides a chicken and egg problem, because we need a
data store for access keys/secret keys, which would be great to have in...DDB.

Therefore, DDB is designed to adhere to the following algorithm:

1. Check if this is a test account (used for `zig build test`). This uses hard-coded creds.
2. Check if the account information is in `access_keys.csv`. This file is loaded at startup
   and contains the root credentials and keys necessary for bootstrap. Future plans
   are to enable encryption of this file and decryption using an HSM, as it is critical
   to everything.
3. Call various services (primarily STS and IAM) if credentials do not exist in #1/#2.

As such, we effectively need a control plane instance on DDB, with appropriate
access keys/secret keys stored somewhere other than DDB. Therefore, the following
environment variables are planned:

* IAM_ACCESS_KEY
* IAM_SECRET_KEY
* IAM_SECRET_FILE: File that will contain the above three values, allowing for cred rotation
* STS_SERVICE_ENDPOINT (tbd - may not be named this)
* IAM_SERVICE_ENDPOINT (tbd - may not be named this)

Secret file, thought here is that we can open/read file only if authentication succeeds, but access key
does not match the ADMIN_ACCESS_KEY. This is a bit of a timing oracle, but not sure we care that much

Note that IAM does not have public APIs to perform authentication on access keys,
nor does it seem to do authorization.

STS is used to [translate access keys -> account ids](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetAccessKeyInfo.html).


Our plan is to use the aws zig library for authentication, and IAM for authorization,
but we'll do that as a bin item.

High level, we have a DDB bootstrap with IAM account id/access key. Those credentials
can then add new, we'll call them "root user" records in the IAM table with
their own account id/access keys.

Those "root users" can then do whatever they want in their own tables, but cannot
touch tables to any other account, including the IAM account. IAM account can only
touch tables in their own account.
