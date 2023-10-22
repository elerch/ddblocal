DDB Local
=========

This project presents itself as [Amazon DynamoDB](https://aws.amazon.com/dynamodb/),
but uses Sqlite for data storage
only supports a handful of operations, and even then not with full fidelity:

* CreateTable
* BatchGetItem
* BatchWriteItem

UpdateItem, PutItem and GetItem should be trivial to implement. Project name
mostly mirrors [DynamoDB Local](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html),
but doesn't have the overhead of a full Java VM, etc. On small data sets, this static executable
executable will use <10MB of resident memory.
                    ^^^ TODO: New measurement

Running as Docker
-----------------

TODO/Not accurate

Latest version can be found at [https://r.lerch.org/repo/ddbbolt/tags/](https://r.lerch.org/repo/ddbbolt/tags/).
Versions are tagged with the short hash of the git commit, and are
built as a multi-architecture image based on a scratch image.

You can run the docker image with a command like:

```sh
docker run \
  --volume=$(pwd)/ddbbolt:/data \
  -e FILE=/data/ddb.db          \
  -e PORT=8080                  \
  -p 8080:8080                  \
  -d                            \
  --name=ddbbolt                \
  --restart=unless-stopped      \
  r.lerch.org/ddbbolt:f501abe
```


Security
--------

This uses typical IAM authentication, but does not have authorization
implemented yet. This provides a chicken and egg problem, because we need a
data store for access keys/secret keys, which would be great to have in...DDB.

As such, we effectively need a control plane instance on DDB, with appropriate
access keys/secret keys stored somewhere other than DDB. Therefore, the following
environment variables are planned:

* IAM_ACCOUNT_ID
* IAM_ACCESS_KEY
* IAM_SECRET_KEY
* IAM_SECRET_FILE: File that will contain the above three values, allowing for cred rotation
* STS_SERVICE_ENDPOINT
* IAM_SERVICE_ENDPOINT

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
