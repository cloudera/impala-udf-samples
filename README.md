This repo contains user-defined functions (UDF) for Apache Impala to implement cryptographic functions in the query language. This is required when building a GDPR secured data lake with or without Data Vault 2.0. 

  * GDPR: https://en.wikipedia.org/wiki/General_Data_Protection_Regulation
  * Data Vault 2.0: check out https://www.scalefree.com and https://blog.scalefree.com for details

This project is funded by Scalefree to support cryptographic functions in Impala. This is required in order to secure a data lake and support deletion of consumer records, a requirement of the GDPR. Transparent, filesystem-level encryption is not sufficient for this purpose / doesn't meet the legal requirements (consult your lawyers). 

To get started:

1. Install the impala udf development package: <http://archive.cloudera.com/cdh5/>
2. cmake .
3. make

The crypto UDFs will get built to build/. This contains test executables that you can run locally, without the impala service installed as well as the shared object artifacts that we can run on impala.

# How do I contribute code?
FIXME

## Find
We use Github issues to track bugs for this project. Find an issue that you would like to
work on (or file one if you have discovered a new issue!). If no-one is working on it,
assign it to yourself only if you intend to work on it shortly.

It’s a good idea to discuss your intended approach on the issue. You are much more
likely to have your patch reviewed and committed if you’ve already got buy-in from the
impala-crypto-udf community before you start.

## Fix
Now start coding! As you are writing your patch, please keep the following things in mind:

First, please include tests with your patch. If your patch adds a feature or fixes a bug
and does not include tests, it will generally not be accepted. If you are unsure how to
write tests for a particular component, please ask on the issue for guidance.

Second, please keep your patch narrowly targeted to the problem described by the issue.
It’s better for everyone if we maintain discipline about the scope of each patch. In
general, if you find a bug while working on a specific feature, file a issue for the bug,
check if you can assign it to yourself and fix it independently of the feature. This helps
us to differentiate between bug fixes and features and allows us to build stable
maintenance releases.

Finally, please write a good, clear commit message, with a short, descriptive title and
a message that is exactly long enough to explain what the problem was, and how it was
fixed.
