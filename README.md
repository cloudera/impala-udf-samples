This repo contains sample user defined functions (UDFs) and user defined aggregate functions (UDAs) built against the Impala UDF/UDA framework.

To get started:

1. Install the impala udf development package for your distribution and Impala version,
   generally called impala-udf-devel or impala-udf-dev. This package is available
   in the various Cloudera package repositories under: <http://archive.cloudera.com/cdh5/>
   for CDH5 and <http://archive.cloudera.com/cdh6/> for CDH6.
2. cmake .
3. make

The samples will get built to build/. This contains test executables that you can run locally, without the impala service installed as well as the shared object artifacts that we can run on impala.

# How do I contribute code?
You need to first sign and return an
[ICLA](https://github.com/cloudera/native-toolchain/blob/icla/Cloudera%20ICLA_25APR2018.pdf)
and
[CCLA](https://github.com/cloudera/native-toolchain/blob/icla/Cloudera%20CCLA_25APR2018.pdf)
before we can accept and redistribute your contribution. Once these are submitted you are
free to start contributing to impala-udf-samples. Submit these to CLA@cloudera.com.

## Find
We use Github issues to track bugs for this project. Find an issue that you would like to
work on (or file one if you have discovered a new issue!). If no-one is working on it,
assign it to yourself only if you intend to work on it shortly.

It’s a good idea to discuss your intended approach on the issue. You are much more
likely to have your patch reviewed and committed if you’ve already got buy-in from the
impala-udf-samples community before you start.

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

Please post your patch to the impala-udf-samples project at https://gerrit.cloudera.org
for review. See
[Impala's guide on using gerrit](https://cwiki.apache.org/confluence/display/IMPALA/Using+Gerrit+to+submit+and+review+patches)
to submit and review patches for instructions on how to send patches to
http://gerrit.cloudera.org, except make sure to send your patch to the impala-udf-samples
project instead of Impala-ASF.
