This repo contains sample user defined functions (UDFs) and user defined aggregate functions (UDAs) built against the Impala UDF/UDA framework.

To get started: 

1. Install the impala udf development package: <http://archive.cloudera.com/cdh5/>
2. cmake .
3. make

The samples will get built to build/. This contains test executables that you can run locally, without the impala service installed as well as the shared object artifacts that we can run on impala.
