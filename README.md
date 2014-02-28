# Impala Sample UDFs and UDAs

This repo contains sample user defined functions (UDFs) and user
defined aggregate functions (UDAs) built against the Impala UDF/UDA
framework.

## Getting Started

1. Install the impala udf development package: <http://archive.cloudera.com/cdh5/>
2. cmake .
3. make

The samples will get built to build/. This contains test executables
that you can run locally, without the impala service installed as well
as the shared object artifacts that we can run on impala.

## Evaluating UDFs

Using custom UDFs can incur additional overhead to the query execution
as they are likely to be executed millions of times. Thus, careful
optimizations of such functions is required. This sample package
allows you to quickly evaluate the performance of you UDFs by counting
instructions and cycles. 

To use performance evaluation, install PAPI for your local platform
and adapt the following bit of code according to your own UDFs.

    #include "helper/papi-tracer.h"
    #include "helper/udf-execute.h"
    
    // ...
    impala_udf::UdfExecuteHelper executor;
    { 
      ScopedTracer sct("AddUdf", 1000u);
      for(int i=0; i < sct.numCalls(); ++i) {
        counter += executor.ExecuteUdf<IntVal, IntVal, IntVal>(
          AddUdf, IntVal(i), IntVal(i+1)).val;
      }
    }


The above code will call the UDF `AddUdf` from the sample code 1000
times and record the cycles and instructions spent. To compile check
the `CMakeList.txt` for the appropriate target to get all the
dependencies. Once the binary is built, you can simply execute it. The
output of the program should now contain something like this:

    --------------------------------------
    Performance Analysis for AddUdf
    Real Time:                 0
    Total Instructions:        64
    Instructions / Cycle:        2.53008
    Cycles / Call:             25
    Time in s per 10^9 calls @3GhZ: 8
    Time in s per 10^9 calls @2GhZ: 12

This overview tells you how many instructions were executed per call,
what the ratio between instructions and cycles is, and most
importantly what the runtime probably will be when the UDF is execute
1B times.

Two things are very important for optimizing UDF code: the ratio of
instructions per cycle should be as high as possible (on modern Intel
platforms the theoretical limit is 4). In addition the number of
instructions should be as low as possible. Both measures determine
together the overall execution time.
