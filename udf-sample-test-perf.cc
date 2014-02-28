// Copyright 2012 Cloudera Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <iostream>

#include <impala_udf/udf-test-harness.h>
#include "udf-sample.h"

#include "helper/papi-tracer.h"
#include "helper/udf-execute.h"

int counter = 0;

int main(int argc, char** argv) {

  // Use the ScopedTracer class with the number of iterations and a
  // descriptions string as constructor arguments to evaluate the
  // performance. The performance evaluation will not look at the data
  // side, but not the data processing side. The most reliable numbers
  // will be the instruction count rather than the cycle count due to
  // possible instruction cache or data cache misses.
  impala_udf::UdfExecuteHelper exe;
  { 
    ScopedTracer sct("AddUdf", 100000u);
    for(int i=0; i < sct.numCalls(); ++i) {
      counter += exe.ExecuteUdf<IntVal, IntVal, IntVal>(
        AddUdf, IntVal(i), IntVal(i+1)).val;
    }
  }

  { 
    ScopedTracer sct("FuzzyEquals", 1000u);
    for(int i=0; i < sct.numCalls(); ++i) {
      counter += exe.ExecuteUdf<BooleanVal, DoubleVal, DoubleVal>(
      FuzzyEquals, DoubleVal(1.0), DoubleVal(1.0000000001)).val;
    }
  }

  // Performance test for string values should use the average number
  // of characters that are checked. It makes a huge difference for
  // the performance estimation if the string is longer as the inner
  // loop of the CountVowels function depends on the input string
  std::vector<std::string> data;
  data.push_back("vo910293801981081092wel");
  data.push_back("nw12312312312312dzl");
  data.push_back("xszsxsqlwoe");
		 
  { 
    ScopedTracer sct("CountVowels", 1000u);
    for(int i=0; i < sct.numCalls(); ++i) {
      counter += exe.ExecuteUdf<IntVal, StringVal>(
        CountVowels, StringVal(data[i % 3].c_str())).val;
    }
  }

  return 0;
}
