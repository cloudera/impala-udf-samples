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
#include <math.h>

#include <impala_udf/uda-test-harness.h>
#include "uda-sample.h"

using namespace impala;
using namespace impala_udf;
using namespace std;

bool TestCount() {
  // Use the UDA test harness to validate the COUNT UDA.
  UdaTestHarness<BigIntVal, BigIntVal, IntVal> test(
      CountInit, CountUpdate, CountMerge, NULL, CountFinalize);

  // Run the UDA over 10000 non-null values
  vector<IntVal> no_nulls;
  no_nulls.resize(10000);
  if (!test.Execute(no_nulls, BigIntVal(no_nulls.size()))) {
    cerr << test.GetErrorMsg() << endl;
    return false;
  }

  // Run the UDA with some nulls
  vector<IntVal> some_nulls;
  some_nulls.resize(10000);
  int expected = some_nulls.size();
  for (int i = 0; i < some_nulls.size(); i += 100) {
    some_nulls[i] = IntVal::null();
    --expected;
  }
  if (!test.Execute(some_nulls, BigIntVal(expected))) {
    cerr << test.GetErrorMsg() << endl;
    return false;
  }

  return true;
}

bool TestAvg() {
  UdaTestHarness<DoubleVal, BufferVal, DoubleVal> test(
      AvgInit, AvgUpdate, AvgMerge, NULL, AvgFinalize);
  test.SetIntermediateSize(16);

  vector<DoubleVal> vals;
  for (int i = 0; i < 1001; ++i) {
    vals.push_back(DoubleVal(i));
  }
  if (!test.Execute<DoubleVal>(vals, DoubleVal(500))) {
    cerr << test.GetErrorMsg() << endl;
    return false;
  }
  return true;
}

bool TestStringConcat() {
  // Use the UDA test harness to validate the COUNT UDA.
  UdaTestHarness2<StringVal, StringVal, StringVal, StringVal> test(
      StringConcatInit, StringConcatUpdate, StringConcatMerge, NULL,
      StringConcatFinalize);

  vector<StringVal> values;
  values.push_back("Hello");
  values.push_back("World");

  vector<StringVal> separators;
  for(int i = 0; i < values.size(); ++i) {
    separators.push_back(",");
  }
  if (!test.Execute(values, separators, StringVal("Hello,World"))) {
    cerr << test.GetErrorMsg() << endl;
    return false;
  }

  return true;
}

// For algorithms that work on floating point values, the results might not match
// exactly due to floating point inprecision. The test harness allows passing a
// custom equality compartor. Here's an example of one that can tolerate some small
// error.
bool FuzzyCompare(const DoubleVal& x, const DoubleVal& y) {
  if (x.is_null && y.is_null) return true;
  if (x.is_null || y.is_null) return false;
  return fabs(x.val - y.val) < 0.00001;
}

bool TestVariance() {
  UdaTestHarness<DoubleVal, StringVal, DoubleVal> simple_variance(
      VarianceInit, VarianceUpdate, VarianceMerge, NULL, VarianceFinalize);
  simple_variance.SetResultComparator(FuzzyCompare);

  UdaTestHarness<DoubleVal, StringVal, DoubleVal> knuth_variance(
      KnuthVarianceInit, KnuthVarianceUpdate, KnuthVarianceMerge, NULL,
      KnuthVarianceFinalize);
  knuth_variance.SetResultComparator(FuzzyCompare);

  vector<DoubleVal> vals;
  double sum = 0;
  for (int i = 0; i < 1001; ++i) {
    vals.push_back(DoubleVal(i));
    sum += i;
  }
  double mean = sum / vals.size();
  double expected_variance = 0;
  for (int i = 0; i < vals.size(); ++i) {
    double d = mean - vals[i].val;
    expected_variance += d * d;
  }
  expected_variance /= (vals.size() - 1);

  if (!simple_variance.Execute(vals, DoubleVal(expected_variance))) {
    cerr << "Simple variance: " << simple_variance.GetErrorMsg() << endl;
    return false;
  }
  if (!knuth_variance.Execute(vals, DoubleVal(expected_variance))) {
    cerr << "Knuth variance: " << knuth_variance.GetErrorMsg() << endl;
    return false;
  }

  return true;
}

int main(int argc, char** argv) {
  bool passed = true;
  passed &= TestCount();
  passed &= TestAvg();
  passed &= TestStringConcat();
  passed &= TestVariance();
  cerr << (passed ? "Tests passed." : "Tests failed.") << endl;
  return 0;
}
