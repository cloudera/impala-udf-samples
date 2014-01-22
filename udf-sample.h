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


#ifndef SAMPLES_UDF_H
#define SAMPLES_UDF_H

#include <impala_udf/udf.h>

using namespace impala_udf;

// Usage: > create function add(int, int) returns int
//          location '/user/cloudera/libudfsample.so' SYMBOL='AddUdf';
//        > select add(1, 2);
IntVal AddUdf(FunctionContext* context, const IntVal& arg1, const IntVal& arg2);

// Returns true if x is approximately equal to y.
// Usage: > create function fuzzy_equals(double, double) returns boolean
//          location '/user/cloudera/libudfsample.so' SYMBOL='FuzzyEquals';
//        > select fuzzy_equals(1, 1.00000001);
BooleanVal FuzzyEquals(FunctionContext* context, const DoubleVal& x, const DoubleVal& y);

#endif
