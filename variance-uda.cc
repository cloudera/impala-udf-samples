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

#include <assert.h>
#include <math.h>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <impala_udf/udf.h>

using namespace std;
using namespace impala_udf;

struct VarianceState {
  // Sum of all input values.
  double sum;
  // Sum of the square of all input values.
  double sum_squared;
  // The number of input values.
  int64_t count;
};

void VarianceInit(FunctionContext* ctx, StringVal* dst) {
  dst->is_null = false;
  dst->len = sizeof(VarianceState);
  dst->ptr = ctx->Allocate(dst->len);
  memset(dst->ptr, 0, dst->len);
}

void VarianceUpdate(FunctionContext* ctx, const DoubleVal& src, StringVal* dst) {
  if (src.is_null) return;
  VarianceState* state = reinterpret_cast<VarianceState*>(dst->ptr);
  state->sum += src.val;
  state->sum_squared += src.val * src.val;
  ++state->count;
}

void VarianceMerge(FunctionContext* ctx, const StringVal& src, StringVal* dst) {
  VarianceState* src_state = reinterpret_cast<VarianceState*>(src.ptr);
  VarianceState* dst_state = reinterpret_cast<VarianceState*>(dst->ptr);
  dst_state->sum += src_state->sum;
  dst_state->sum_squared += src_state->sum_squared;
  dst_state->count += src_state->count;
}

DoubleVal VarianceFinalize(FunctionContext* ctx, const StringVal& src) {
  VarianceState* state = reinterpret_cast<VarianceState*>(src.ptr);
  if (state->count == 0) return DoubleVal::null();
  double mean = state->sum / state->count;
  double variance = state->sum_squared / state->count - mean * mean;
  return DoubleVal(variance);
}

