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

#include "uda-sample.h"
#include <assert.h>

using namespace impala_udf;

// ---------------------------------------------------------------------------
// This is a sample of implementing a COUNT aggregate function.
// ---------------------------------------------------------------------------
void CountInit(FunctionContext* context, BigIntVal* val) {
  val->is_null = false;
  val->val = 0;
}

void CountUpdate(FunctionContext* context, const IntVal& input, BigIntVal* val) {
  if (input.is_null) return;
  ++val->val;
}

void CountMerge(FunctionContext* context, const BigIntVal& src, BigIntVal* dst) {
  dst->val += src.val;
}

BigIntVal CountFinalize(FunctionContext* context, const BigIntVal& val) {
  return val;
}

// ---------------------------------------------------------------------------
// This is a sample of implementing a AVG aggregate function.
// ---------------------------------------------------------------------------
struct AvgStruct {
  double sum;
  int64_t count;
};

void AvgInit(FunctionContext* context, BufferVal* val) {
  assert(sizeof(AvgStruct) == 16);
  memset(*val, 0, sizeof(AvgStruct));
}

void AvgUpdate(FunctionContext* context, const DoubleVal& input, BufferVal* val) {
  if (input.is_null) return;
  AvgStruct* avg = reinterpret_cast<AvgStruct*>(*val);
  avg->sum += input.val;
  ++avg->count;
}

void AvgMerge(FunctionContext* context, const BufferVal& src, BufferVal* dst) {
  if (src == NULL) return;
  const AvgStruct* src_struct = reinterpret_cast<const AvgStruct*>(src);
  AvgStruct* dst_struct = reinterpret_cast<AvgStruct*>(*dst);
  dst_struct->sum += src_struct->sum;
  dst_struct->count += src_struct->count;
}

DoubleVal AvgFinalize(FunctionContext* context, const BufferVal& val) {
  if (val == NULL) return DoubleVal::null();
  AvgStruct* val_struct = reinterpret_cast<AvgStruct*>(val);
  return DoubleVal(val_struct->sum / val_struct->count);
}

// ---------------------------------------------------------------------------
// This is a sample of implementing the STRING_CONCAT aggregate function.
// Example: select string_concat(string_col, ",") from table
// ---------------------------------------------------------------------------
// Delimiter to use if the separator is NULL.
static const StringVal DEFAULT_STRING_CONCAT_DELIM((uint8_t*)", ", 2);

void StringConcatInit(FunctionContext* context, StringVal* val) {
  val->is_null = true;
}

void StringConcatUpdate(FunctionContext* context, const StringVal& str,
    const StringVal& separator, StringVal* result) {
  if (str.is_null) return;
  if (result->is_null) {
    // This is the first string, simply set the result to be the value.
    uint8_t* copy = context->Allocate(str.len);
    memcpy(copy, str.ptr, str.len);
    *result = StringVal(copy, str.len);
    return;
  }

  const StringVal* sep_ptr = separator.is_null ? &DEFAULT_STRING_CONCAT_DELIM :
      &separator;

  // We need to grow the result buffer and then append the new string and
  // separator.
  int new_size = result->len + sep_ptr->len + str.len;
  result->ptr = context->Reallocate(result->ptr, new_size);
  memcpy(result->ptr + result->len, sep_ptr->ptr, sep_ptr->len);
  result->len += sep_ptr->len;
  memcpy(result->ptr + result->len, str.ptr, str.len);
  result->len += str.len;
}

void StringConcatMerge(FunctionContext* context, const StringVal& src, StringVal* dst) {
  if (src.is_null) return;
  StringConcatUpdate(context, src, ",", dst);
}

StringVal StringConcatFinalize(FunctionContext* context, const StringVal& val) {
  return val;
}
