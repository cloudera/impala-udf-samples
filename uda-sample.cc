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
#include <sstream>

#include "common.h"

using namespace impala_udf;
using namespace std;

template <typename T>
StringVal ToStringVal(FunctionContext* context, const T& val) {
  stringstream ss;
  ss << val;
  string str = ss.str();
  StringVal string_val(context, str.size());
  memcpy(string_val.ptr, str.c_str(), str.size());
  return string_val;
}

template <>
StringVal ToStringVal<DoubleVal>(FunctionContext* context, const DoubleVal& val) {
  if (val.is_null) return StringVal::null();
  return ToStringVal(context, val.val);
}

// ---------------------------------------------------------------------------
// This is a sample of implementing a COUNT aggregate function.
// ---------------------------------------------------------------------------
IMPALA_UDF_EXPORT
void CountInit(FunctionContext* context, BigIntVal* val) {
  val->is_null = false;
  val->val = 0;
}

IMPALA_UDF_EXPORT
void CountUpdate(FunctionContext* context, const IntVal& input, BigIntVal* val) {
  if (input.is_null) return;
  ++val->val;
}

IMPALA_UDF_EXPORT
void CountMerge(FunctionContext* context, const BigIntVal& src, BigIntVal* dst) {
  dst->val += src.val;
}

IMPALA_UDF_EXPORT
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

// Initialize the StringVal intermediate to a zero'd AvgStruct
IMPALA_UDF_EXPORT
void AvgInit(FunctionContext* context, StringVal* val) {
  val->ptr = context->Allocate(sizeof(AvgStruct));
  // Exit on failed allocation. Impala will fail the query after some time.
  if (val->ptr == NULL) {
    *val = StringVal::null();
    return;
  }
  val->is_null = false;
  val->len = sizeof(AvgStruct);
  memset(val->ptr, 0, val->len);
}

IMPALA_UDF_EXPORT
void AvgUpdate(FunctionContext* context, const DoubleVal& input, StringVal* val) {
  if (input.is_null) return;
  // Handle failed allocation. Impala will fail the query after some time.
  if (val->is_null) return;
  assert(val->len == sizeof(AvgStruct));
  AvgStruct* avg = reinterpret_cast<AvgStruct*>(val->ptr);
  avg->sum += input.val;
  ++avg->count;
}

IMPALA_UDF_EXPORT
void AvgMerge(FunctionContext* context, const StringVal& src, StringVal* dst) {
  if (src.is_null || dst->is_null) return;
  const AvgStruct* src_avg = reinterpret_cast<const AvgStruct*>(src.ptr);
  AvgStruct* dst_avg = reinterpret_cast<AvgStruct*>(dst->ptr);
  dst_avg->sum += src_avg->sum;
  dst_avg->count += src_avg->count;
}

// A serialize function is necesary to free the intermediate state allocation. We use the
// StringVal constructor to allocate memory owned by Impala, copy the intermediate state,
// and free the original allocation. Note that memory allocated by the StringVal ctor is
// not necessarily persisted across UDA function calls, which is why we don't use it in
// AvgInit().
IMPALA_UDF_EXPORT
StringVal AvgSerialize(FunctionContext* context, const StringVal& val) {
  if (val.is_null) return StringVal::null();
  // Copy the value into Impala-managed memory with StringVal::CopyFrom().
  // NB: CopyFrom() will return a null StringVal and and fail the query if the allocation
  // fails because of lack of memory.
  StringVal result = StringVal::CopyFrom(context, val.ptr, val.len);
  context->Free(val.ptr);
  return result;
}

IMPALA_UDF_EXPORT
StringVal AvgFinalize(FunctionContext* context, const StringVal& val) {
  if (val.is_null) return StringVal::null();
  assert(val.len == sizeof(AvgStruct));
  AvgStruct* avg = reinterpret_cast<AvgStruct*>(val.ptr);
  StringVal result;
  if (avg->count == 0) {
    result = StringVal::null();
  } else {
    // Copies the result to memory owned by Impala
    result = ToStringVal(context, avg->sum / avg->count);
  }
  context->Free(val.ptr);
  return result;
}

// ---------------------------------------------------------------------------
// This is a sample of implementing the STRING_CONCAT aggregate function.
// Example: select string_concat(string_col, ",") from table
// ---------------------------------------------------------------------------
// Delimiter to use if the separator is NULL.
static const StringVal DEFAULT_STRING_CONCAT_DELIM((uint8_t*)", ", 2);

IMPALA_UDF_EXPORT
void StringConcatInit(FunctionContext* context, StringVal* val) {
  val->is_null = true;
}

IMPALA_UDF_EXPORT
void StringConcatUpdate(FunctionContext* context, const StringVal& str,
    const StringVal& separator, StringVal* result) {
  if (str.is_null) return;
  if (result->is_null) {
    // This is the first string, simply set the result to be the value.
    uint8_t* copy = context->Allocate(str.len);
    // If the allocation fails, don't update the result, just let Impala fail the query.
    if (copy == NULL) return;
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
  if (result->ptr == NULL) {
    // If the allocation fails, set the result to null and let Impala fail the query.
    *result = StringVal::null();
    return;
  }
  memcpy(result->ptr + result->len, sep_ptr->ptr, sep_ptr->len);
  result->len += sep_ptr->len;
  memcpy(result->ptr + result->len, str.ptr, str.len);
  result->len += str.len;
}

IMPALA_UDF_EXPORT
void StringConcatMerge(FunctionContext* context, const StringVal& src, StringVal* dst) {
  if (src.is_null) return;
  StringConcatUpdate(context, src, ",", dst);
}

// A serialize function is necesary to free the intermediate state allocation. We use the
// StringVal constructor to allocate memory owned by Impala, copy the intermediate
// StringVal, and free the intermediate's memory. Note that memory allocated by the
// StringVal ctor is not necessarily persisted across UDA function calls, which is why we
// don't use it in StringConcatUpdate().
IMPALA_UDF_EXPORT
StringVal StringConcatSerialize(FunctionContext* context, const StringVal& val) {
  if (val.is_null) return val;
  // Copy the value into Impala-managed memory with StringVal::CopyFrom().
  // NB: CopyFrom() will return a null StringVal and and fail the query if the allocation
  // fails because of lack of memory.
  StringVal result = StringVal::CopyFrom(context, val.ptr, val.len);
  context->Free(val.ptr);
  return result;
}

// Same as StringConcatSerialize().
IMPALA_UDF_EXPORT
StringVal StringConcatFinalize(FunctionContext* context, const StringVal& val) {
  if (val.is_null) return val;
  // Copy the value into Impala-managed memory with StringVal::CopyFrom().
  // NB: CopyFrom() will return a null StringVal and and fail the query if the allocation
  // fails because of lack of memory.
  StringVal result = StringVal::CopyFrom(context, val.ptr, val.len);
  context->Free(val.ptr);
  return result;
}
