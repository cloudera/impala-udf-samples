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

#include "udf-sample.h"
#include <math.h>

// In this sample we are declaring a UDF that adds two ints and returns an int.
IntVal AddUdf(FunctionContext* context, const IntVal& arg1, const IntVal& arg2) {
  if (arg1.is_null || arg2.is_null) return IntVal::null();
  return IntVal(arg1.val + arg2.val);
}

// Multiple UDFs can be defined in the same file

BooleanVal FuzzyEquals(FunctionContext* ctx, const DoubleVal& x, const DoubleVal& y) {
  const double EPSILON = 0.000001f;
  if (x.is_null || y.is_null) return BooleanVal::null();
  double delta = fabs(x.val - y.val);
  return BooleanVal(delta < EPSILON);
}

// Check if the input string has any occurrences of the letters (a,e,i,o,u).
// Case-insensitive, so also detects (A,E,I,O,U).
BooleanVal HasVowels(FunctionContext* context, const StringVal& input) {
  if (input.is_null) return BooleanVal::null();

  int index;
  uint8_t *ptr;

  for (ptr = input.ptr, index = 0; index <= input.len; index++, ptr++) {
    uint8_t c = tolower(*ptr);
    if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
      return BooleanVal(true);
    }
  }
  return BooleanVal(false);
}

// Count all occurrences of the letters (a,e,i,o,u) in the input string.
// Case-insensitive, so also counts (A,E,I,O,U).
IntVal CountVowels(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return IntVal::null();

  int count;
  int index;
  uint8_t *ptr;

  for (ptr = arg1.ptr, count = 0, index = 0; index <= arg1.len; index++, ptr++) {
    uint8_t c = tolower(*ptr);
    if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
      count++;
    }
  }
  return IntVal(count);
}

// Remove all occurrences of the letters (a,e,i,o,u) from the input string.
// Case-insensitive, so also removes (A,E,I,O,U).
StringVal StripVowels(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();

  int index;
  std::string original((const char *)arg1.ptr,arg1.len);
  std::string shorter("");

  for (index = 0; index < original.length(); index++) {
    uint8_t c = original[index];
    uint8_t l = tolower(c);

    if (l == 'a' || l == 'e' || l == 'i' || l == 'o' || l == 'u') {
      ;
    }
    else {
        shorter.append(1, (char)c);
    }
  }
  // The modified string is stored in 'shorter', which is destroyed when this function ends. We need to make a string val
  // and copy the contents.
  StringVal result(context, shorter.size()); // Only the version of the ctor that takes a context object allocates new memory
  memcpy(result.ptr, shorter.c_str(), shorter.size());
  return result;
}
