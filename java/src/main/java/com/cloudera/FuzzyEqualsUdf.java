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

package com.cloudera.impala;

import org.apache.hadoop.hive.ql.exec.UDF;
import org.apache.hadoop.hive.serde2.io.ByteWritable;
import org.apache.hadoop.hive.serde2.io.DoubleWritable;
import org.apache.hadoop.hive.serde2.io.ShortWritable;
import org.apache.hadoop.hive.serde2.io.TimestampWritable;
import org.apache.hadoop.io.BooleanWritable;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.FloatWritable;
import org.apache.hadoop.io.IntWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;

/**
 * Udf that returns true if two double arguments  are approximately equal.
 * Usage: > create fuzzy_equals(double, double) returns boolean
 *          location '/user/cloudera/hive-udf-samples-1.0.jar'
 *          SYMBOL='com.cloudera.impala.FuzzyEqualsUdf';
 *        > select fuzzy_equals(1, 1.000001);
 */
public class FuzzyEqualsUdf extends UDF {
  public FuzzyEqualsUdf() {
  }

  public BooleanWritable evaluate(DoubleWritable x, DoubleWritable y) {
    double EPSILON = 0.000001f;
    if (x == null || y == null) return null;
    return new BooleanWritable(Math.abs(x.get() - y.get()) < EPSILON);
  }
}
