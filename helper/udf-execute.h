#ifndef UDF_EXECUTE_HELPER_H
#define UDF_EXECUTE_HELPER_H

#include <boost/function.hpp>
#include <boost/scoped_ptr.hpp>

#include <impala_udf/udf.h>
#include <impala_udf/udf-debug.h>


namespace impala_udf {

class UdfExecuteHelper {

  boost::scoped_ptr<FunctionContext> context;

 public:

 UdfExecuteHelper() : context(FunctionContext::CreateTestContext()) {}

  template<typename RET>
  RET ExecuteUdf(boost::function<RET(FunctionContext*)> fn) {
    return fn(context.get());
  }

  template<typename RET, typename A1>
  RET ExecuteUdf(boost::function<RET(FunctionContext*, const A1&)> fn,
      const A1& a1) {
    return fn(context.get(), a1);
  }

  template<typename RET, typename A1>
  RET ExecuteUdf(boost::function<RET(FunctionContext*, int, const A1*)> fn,
      const std::vector<A1>& a1) {
    return fn(context.get(), a1.size(), &a1[0]);
  }

  template<typename RET, typename A1, typename A2>
  RET ExecuteUdf(
      boost::function<RET(FunctionContext*, const A1&, const A2&)> fn,
      const A1& a1, const A2& a2) {
    return fn(context.get(), a1, a2);
  }

  template<typename RET, typename A1, typename A2>
  RET ExecuteUdf(
      boost::function<RET(FunctionContext*, const A1&, int, const A2*)> fn,
      const A1& a1, const std::vector<A2>& a2) {
    return fn(context.get(), a1, a2.size(), &a2[0]);
  }

  template<typename RET, typename A1, typename A2, typename A3>
  RET ExecuteUdf(
      boost::function<RET(FunctionContext*, const A1&, const A2&, const A3&)> fn,
      const A1& a1, const A2& a2, const A3& a3) {
    return fn(context.get(), a1, a2, a3);
  }

  template<typename RET, typename A1, typename A2, typename A3>
  RET ExecuteUdf(
      boost::function<RET(FunctionContext*, const A1&, const A2&, int, const A3*)> fn,
      const A1& a1, const A2& a2, const std::vector<A3>& a3) {
    return fn(context.get(), a1, a2, a3.size(), &a3[0]);
  }

  template<typename RET, typename A1, typename A2, typename A3, typename A4>
  RET ExecuteUdf(
      boost::function<RET(FunctionContext*, const A1&, const A2&, const A3&,
          const A4&)> fn,
      const A1& a1, const A2& a2, const A3& a3, const A4& a4) {
    return fn(context.get(), a1, a2, a3, a4);
  }

  template<typename RET, typename A1, typename A2, typename A3, typename A4>
  RET ExecuteUdf(
      boost::function<RET(FunctionContext*, const A1&, const A2&, const A3&,
          int, const A4*)> fn,
      const A1& a1, const A2& a2, const A3& a3, const std::vector<A4>& a4) {
    return fn(context.get(), a1, a2, a3, a4.size(), &a4[0]);
  }

  template<typename RET, typename A1, typename A2, typename A3, typename A4,
      typename A5>
  RET ExecuteUdf(
      boost::function<RET(FunctionContext*, const A1&, const A2&, const A3&,
          const A4&, const A5&)> fn,
      const A1& a1, const A2& a2, const A3& a3, const A4& a4, const A5& a5) {
    return fn(context.get(), a1, a2, a3, a4, a5);
  }

  template<typename RET, typename A1, typename A2, typename A3, typename A4,
      typename A5, typename A6>
  RET ExecuteUdf(
      boost::function<RET(FunctionContext*, const A1&, const A2&, const A3&,
          const A4&, const A5&, const A6&)> fn,
      const A1& a1, const A2& a2, const A3& a3, const A4& a4, const A5& a5,
      const A6& a6) {
    return fn(context.get(), a1, a2, a3, a4, a5, a6);
  }

  template<typename RET, typename A1, typename A2, typename A3, typename A4,
      typename A5, typename A6, typename A7>
  RET ValidateUdf(
      boost::function<RET(FunctionContext*, const A1&, const A2&, const A3&,
          const A4&, const A5&, const A6&, const A7&)> fn,
      const A1& a1, const A2& a2, const A3& a3, const A4& a4, const A5& a5,
      const A6& a6, const A7& a7) {
    return fn(context.get(), a1, a2, a3, a4, a5, a6, a7);
  }

  template<typename RET, typename A1, typename A2, typename A3, typename A4,
      typename A5, typename A6, typename A7, typename A8>
  RET ValidateUdf(
      boost::function<RET(FunctionContext*, const A1&, const A2&, const A3&,
          const A4&, const A5&, const A6&, const A7&)> fn,
      const A1& a1, const A2& a2, const A3& a3, const A4& a4, const A5& a5,
      const A6& a6, const A7& a7, const A8& a8, const RET& expected) {
    return fn(context.get(), a1, a2, a3, a4, a5, a6, a7, a8);
  }
};

}


#endif // UDF_EXECUTE_HELPER_H
