#ifndef PAPI_TRACER_H
#define PAPI_TRACER_H

#ifdef HAVE_PAPI

#include <papi.h>

#include <iostream>
#include <stdexcept>


// This class provides very simple tracing and printing mechanisms to
// analyze the performance of a certain piece of code. Currently, the
// tracer only captures number of instructions and cycles.
class Tracer {

  int _eventset[2];;

  // Real time
  float _rtime;

  // Instructions
  long long _ins;

  // Cycles
  long long _cyc;

  // Number of calls to the UDF 
  int _calls;
  
  void handleError(int retval) {
    if (retval != PAPI_OK) {
      throw std::runtime_error(PAPI_strerror(retval));
    }
  }
  

public:

   Tracer() :  _rtime(0.0f), _ins(0ll), _cyc(0ll), _calls(1) {
    int retval = PAPI_library_init( PAPI_VER_CURRENT );
    if ( retval != PAPI_VER_CURRENT )
      throw std::runtime_error(std::string("Could not initialize PAPI: ") + PAPI_strerror(retval));
  }

  // Start the tracing procedure and add the events to the
  // eventlist. The calls parameter can be used if multiple iterations of a
  // certain piece of code are tested and this parameter is then used for
  // normalization of the output.
  void start(unsigned calls = 1) {
    _calls = calls;
    _eventset[0] = PAPI_TOT_CYC;
    _eventset[1] = PAPI_TOT_INS;

    // Get timers
    _rtime = PAPI_get_real_usec();
    handleError(PAPI_start_counters(_eventset, 2));
  }

  // stop tracing and clear the state
  void stop() {
    long long data[2];
    handleError(PAPI_stop_counters(data, 2));

    _rtime = PAPI_get_real_usec() - _rtime;
    _ins = data[1];
    _cyc = data[0];
  }

  int numCalls() {
    return _calls;
  }




  void print() {
    const PAPI_hw_info_t *hwinfo = PAPI_get_hardware_info();

    std::cout << "Real Time:                 " << (_rtime / _calls) << std::endl;
    std::cout << "Total Instructions:        " << (_ins / _calls) << std::endl;
    std::cout << "Instructions / Cycle:        " << (float(_ins) / float(_cyc)) << std::endl;
    std::cout << "Cycles / Call:             " << (_cyc / _calls) << std::endl;
    std::cout << "Time in s per 10^9 calls @3GhZ: " << ((_cyc * 1000000000ll) / (3 * 1000000000ll) / _calls) << std::endl;
    std::cout << "Time in s per 10^9 calls @2GhZ: " << ((_cyc * 1000000000ll) / (2 * 1000000000ll) / _calls) << std::endl;
  }

};


class ScopedTracer {
  const std::string _msg;
  Tracer _trc;
public:

 ScopedTracer(const std::string& msg, int c) : _msg(msg) {
    _trc.start(c);
  }

  explicit ScopedTracer(unsigned c) {
    _trc.start(c);
  }

  ~ScopedTracer() {
    _trc.stop();
    std::cout << "\n--------------------------------------" << std::endl;
    std::cout << "Performance Analysis for " << _msg << std::endl;
    _trc.print();
    std::cout << std::endl;
  }

  int numCalls() {
    return _trc.numCalls();
  }

};

#endif
#endif // PAPI_TRACER_H
