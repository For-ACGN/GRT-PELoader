IFDEF _WIN32
.model flat
ENDIF

.code

IFDEF _WIN32
  _InitRuntime@4 proc
  INCLUDE <inst/runtime_x86.inst>
  _InitRuntime@4 endp
ELSE
  InitRuntime proc
  INCLUDE <inst/runtime_x64.inst>
  InitRuntime endp
ENDIF

IFDEF _WIN32
  _Argument_Stub@0 proc
  INCLUDE <inst/argument_x86.inst>
  _Argument_Stub@0 endp
ELSE
  Argument_Stub proc
  INCLUDE <inst/argument_x64.inst>
  Argument_Stub endp
ENDIF

end
