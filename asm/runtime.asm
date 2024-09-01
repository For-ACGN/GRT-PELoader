IFDEF _WIN32
.model tiny
ENDIF

.code

IFDEF _WIN32
  _InitRuntime@4 proc
  INCLUDE <runtime_x86.inst>
  _InitRuntime@4 endp
ELSE
  InitRuntime proc
  INCLUDE <runtime_x64.inst>
  InitRuntime endp
ENDIF

IFNDEF RELEASE_MODE
  TestRuntimeArgStub proc
  INCLUDE <runtime_args.inst>
  TestRuntimeArgStub endp
ENDIF

end
