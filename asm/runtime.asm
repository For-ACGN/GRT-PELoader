IFDEF _WIN32
.model tiny
ENDIF

.code

IFDEF _WIN32
  INCLUDE <runtime_x86.inst>
ELSE
  INCLUDE <runtime_x64.inst>
ENDIF

IFNDEF RELEASE_MODE
  INCLUDE <runtime_arg.inst>
ENDIF

end
