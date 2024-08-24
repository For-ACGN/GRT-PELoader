IFDEF _WIN32
.model tiny
ENDIF

.code

IFDEF _WIN32
  INCLUDE <runtime_x86.asm>
ELSE
  INCLUDE <runtime_x64.asm>
ENDIF

end
