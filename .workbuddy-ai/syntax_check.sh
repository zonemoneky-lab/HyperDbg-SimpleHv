#!/bin/sh
# Syntax-only compile check for the SimpleHv kernel driver sources.
# Usage: sh .workbuddy-ai/syntax_check.sh <relative/source/file.c> [more files...]
#
# NOTE: use '-' style flags (this is MSVC invoked from Git Bash, so '/' flags
# would be mangled into paths).

MSVC_INC="/c/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC/14.44.35207/include"
CL="/c/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/cl.exe"
WDK="/c/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0"
KMDF="/c/Program Files (x86)/Windows Kits/10/Include/wdf/kmdf/1.35"
ROOT="$(pwd)"

"$CL" -nologo -Zs -W3 \
  -D_AMD64_ -DAMD64 -kernel \
  -I"$WDK/km/crt" \
  -I"$WDK/km" \
  -I"$WDK/shared" \
  -I"$KMDF" \
  -I"$MSVC_INC" \
  -I"$ROOT/include" \
  -I"$ROOT/header" \
  -I"$ROOT/code" \
  -I"$ROOT" \
  -I"$ROOT/dependencies" \
  -I"$ROOT/dependencies/zydis/include" \
  -I"$ROOT/dependencies/zydis/dependencies/zycore/include" \
  "$@"
echo "EXIT=$?"
