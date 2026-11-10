#!/bin/sh
# PCMF R244 explicit tier writes + hardened owner acceptance + local llama.cpp.
# Ubuntu/Linux x86_64 native build. Core remains PCMF_IPv1 compatible.
set -eu
cd "$(dirname "$0")/.."

CFL="-std=c11 -O2 -Wall -Wextra -Werror -pedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2"
CXXFL="-std=c++20 -O2 -Wall -Wextra -Werror -pedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2"

command -v cc >/dev/null 2>&1 || { echo "BLOCKED compiler cc missing" >&2; exit 2; }
command -v c++ >/dev/null 2>&1 || { echo "BLOCKED compiler c++ missing" >&2; exit 2; }
command -v sha256sum >/dev/null 2>&1 || { echo "BLOCKED sha256sum missing" >&2; exit 2; }

mkdir -p build bin connector

cc $CFL -c src/pcmf_sha256.c -o build/sha256.o
cc $CFL -c src/pcmf_policy.c -o build/policy.o
for f in pcmf_json pcmf_util pcmf_engine pcmf_engine_ops pcmf_engine_admin; do
  c++ $CXXFL -c src/$f.cpp -o build/$f.o
done

CORE="build/sha256.o build/policy.o build/pcmf_json.o build/pcmf_util.o build/pcmf_engine.o build/pcmf_engine_ops.o build/pcmf_engine_admin.o"

c++ $CXXFL $CORE src/pcmf_cli.cpp -o bin/pcmf -static-libstdc++ -static-libgcc
c++ $CXXFL $CORE src/pcmf_serve.cpp -o bin/pcmf-serve -static-libstdc++ -static-libgcc
c++ $CXXFL $CORE src/pcmf_setup.cpp -o bin/pcmf-setup -static-libstdc++ -static-libgcc
c++ $CXXFL -I src -I tests $CORE tests/pcmf_selftest.cpp -o bin/pcmf-selftest -static-libstdc++ -static-libgcc

PCMF_SHA=$(sha256sum bin/pcmf | awk '{print $1}')
c++ $CXXFL -DPCMF_OWNER_CLI_SHA256=\"$PCMF_SHA\" \
  src/forge_pcmf_owner_review_r4.cpp src/pcmf_json.cpp build/sha256.o \
  -o bin/forge-pcmf-owner-review-r4 -lX11 -static-libstdc++ -static-libgcc
chmod 700 bin/forge-pcmf-owner-review-r4
REVIEWER_SHA=$(sha256sum bin/forge-pcmf-owner-review-r4 | awk '{print $1}')

c++ $CXXFL -DPCMF_OWNER_REVIEWER_R4_SHA256=\"$REVIEWER_SHA\" \
  src/pcmf_mcp_review_r2.cpp src/pcmf_json.cpp src/pcmf_util.cpp build/sha256.o \
  -o connector/pcmf-mcp-review-r2 -static-libstdc++ -static-libgcc
chmod 700 connector/pcmf-mcp-review-r2

c++ $CXXFL src/pcmf_local_model.cpp src/pcmf_json.cpp \
  -o bin/pcmf-local-model -static-libstdc++ -static-libgcc
chmod 700 bin/pcmf-local-model

chmod 700 bin/pcmf bin/pcmf-serve bin/pcmf-setup bin/pcmf-selftest
chmod 700 scripts/configure_forge_gpt_r2.sh

echo "PCMF_SHA256=$PCMF_SHA"
echo "REVIEWER_SHA256=$REVIEWER_SHA"
sha256sum bin/pcmf bin/pcmf-serve bin/pcmf-setup bin/pcmf-selftest \
  bin/forge-pcmf-owner-review-r4 bin/pcmf-local-model connector/pcmf-mcp-review-r2
echo "PASS_PCMF_R244_EXPLICIT_TIER_NATIVE_BUILD"
