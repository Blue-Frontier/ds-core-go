#!/usr/bin/env bash
# Rebuilds build/kernel.aar from ./mobile with gomobile.
#
# No proxy and no network rewrite here: a local run picks its Go proxy up from
# the environment (or from kernel/env.sh), and an offline build of the kind
# F-Droid runs works from vendor/ alone.
#
# Usage: ./build-kernel-aar.sh [target ...]
#        Default target is android/arm64; android/amd64 covers x86_64.
#        gomobile honours only one architecture per invocation, so each target
#        is built on its own and merged into one AAR below.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
native_dir() { case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) cygpath -m "$1" ;; *) printf '%s' "$1" ;; esac; }
cd "$HERE"

TARGETS=("$@")
if ((${#TARGETS[@]} == 0)); then TARGETS=(android/arm64); fi

if [[ -f "$HERE/env.sh" ]]; then
    # shellcheck disable=SC1091
    . "$HERE/env.sh"
fi

if [[ -z "${ANDROID_HOME:-}" ]]; then
    echo "ANDROID_HOME is not set" >&2
    exit 1
fi

# gomobile shells out to javac when it generates the Java bindings, so JAVA_HOME
# has to be on PATH as well.
if [[ -n "${JAVA_HOME:-}" ]]; then
    case "$(uname -s)" in
        # MSYS needs the POSIX form on PATH, gomobile execs javac directly.
        MINGW* | MSYS* | CYGWIN*) JAVA_HOME=$(cygpath -u "$JAVA_HOME") ;;
    esac
    export JAVA_HOME
    export PATH="$JAVA_HOME/bin:$PATH"
fi

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    NDK=$(find "$ANDROID_HOME/ndk" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort | tail -1)
    if [[ -z "$NDK" ]]; then echo "no NDK under $ANDROID_HOME/ndk (set ANDROID_NDK_HOME)" >&2; exit 1; fi
    export ANDROID_NDK_HOME="$NDK"
fi
export ANDROID_NDK="$ANDROID_NDK_HOME"
echo "NDK=$ANDROID_NDK_HOME"

# Offline module resolution: kernel/goproxy is a file:// module proxy holding
# exactly the modules this build needs. F-Droid builds without a network, and
# a vendor/ tree is not an option: Go would switch to -mod=vendor and gomobile
# cannot find its own package there.
if [[ -d "$HERE/goproxy" ]]; then
    _proxy_dir=$(native_dir "$HERE/goproxy")
    case "$_proxy_dir" in /*) GOPROXY="file://$_proxy_dir" ;; *) GOPROXY="file:///$_proxy_dir" ;; esac
    export GOPROXY
    export GOFLAGS="${GOFLAGS:--mod=mod}"
    export GOSUMDB=off
    echo "GOPROXY=$GOPROXY"
fi

# gomobile has to exist before bind runs; install it from the proxy when it is
# not on PATH (the version is pinned in go.mod).
if ! command -v gomobile >/dev/null; then
    ver=$(awk '/golang.org\/x\/mobile v/ {print $2}' go.mod | head -1)
    if [[ -z "$ver" ]]; then echo "golang.org/x/mobile version not found in go.mod" >&2; exit 1; fi
    echo "installing gomobile $ver"
    GOFLAGS="${GOFLAGS:--mod=mod}" go install "golang.org/x/mobile/cmd/gomobile@$ver"
    # gomobile shells out to gobind, which is a separate main package.
    GOFLAGS="${GOFLAGS:--mod=mod}" go install "golang.org/x/mobile/cmd/gobind@$ver"
    gopath=$(go env GOPATH)
    case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) gopath=$(cygpath -u "$gopath") ;; esac
    export PATH="$gopath/bin:$PATH"
fi

# A fresh clone has no build/ (it is git-ignored) and gomobile will not create
# the output file's parent directory.
mkdir -p build

PARTS=()
for t in "${TARGETS[@]}"; do
    name=${t#android/}
    name=${name//[^A-Za-z0-9]/-}
    part="build/kernel-$name.aar"
    echo "gomobile bind -target=$t"
    gomobile bind "-target=$t" -androidapi=35 -o "$part" ./mobile
    PARTS+=("$part")
done

# The first AAR is the base (classes.jar and the manifest are identical for every
# architecture); the rest only contribute their jni/<abi>/libgojni.so.
FINAL=build/kernel.aar
cp "${PARTS[0]}" "$FINAL"
if ((${#PARTS[@]} > 1)); then
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    for part in "${PARTS[@]:1}"; do
        rm -rf "$TMP"/*
        unzip -q "$part" -d "$TMP"
        while IFS= read -r so; do
            abi=$(basename "$(dirname "$so")")
            entry="jni/$abi/libgojni.so"
            if unzip -l "$FINAL" | grep -q " $entry\$"; then continue; fi
            # jar uf adds an entry without rewriting the rest of the archive.
            (cd "$TMP" && jar uf "$HERE/$FINAL" "$entry")
            echo "merged $entry"
        done < <(find "$TMP" -name libgojni.so | sort)
    done
fi

echo "ABIS: $(unzip -l "$FINAL" | grep -o 'jni/[^/]*/libgojni.so' | sort | tr '\n' ' ')"
echo GOMOBILE-OK
