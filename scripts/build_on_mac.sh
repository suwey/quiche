#!/bin/bash
# Build script: compile all targets (desktop + Linux musl + Android) and optionally build APK.
#
# Usage:
#   ./scripts/build_on_mac.sh            # build all targets (desktop is debug)
#   ./scripts/build_on_mac.sh --apk      # also build the Android release APK
#   ./scripts/build_on_mac.sh --releases # desktop becomes release; collect
#                                        # anywhere-v<version>-<platform>.(tgz|apk)
#                                        # for every platform into quiche/releases/
#                                        # (implies --apk)
#
# Prerequisites:
#   - Android NDK installed (ANDROID_NDK_HOME set)
#   - Rust targets: rustup target add aarch64-linux-android aarch64-unknown-linux-musl
#   - cargo-ndk: cargo install cargo-ndk
#   - cargo-zigbuild: cargo install cargo-zigbuild
#   - For APK: Android SDK with build-tools + JDK 17+

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

# --- Load user environment (non-interactive shell doesn't source .zshrc) ---
# NOTE: If you run this script manually from your terminal, you can comment
#       out this block — your shell already has these vars from .zshrc.
#       This is only needed when running from a non-interactive context (CI, agent, etc.).
if [[ -f "$HOME/.zshrc" ]]; then
    eval "$(grep -E '^export [A-Z_]+=' "$HOME/.zshrc" 2>/dev/null || true)"
fi

ANDROID_PROJECT="$SCRIPT_DIR/../anywhere-android"
RUST_PROJECT="$SCRIPT_DIR/../anywhere"

# --- Parse args ---
BUILD_APK=false
RELEASES=false
RELEASE_FLAG=""
for arg in "$@"; do
    case "$arg" in
        --apk) BUILD_APK=true ;;
        --all) BUILD_APK=true ;;
        # Build release artifacts for every platform and collect them in
        # quiche/releases/ as anywhere-v<version>-<platform>.(tgz|apk),
        # ready for a GitHub release upload. Implies --apk.
        --releases) RELEASES=true; BUILD_APK=true ;;
    esac
done
if [[ "$RELEASES" == "true" ]]; then
    RELEASE_FLAG="--release"
fi

# Crate version from the [package] section (single source of truth for
# artifact naming; the Android gradle build reads the same field).
VERSION=$(awk '/^\[package\]/{p=1;next} /^\[/{p=0} p && /^version/{gsub(/"/,"",$3); print $3; exit}' "$RUST_PROJECT/Cargo.toml")
if [[ -z "$VERSION" ]]; then
    echo "ERROR: failed to parse version from $RUST_PROJECT/Cargo.toml"
    exit 1
fi

# --- Environment info ---
echo ""
echo "=== Environment ==="
echo "zig:      $(zig version 2>/dev/null || echo 'not found')"
echo "java:     $(java -version 2>&1 | head -1 || echo 'not found')"
echo "cargo:    $(cargo --version)"
echo "NDK:      ${ANDROID_NDK_HOME:-${NDK_HOME:-not set}}"
echo ""

# ============================================================
# 1. Desktop build (native)
# ============================================================
echo "=== Building desktop (native) ==="
cargo build -p anywhere $RELEASE_FLAG

# ============================================================
# 2. Linux musl cross-compile (aarch64) — requires zig
# ============================================================
if [[ -n "$(command -v zig 2>/dev/null || true)" ]]; then
    echo ""
    echo "=== Building aarch64-unknown-linux-musl ==="
    cargo zigbuild -p anywhere --target aarch64-unknown-linux-musl --release
else
    echo ""
    echo "=== Skipping aarch64-unknown-linux-musl (zig not found in PATH) ==="
    echo "  Current PATH: $PATH"
fi

# ============================================================
# 3. Windows cross-compile (x86_64-pc-windows-gnu) - requires mingw-w64
# ============================================================
# Prerequisites: rustup target add x86_64-pc-windows-gnu
#                brew install mingw-w64 nasm
if [[ -n "$(command -v x86_64-w64-mingw32-gcc 2>/dev/null || true)" ]]; then
    echo ""
    echo "=== Building x86_64-pc-windows-gnu ==="
    # Must build from anywhere/ so .cargo/config.toml (mingw linker/ar/rustflags)
    # is discovered by cargo (config lookup goes up from CWD, not into subdirs).
    cd "$RUST_PROJECT"
    # boring-sys bindgen needs the MinGW sysroot headers (sys/types.h etc.).
    MINGW_PREFIX="$(brew --prefix mingw-w64 2>/dev/null || echo /opt/homebrew/opt/mingw-w64)"
    MINGW_SYSROOT="$MINGW_PREFIX/toolchain-x86_64/x86_64-w64-mingw32/include"
    if [[ -d "$MINGW_SYSROOT" ]]; then
        export BINDGEN_EXTRA_CLANG_ARGS="--target=x86_64-pc-windows-gnu -isystem $MINGW_SYSROOT"
    fi
    cargo build --target x86_64-pc-windows-gnu --release --bin anywhere
    cd "$SCRIPT_DIR/.."
    echo "  Product: target/x86_64-pc-windows-gnu/release/anywhere.exe"
else
    echo ""
    echo "=== Skipping x86_64-pc-windows-gnu (mingw-w64 not found) ==="
    echo "  Install: brew install mingw-w64 nasm"
    echo "  Target:  rustup target add x86_64-pc-windows-gnu"
fi
# ============================================================
# 4. Android cross-compile
# ============================================================
# --- Determine NDK path ---
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    # Try auto-detect from default location
    AUTO_NDK=$(ls -d "$HOME/Library/Android/sdk/ndk/"*/ 2>/dev/null | head -1)
    if [[ -n "$AUTO_NDK" ]]; then
        export ANDROID_NDK_HOME="${AUTO_NDK%/}"
        echo "Auto-detected NDK: $ANDROID_NDK_HOME"
    else
        echo "ERROR: ANDROID_NDK_HOME is not set."
        echo "  Set it to your NDK path, e.g.:"
        echo "  export ANDROID_NDK_HOME=\$HOME/Library/Android/sdk/ndk/28.0.12674087"
        exit 1
    fi
else
    echo "NDK: $ANDROID_NDK_HOME"
fi

# --- Rust targets to build ---
TARGETS=(
    "aarch64-linux-android"   # arm64-v8a (most modern devices)
    # "armv7-linux-androideabi"  # armeabi-v7a (older devices, uncomment if needed)
    # "x86_64-linux-android"     # x86_64 (emulator, uncomment if needed)
)

# --- Build each target ---
for target in "${TARGETS[@]}"; do
    echo ""
    echo "=== Building $target ==="

    cd "$RUST_PROJECT"

    # cargo-ndk simplifies Android cross-compilation (installs with: cargo install cargo-ndk)
    # It handles setting CC, CXX, and linker for the NDK automatically.
    if command -v cargo-ndk &>/dev/null; then
        cargo ndk -t "$target" build --release -p anywhere
    else
        # Fallback: manual cargo build with NDK linker
        export CC_aarch64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"
        export CC_armv7_linux_androideabi="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi24-clang"
        export CC_x86_64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android24-clang"

        cargo build --target "$target" --release -p anywhere
    fi

    # Copy .so to jniLibs
    ABI_DIR=""
    case "$target" in
        aarch64-linux-android)      ABI_DIR="arm64-v8a" ;;
        armv7-linux-androideabi)    ABI_DIR="armeabi-v7a" ;;
        x86_64-linux-android)       ABI_DIR="x86_64" ;;
        *) echo "Unknown ABI for $target"; exit 1 ;;
    esac

    SO_SRC="$SCRIPT_DIR/../target/$target/release/libanywhere.so"
    SO_DST="$ANDROID_PROJECT/app/src/main/jniLibs/$ABI_DIR/"

    mkdir -p "$SO_DST"
    cp "$SO_SRC" "$SO_DST"
    echo "Copied: $SO_SRC → $SO_DST"
done

# ============================================================
# 5. APK build (optional, pass --apk or --all)
# ============================================================
if [[ "$BUILD_APK" == "true" ]]; then
    echo ""
    echo "=== Building APK ==="

    cd "$ANDROID_PROJECT"

    # Ensure gradlew is executable
    chmod +x ./gradlew

    # Check JAVA_HOME
    if [[ -z "${JAVA_HOME:-}" ]]; then
        # Try to find Java on macOS
        JAVA_HOME=$(/usr/libexec/java_home 2>/dev/null || true)
        if [[ -z "$JAVA_HOME" ]]; then
            # Fallback: Android Studio's bundled JBR
            AS_JBR="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
            if [[ -x "$AS_JBR/bin/java" ]]; then
                JAVA_HOME="$AS_JBR"
                echo "Using Android Studio bundled JBR: $JAVA_HOME"
            else
                echo "ERROR: JAVA_HOME not set and no Java found."
                echo "  Install JDK 17+ or set JAVA_HOME."
                exit 1
            fi
        fi
        export JAVA_HOME
    fi

    echo "JAVA_HOME: $JAVA_HOME"

    # Set Android SDK location
    export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"
    echo "ANDROID_SDK_ROOT: $ANDROID_SDK_ROOT"

    # Build release APK (optimized, smaller, signed with debug key)
    ./gradlew assembleRelease --no-daemon

    APK_PATH="app/build/outputs/apk/release/app-release.apk"
    if [[ -f "$APK_PATH" ]]; then
        echo ""
        echo "✅ APK built: $ANDROID_PROJECT/$APK_PATH"
        ls -lh "$APK_PATH"
    else
        echo "ERROR: APK not found at expected path"
        exit 1
    fi
else
    echo ""
    echo "=== Build complete ==="
    echo "The .so files are in: $ANDROID_PROJECT/app/src/main/jniLibs/"
    echo ""
    echo "To build the APK, run:"
    echo "  ./scripts/build_on_mac.sh --apk"
    echo "  (or open the project in Android Studio)"
fi

# ============================================================
# 6. Package release artifacts (--releases)
# ============================================================
# Collect per-platform release artifacts into quiche/releases/ as
# anywhere-v<version>-<platform>.(tgz|apk), ready for GitHub upload.
if [[ "$RELEASES" == "true" ]]; then
    echo ""
    echo "=== Packaging releases (v${VERSION}) ==="
    REL_DIR="$SCRIPT_DIR/../releases"
    mkdir -p "$REL_DIR"
    # Stage inside REL_DIR, not the system tmpdir: sandboxed environments
    # can virtualize /var/folders|/tmp writes, which once materialized the
    # staging copies into releases/ itself. Workspace writes are always real.
    STAGE="$REL_DIR/.stage.$$"
    mkdir -p "$STAGE"
    trap 'rm -rf "$STAGE"' EXIT

    # Tar the given binaries into <top>.tgz with a top-level directory
    # named after the archive base. extra_src (may be empty) copies
    # additional deploy files (configs, runtime DLLs, ...) next to the
    # binary. Missing binaries are skipped with a warning.
    pack_bins() {
        local platform="$1" src="$2" extra_src="$3"
        shift 3
        local top="anywhere-v${VERSION}-${platform}"
        local bin have=0
        mkdir -p "$STAGE/$top"
        for bin in "$@"; do
            if [[ -f "$src/$bin" ]]; then
                cp "$src/$bin" "$STAGE/$top/"
                have=1
            else
                echo "  ⚠ $platform: $bin not found, skipped"
            fi
        done
        if [[ -n "$extra_src" ]]; then
            if [[ -d "$extra_src" ]]; then
                local f
                for f in "$extra_src"/*; do
                    if [[ -f "$f" ]]; then
                        cp "$f" "$STAGE/$top/"
                    fi
                done
            else
                echo "  ⚠ $platform: extra dir $extra_src not found, skipped"
            fi
        fi
        if [[ "$have" == "1" ]]; then
            # COPYFILE_DISABLE: keep macOS xattrs out of the archive
            # (otherwise every file gets a junk ._ AppleDouble twin)
            COPYFILE_DISABLE=1 tar --exclude='._*' -czf "$REL_DIR/${top}.tgz" -C "$STAGE" "$top"
            echo "  ✅ ${top}.tgz"
        fi
        rm -rf "$STAGE/$top"
    }

    pack_bins "mac-arm64" \
        "$SCRIPT_DIR/../target/release" "" \
        anywhere
    pack_bins "linux-aarch64-musl" \
        "$SCRIPT_DIR/../target/aarch64-unknown-linux-musl/release" "" \
        anywhere
    pack_bins "windows-x64-gnu" \
        "$SCRIPT_DIR/../target/x86_64-pc-windows-gnu/release" \
        "$SCRIPT_DIR/../anywhere/deploy/windows" \
        anywhere.exe

    # Android raw executable: the APK carries only the cdylib (not exec'able),
    # while the conformance harness runs this bin via adb shell.
    pack_bins "android-arm64" \
        "$SCRIPT_DIR/../target/aarch64-linux-android/release" "" \
        anywhere

    # Android APK
    APK_SRC="$ANDROID_PROJECT/app/build/outputs/apk/release/app-release.apk"
    if [[ -f "$APK_SRC" ]]; then
        cp "$APK_SRC" "$REL_DIR/anywhere-v${VERSION}-android-arm64.apk"
        echo "  ✅ anywhere-v${VERSION}-android-arm64.apk"
    else
        echo "  ⚠ APK not found, android artifact skipped"
    fi

    # Web UI, taken from the Android assets. AAPT forbids '_'-prefixed asset
    # dirs, so the repo stores nuxt/ and fonts/ — rename them back to
    # _nuxt/_fonts (same mapping as Kotlin's copyUiAssets) for serving.
    UI_SRC="$ANDROID_PROJECT/app/src/main/assets/ui"
    if [[ -d "$UI_SRC" ]]; then
        rm -rf "$STAGE/ui"
        cp -R "$UI_SRC" "$STAGE/ui"
        if [[ -d "$STAGE/ui/nuxt" ]]; then
            mv "$STAGE/ui/nuxt" "$STAGE/ui/_nuxt"
        fi
        if [[ -d "$STAGE/ui/fonts" ]]; then
            mv "$STAGE/ui/fonts" "$STAGE/ui/_fonts"
        fi
        COPYFILE_DISABLE=1 tar --exclude='._*' -czf "$REL_DIR/anywhere-v${VERSION}-ui.tgz" -C "$STAGE" ui
        rm -rf "$STAGE/ui"
        echo "  ✅ anywhere-v${VERSION}-ui.tgz"
    else
        echo "  ⚠ UI assets not found at $UI_SRC, ui artifact skipped"
    fi

    echo ""
    echo "=== Releases in $REL_DIR ==="
    ls -lh "$REL_DIR"
    echo ""
    echo "Upload hint:"
    echo "  gh release create v${VERSION} $REL_DIR/* --generate-notes"
fi
