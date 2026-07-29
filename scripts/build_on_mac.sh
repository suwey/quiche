#!/bin/bash
# Build script: compile all targets (desktop + Linux musl + Android) and optionally build APK.
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
for arg in "$@"; do
    case "$arg" in
        --apk) BUILD_APK=true ;;
        --all) BUILD_APK=true ;;
    esac
done

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
cargo build -p anywhere

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
    echo "  ./scripts/build.sh --apk"
    echo "  (or open the project in Android Studio)"
fi
