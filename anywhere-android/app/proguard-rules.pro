# Keep JNI bridge classes - Rust calls them by exact name
-keep class com.anywhere.android.EngineBridge { *; }
-keep class com.anywhere.android.ProxyVpnService { *; }

# Keep classes referenced by JNI (protect method, onEngineRestart)
-keepclassmembers class com.anywhere.android.ProxyVpnService {
    public boolean protect(int);
    public void onEngineRestart();
}

# Keep Compose runtime
-dontwarn androidx.compose.**
-keep class androidx.compose.** { *; }

# Rust .so is not affected by ProGuard, but keep native method declarations
-keepclasseswithmembernames class * {
    native <methods>;
}
