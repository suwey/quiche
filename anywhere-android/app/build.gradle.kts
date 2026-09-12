plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Keep the APK version in sync with the Rust crate: read the [package]
// version straight from ../anywhere/Cargo.toml at configuration time, so
// bumping the Rust version updates versionName/versionCode automatically.
val cargoToml = rootDir.parentFile.resolve("anywhere/Cargo.toml")
val cargoPackageSection = cargoToml.readText()
    .substringAfter("[package]")
    .substringBefore("\n[")
val anywhereVersion = Regex("""(?m)^\s*version\s*=\s*"([^"]+)"""")
    .find(cargoPackageSection)?.groupValues?.get(1)
    ?: error("Failed to parse package `version` from $cargoToml")

android {
    namespace = "com.anywhere.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.anywhere.android"
        minSdk = 29      // Android 10+ (VpnService.requireStrongKeystore etc.)
        targetSdk = 35
        // major*10000 + minor*100 + patch keeps versionCode monotonic across
        // semver bumps (pre-release suffixes like 1.2.0-rc.1 are truncated).
        val semver = anywhereVersion.substringBefore('-').split(".")
        versionCode = semver[0].toInt() * 10000 +
            semver.getOrElse(1) { "0" }.toInt() * 100 +
            semver.getOrElse(2) { "0" }.toInt()
        versionName = anywhereVersion
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Sign with debug key for personal use (not Play Store)
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    // Pack the Rust .so into the APK
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    // Compose BOM
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")
    implementation("androidx.activity:activity-compose:1.9.0")

    // Compose UI
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // Lifecycle
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.2")
    implementation("androidx.lifecycle:lifecycle-service:2.8.2")
}
