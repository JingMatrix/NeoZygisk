plugins {
    alias(libs.plugins.agp.lib)
}

val minAPatchVersion: Int by rootProject.extra
val minKsuVersion: Int by rootProject.extra
val maxKsuVersion: Int by rootProject.extra
val minMagiskVersion: Int by rootProject.extra
val verCode: Int by rootProject.extra
val verName: String by rootProject.extra
val commitHash: String by rootProject.extra
val androidMinSdkVersion: Int by rootProject.extra

android {
    buildFeatures {
        buildConfig = false
    }
    androidResources.enable = false
}

// AGP 9 removed `android.ndkDirectory`; resolve the NDK lazily through the provider.
val ndkDirProvider = androidComponents.sdkComponents.ndkDirectory

// Android ABI -> Rust target triple. cargo-ndk accepts the ABI names directly for `-t`;
// the triple is only needed to locate the compiled binary inside the target directory.
val abiToTriple = linkedMapOf(
    "arm64-v8a" to "aarch64-linux-android",
    "armeabi-v7a" to "armv7-linux-androideabi",
    "x86" to "i686-linux-android",
    "x86_64" to "x86_64-linux-android",
)

listOf("Debug", "Release").forEach { variantCap ->
    val profileName = variantCap.lowercase()
    val isRelease = profileName == "release"

    tasks.register("buildAndStrip$variantCap") {
        group = "rust"
        doLast {
            val ndkFile = ndkDirProvider.get().asFile
            val prebuilt = File(ndkFile, "toolchains/llvm/prebuilt").listFiles()?.firstOrNull()
                ?: error("NDK LLVM toolchain not found under $ndkFile")
            val binDir = File(prebuilt, "bin")
            val exeExt = if (prebuilt.name.contains("windows")) ".exe" else ""
            val strip = File(binDir, "llvm-strip$exeExt")
            val objcopy = File(binDir, "llvm-objcopy$exeExt")

            // Keep Cargo's output inside the module build directory for a clean workspace.
            val targetDir = layout.buildDirectory.dir("rust/target").get().asFile
            val outJniDir = layout.buildDirectory.dir("intermediates/rust/$profileName/jniLibs").get().asFile
            val symbolDir = layout.buildDirectory.dir("symbols/$profileName").get().asFile

            // cargo-ndk wires the correct NDK linker/ar per ABI; one invocation builds every ABI.
            // Use the long `--platform` flag: it is stable across cargo-ndk 3.x and 4.x,
            // unlike the short flag which was renamed from `-p` to `-P` in 4.0.3.
            val cargoArgs = mutableListOf("cargo", "ndk", "--platform", androidMinSdkVersion.toString())
            abiToTriple.keys.forEach { abi -> cargoArgs += listOf("-t", abi) }
            cargoArgs += listOf("build", "--target-dir", targetDir.absolutePath)
            if (isRelease) cargoArgs += "--release"

            providers.exec {
                workingDir = projectDir
                environment("ANDROID_NDK_HOME", ndkFile.absolutePath)
                environment("MIN_APATCH_VERSION", minAPatchVersion.toString())
                environment("MIN_KSU_VERSION", minKsuVersion.toString())
                environment("MAX_KSU_VERSION", maxKsuVersion.toString())
                environment("MIN_MAGISK_VERSION", minMagiskVersion.toString())
                environment("ZKSU_VERSION", "$verName-$verCode-$commitHash-$profileName")
                commandLine(cargoArgs)
            }.result.get().assertNormalExitValue()

            // Strip each binary, keeping a detached debug-symbol file linked back via gnu-debuglink.
            abiToTriple.forEach { (abi, triple) ->
                val built = File(targetDir, "$triple/$profileName/zygiskd")
                if (!built.exists()) error("zygiskd binary not found for $abi at $built")

                val abiDir = File(outJniDir, abi).apply { mkdirs() }
                built.copyTo(File(abiDir, "zygiskd"), overwrite = true)

                val symbolPath = File(symbolDir, "$abi/zygiskd.debug")
                symbolPath.parentFile.mkdirs()
                providers.exec { workingDir = abiDir; commandLine(objcopy.absolutePath, "--only-keep-debug", "zygiskd", symbolPath.absolutePath) }.result.get().assertNormalExitValue()
                providers.exec { workingDir = abiDir; commandLine(strip.absolutePath, "--strip-all", "zygiskd") }.result.get().assertNormalExitValue()
                providers.exec { workingDir = abiDir; commandLine(objcopy.absolutePath, "--add-gnu-debuglink", symbolPath.absolutePath, "zygiskd") }.result.get().assertNormalExitValue()
            }
        }
    }
}
