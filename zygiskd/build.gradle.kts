import org.gradle.process.ExecOperations
import javax.inject.Inject

plugins {
    alias(libs.plugins.agp.lib)
    alias(libs.plugins.rust.android)
}

val minAPatchVersion: Int by rootProject.extra
val minKsuVersion: Int by rootProject.extra
val maxKsuVersion: Int by rootProject.extra
val minMagiskVersion: Int by rootProject.extra
val verCode: Int by rootProject.extra
val verName: String by rootProject.extra
val commitHash: String by rootProject.extra

android {
    androidResources.enable = false
    buildFeatures.buildConfig = false
}

cargo {
    module = "."
    libname = "zygiskd"
    targetIncludes = arrayOf("zygiskd")
    targets = listOf("arm64", "arm", "x86", "x86_64")
    targetDirectory = "build/intermediates/rust"
    val isDebug = gradle.startParameter.taskNames.any { it.lowercase().contains("debug") }
    profile = if (isDebug) "debug" else "release"
    exec = { spec, _ ->
        spec.environment("ANDROID_NDK_HOME", android.ndkDirectory.path)
        spec.environment("MIN_APATCH_VERSION", minAPatchVersion)
        spec.environment("MIN_KSU_VERSION", minKsuVersion)
        spec.environment("MAX_KSU_VERSION", maxKsuVersion)
        spec.environment("MIN_MAGISK_VERSION", minMagiskVersion)
        spec.environment("ZKSU_VERSION", "$verName-$verCode-$commitHash-$profile")
    }
}

// An interface to safely inject the ExecOperations service for use in doLast {}.
interface ExecOperationsService {
    @get:Inject
    val execOperations: ExecOperations
}

tasks.register("buildAndStrip") {
    dependsOn(":zygiskd:cargoBuild")

    // Create a holder for the exec service during the configuration phase.
    val serviceHolder = project.objects.newInstance<ExecOperationsService>()

    doLast {
        val isDebug = gradle.startParameter.taskNames.any { it.lowercase().contains("debug") }

        val buildDir = layout.buildDirectory.get().asFile
        val dir = buildDir.resolve("rustJniLibs/android")
        val prebuilt = android.ndkDirectory.resolve("toolchains/llvm/prebuilt").listFiles()!!.first()
        val binDir = prebuilt.resolve("bin")
        val symbolDir = buildDir.resolve("symbols/${if (isDebug) "debug" else "release"}")
        symbolDir.mkdirs()
        val isWindows = System.getProperty("os.name").lowercase().contains("win")
        val suffix = if (isWindows) ".exe" else ""
        val strip = binDir.resolve("llvm-strip$suffix")
        val objcopy = binDir.resolve("llvm-objcopy$suffix")

        // Get the exec service from the holder during the execution phase.
        val execOps = serviceHolder.execOperations

        dir.listFiles()!!.forEach {
            if (!it.isDirectory) return@forEach
            val symbolPath = symbolDir.resolve("${it.name}/zygiskd.debug")
            symbolPath.parentFile.mkdirs()
            execOps.exec {
                workingDir = it
                commandLine(objcopy, "--only-keep-debug", "zygiskd", symbolPath)
            }
            execOps.exec {
                workingDir = it
                commandLine(strip, "--strip-all", "zygiskd")
            }
            execOps.exec {
                workingDir = it
                commandLine(objcopy, "--add-gnu-debuglink", symbolPath, "zygiskd")
            }
        }
    }
}
