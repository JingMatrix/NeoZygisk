import java.nio.file.Paths
import org.gradle.internal.os.OperatingSystem

plugins {
    alias(libs.plugins.agp.lib)
}

val verCode: Int by rootProject.extra
val verName: String by rootProject.extra
val commitHash: String by rootProject.extra
val workDirectory: String by rootProject.extra

fun Project.findInPath(executable: String, property: String): String? {
    val pathEnv = System.getenv("PATH")
    return pathEnv.split(File.pathSeparator).map { folder ->
        Paths.get("${folder}${File.separator}${executable}${if (OperatingSystem.current().isWindows) ".exe" else ""}")
            .toFile()
    }.firstOrNull { path ->
        path.exists()
    }?.absolutePath ?: properties.getOrDefault(property, null) as? String?
}

val ccachePath by lazy {
    project.findInPath("ccache", "ccache.path")?.also {
        println("loader: Use ccache: $it")
    }
}

val defaultCFlags = arrayOf(
    "-Wall", "-Wextra",
    "-fno-rtti", "-fno-exceptions",
    "-fno-stack-protector", "-fomit-frame-pointer",
    "-Wno-builtin-macro-redefined", "-D__FILE__=__FILE_NAME__",
    "-DWORK_DIRECTORY=\"${workDirectory}\""
)

val releaseFlags = arrayOf(
    "-Oz", "-flto",
    "-Wno-unused", "-Wno-unused-parameter",
    "-fvisibility=hidden", "-fvisibility-inlines-hidden",
    "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
    "-ffunction-sections", "-fdata-sections",
    "-Wl,--exclude-libs,ALL", "-Wl,--gc-sections", "-Wl,--icf=all", "-Wl,--strip-all", "-Wl,--pack-dyn-relocs=android"
)

android {
    buildFeatures {
        androidResources = false
        buildConfig = false
        prefab = true
    }

    externalNativeBuild.cmake {
        path("src/CMakeLists.txt")
        version = "4.1.2"
        buildStagingDirectory = layout.buildDirectory.get().asFile
    }

    defaultConfig {
        ndk.abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "riscv64")
        externalNativeBuild.cmake {
            cFlags("-std=c18", *defaultCFlags)
            cppFlags("-std=c++20", *defaultCFlags)
            ccachePath?.let {
                arguments += "-DNDK_CCACHE=$it"
            }
        }
    }

    buildTypes {
        debug {
            externalNativeBuild.cmake {
                arguments += "-DZKSU_VERSION=$verName-$verCode-$commitHash-debug"
            }
        }
        release {
            externalNativeBuild.cmake {
                cFlags += releaseFlags
                cppFlags += releaseFlags
                arguments += "-DZKSU_VERSION=$verName-$verCode-$commitHash-release"
            }
        }
    }
}
