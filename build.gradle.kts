import com.android.build.gradle.LibraryExtension
import java.io.ByteArrayOutputStream
import javax.inject.Inject
import org.gradle.process.ExecOperations

plugins {
    alias(libs.plugins.agp.lib) apply false
}

// Helper class to get access to the ExecOperations service
abstract class GitExecutor @Inject constructor(private val execOperations: ExecOperations) {
    fun execute(command: String, currentWorkingDir: File): String {
        val byteOut = ByteArrayOutputStream()
        execOperations.exec {
            workingDir = currentWorkingDir
            commandLine = command.split("\\s".toRegex())
            standardOutput = byteOut
        }
        return String(byteOut.toByteArray()).trim()
    }
}

// Instantiate the helper class using Gradle's object factory
val gitExecutor = objects.newInstance(GitExecutor::class.java)

// Use the helper to execute the git commands
val gitCommitCount = gitExecutor.execute("git rev-list HEAD --count", rootDir).toInt()
val gitCommitHash = gitExecutor.execute("git rev-parse --verify --short HEAD", rootDir)

val moduleId by extra("zygisksu")
val moduleName by extra("NeoZygisk")
val verName by extra("v2.3")
val verCode by extra(gitCommitCount)
val commitHash by extra(gitCommitHash)
val minAPatchVersion by extra(10762)
val minKsuVersion by extra(10940)
val minKsudVersion by extra(11425)
val maxKsuVersion by extra(30000)
val minMagiskVersion by extra(26402)
val workDirectory by extra("/data/adb/neozygisk")
val updateJson by extra("https://raw.githubusercontent.com/JingMatrix/NeoZygisk/master/module/zygisk.json")

val androidMinSdkVersion by extra(26)
val androidTargetSdkVersion by extra(36)
val androidCompileSdkVersion by extra(36)
val androidBuildToolsVersion by extra("36.0.0")
// Don't update NDK unless after careful and detailed tests,
// as explained in https://github.com/JingMatrix/NeoZygisk/pull/36
val androidCompileNdkVersion by extra("27.2.12479018")
val androidSourceCompatibility by extra(JavaVersion.VERSION_21)
val androidTargetCompatibility by extra(JavaVersion.VERSION_21)

tasks.register("Delete", Delete::class) {
    delete(rootProject.layout.buildDirectory)
}

fun Project.configureBaseExtension() {
    extensions.findByType(LibraryExtension::class)?.run {
        namespace = "org.matrix.zygisk"
        compileSdk = androidCompileSdkVersion
        ndkVersion = androidCompileNdkVersion
        buildToolsVersion = androidBuildToolsVersion

        defaultConfig {
            minSdk = androidMinSdkVersion
        }

        lint {
            targetSdk = androidTargetSdkVersion
            abortOnError = true
        }
    }
}

subprojects {
    plugins.withId("com.android.library") {
        configureBaseExtension()
    }
}
