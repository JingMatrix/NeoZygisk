import com.android.build.api.variant.LibraryVariant
import org.apache.tools.ant.filters.FixCrLfFilter
import org.apache.tools.ant.filters.ReplaceTokens
import org.apache.commons.codec.binary.Hex
import java.security.MessageDigest
import org.gradle.process.ExecOperations
import javax.inject.Inject

plugins {
    alias(libs.plugins.agp.lib)
}

// region Extra Properties
val moduleId: String by rootProject.extra
val moduleName: String by rootProject.extra
val verCode: Int by rootProject.extra
val verName: String by rootProject.extra
val minAPatchVersion: Int by rootProject.extra
val minKsuVersion: Int by rootProject.extra
val minKsudVersion: Int by rootProject.extra
val maxKsuVersion: Int by rootProject.extra
val minMagiskVersion: Int by rootProject.extra
val workDirectory: String by rootProject.extra
val commitHash: String by rootProject.extra
val updateJson: String by rootProject.extra
// endregion

android {
    androidResources.enable = false
    buildFeatures.buildConfig = false
}

interface ExecOperationsService {
    @get:Inject
    val execOperations: ExecOperations
}

fun Project.registerShellInstallTask(
    variant: LibraryVariant,
    toolName: String,
    pushTaskProvider: TaskProvider<Exec>,
    zipFileNameProvider: Provider<String>,
    installCommand: String
): TaskProvider<Task> {
    val variantCapped = variant.name.replaceFirstChar { it.titlecase() }
    return tasks.register("install${toolName}${variantCapped}") {
        group = "module"
        description = "Pushes the module zip and installs it using $toolName."
        dependsOn(pushTaskProvider)
        val serviceHolder = project.objects.newInstance<ExecOperationsService>()
        doLast {
            val execOps = serviceHolder.execOperations
            val zipFileName = zipFileNameProvider.get()
            execOps.exec {
                commandLine(
                    "adb", "shell", "echo",
                    "'$installCommand /data/local/tmp/$zipFileName'",
                    "> /data/local/tmp/install.sh"
                )
            }
            execOps.exec {
                commandLine("adb", "shell", "chmod", "755", "/data/local/tmp/install.sh")
            }
            execOps.exec {
                commandLine("adb", "shell", "su", "-c", "/data/local/tmp/install.sh")
            }
        }
    }
}

fun Project.registerRebootTask(
    variant: LibraryVariant,
    toolName: String,
    installTaskProvider: TaskProvider<out Task>
): TaskProvider<Exec> {
    val variantCapped = variant.name.replaceFirstChar { it.titlecase() }
    return tasks.register<Exec>("install${toolName}AndReboot${variantCapped}") {
        group = "module"
        description = "Installs the module using $toolName and reboots the device."
        dependsOn(installTaskProvider)
        commandLine("adb", "reboot")
    }
}

androidComponents.onVariants { variant ->
    val variantCapped = variant.name.replaceFirstChar { it.titlecase() }
    val variantLowered = variant.name.lowercase()
    val buildTypeLowered = variant.buildType?.lowercase() ?: ""

    val moduleDir = layout.buildDirectory.dir("outputs/module/$variantLowered")
    val zipFileNameProvider = provider { "$moduleName-$verName-$verCode-$commitHash-$buildTypeLowered.zip".replace(' ', '-') }

    val prepareModuleFilesTask = tasks.register<Sync>("prepareModuleFiles$variantCapped") {
        group = "module"
        dependsOn(":loader:assemble$variantCapped", ":zygiskd:buildAndStrip")
        into(moduleDir)
        from(rootProject.projectDir.resolve("README.md"))
        from(projectDir.resolve("src")) {
            exclude("module.prop", "action.sh", "customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh", "zygisk-ctl.sh")
            filter<FixCrLfFilter>(mapOf("eol" to FixCrLfFilter.CrLf.newInstance("lf")))
        }
        from(projectDir.resolve("src")) {
            include("module.prop")
            expand(
                "moduleId" to moduleId,
                "moduleName" to moduleName,
                "versionName" to "$verName ($verCode-$commitHash-$variantLowered)",
                "versionCode" to verCode.toString(),
                "updateJson" to updateJson
            )
        }
        from(projectDir.resolve("src")) {
            include("action.sh", "customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh", "zygisk-ctl.sh")
            val tokens = mapOf(
                "DEBUG" to (buildTypeLowered == "debug").toString(),
                "MIN_APATCH_VERSION" to minAPatchVersion.toString(),
                "MIN_KSU_VERSION" to minKsuVersion.toString(),
                "MIN_KSUD_VERSION" to minKsudVersion.toString(),
                "MAX_KSU_VERSION" to maxKsuVersion.toString(),
                "MIN_MAGISK_VERSION" to minMagiskVersion.toString(),
                "WORK_DIRECTORY" to workDirectory
            )
            filter<ReplaceTokens>(mapOf("tokens" to tokens))
            filter<FixCrLfFilter>(mapOf("eol" to FixCrLfFilter.CrLf.newInstance("lf")))
        }
        into("bin") {
            from(project(":zygiskd").layout.buildDirectory.dir("rustJniLibs/android")) {
                include("**/zygiskd")
            }
        }
        into("lib") { from(project(":loader").layout.buildDirectory.file("intermediates/stripped_native_libs/$variantLowered/strip${variantCapped}DebugSymbols/out/lib")) }

        doLast {
            fileTree(moduleDir).visit {
                if (isDirectory) return@visit
                val md = MessageDigest.getInstance("SHA-256")
                file.forEachBlock(4096) { bytes, size ->
                    md.update(bytes, 0, size)
                }
                // Use project.file() for robust path resolution.
                project.file(file.path + ".sha256").writeText(Hex.encodeHexString(md.digest()))
            }
        }
    }

    val zipTask = tasks.register<Zip>("zip$variantCapped") {
        group = "module"
        dependsOn(prepareModuleFilesTask)
        archiveFileName.set(zipFileNameProvider)
        destinationDirectory.set(layout.buildDirectory.dir("outputs/release"))
        from(moduleDir)
    }

    val pushTask = tasks.register<Exec>("push$variantCapped") {
        group = "module"
        dependsOn(zipTask)
        doFirst {
            commandLine(
                "adb",
                "push",
                zipTask.get().archiveFile.get().asFile.absolutePath,
                "/data/local/tmp"
            )
        }
    }

    val installAPatchTask = registerShellInstallTask(variant, "APatch", pushTask, zipFileNameProvider, "/data/adb/apd module install")
    val installKsuTask = registerShellInstallTask(variant, "Ksu", pushTask, zipFileNameProvider, "/data/adb/ksud module install")

    val installMagiskTask = tasks.register<Exec>("installMagisk$variantCapped") {
        group = "module"
        dependsOn(pushTask)
        doFirst {
            val zipFileName = zipFileNameProvider.get()
            val installCommand = "su -c 'magisk --install-module /data/local/tmp/$zipFileName'"
            commandLine("adb", "shell", installCommand)
        }
    }

    registerRebootTask(variant, "APatch", installAPatchTask)
    registerRebootTask(variant, "Ksu", installKsuTask)
    registerRebootTask(variant, "Magisk", installMagiskTask)
}
