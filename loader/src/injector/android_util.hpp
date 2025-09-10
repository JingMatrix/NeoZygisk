#pragma once

#include <jni.h>

#include <string_view>
#include <type_traits>
#include <utility>

#include "logging.hpp"

/**
 * @file android_util.hpp
 * @brief A modern C++ JNI helper library for Android.
 *
 * This header provides a collection of utilities designed to make working with the JNI
 * safer, more convenient, and less error-prone. It leverages modern C++ features like
 * RAII, concepts, and templates to abstract away common boilerplate and pitfalls.
 *
 * Key Features:
 * 1.  **RAII for JNI Resources (`ScopedLocalRef`, `JUTFString`):** Automatically manages
 *     the lifecycle of JNI local references and UTF strings, preventing common resource leaks.
 * 2.  **Type Safety (`JObject` Concept):** Uses C++20 concepts to ensure that JNI
 *     functions are called with the correct types, providing clear compile-time errors.
 * 3.  **Centralized Exception Handling (`SafeInvoke`):** A wrapper that automatically
 *     checks for, describes, and clears pending JNI exceptions after every call.
 * 4.  **Expanded Set of Common Wrappers:** Provides safe, convenient wrappers for the most
 *     frequently used JNI functions.
 * 5.  **ART Introspection (`art::ArtMethod`):** A specialized utility for interacting
 *     with the internal structures of the Android Runtime.
 */
namespace util {
namespace jni {

// --- CONCEPTS (PART 1 - NO DEPENDENCIES) ---
/**
 * @brief A C++20 concept that checks if a type `T` is a JNI object type.
 * @details This is the cornerstone of the library's type safety. It works by checking
 *          if a given type can be safely converted to `jobject`. All true object types
 *          (jclass, jstring, jobjectArray, etc.) satisfy this, while opaque identifier
 *          types (jfieldID, jmethodID) do not. This prevents accidentally trying to
 *          treat an ID as a garbage-collected object.
 */
template <typename T>
concept JObject = std::is_convertible_v<std::decay_t<T>, jobject>;

// --- RAII WRAPPERS ---
/**
 * @brief A RAII wrapper for a JNI local reference.
 *
 * @details This class is a "smart pointer" for JNI local references. It takes ownership
 *          of a reference (like a jclass or jstring) and guarantees that `DeleteLocalRef`
 *          is called when the `ScopedLocalRef` object goes out of scope. This completely
 *          eliminates a major class of JNI bugs related to leaking references.
 *
 *          VISUAL EXPLANATION (RAII Pattern):
 *          +--------------------------------------------------------------------------+
 *          | void myFunction(JNIEnv* env) {                                           |
 *          |   // Scope begins                                                        |
 *          |   ScopedLocalRef<jclass> clazz(env, env->FindClass(...)); // ACQUISITION |
 *          |                                                                          |
 *          |   // ... code uses clazz ...                                             |
 *          |                                                                          |
 *          | } // Scope ends, `clazz` is destroyed, its destructor runs => RELEASE    |
 *          +--------------------------------------------------------------------------+
 *
 * @tparam T A JNI type that satisfies the `JObject` concept.
 */
template <JObject T>
class ScopedLocalRef {
public:
    using BaseType = T;

    /// @brief Constructs a null reference wrapper.
    explicit ScopedLocalRef(JNIEnv* env) noexcept : env_(env), ref_(nullptr) {}

    /// @brief Constructs a wrapper that takes ownership of an existing local reference.
    ScopedLocalRef(JNIEnv* env, T local_ref) : env_(env), ref_(local_ref) {}

    /// @brief Move constructor. Transfers ownership from another `ScopedLocalRef`.
    ScopedLocalRef(ScopedLocalRef&& other) noexcept : env_(other.env_), ref_(other.release()) {}

    /// @brief Move constructor for converting between compatible `ScopedLocalRef` types.
    template <JObject U>
    ScopedLocalRef(ScopedLocalRef<U>&& other) noexcept
        : env_(other.env_), ref_(static_cast<T>(other.release())) {}

    /// @brief Destructor. Automatically releases the managed JNI reference.
    ~ScopedLocalRef() { reset(); }

    /// @brief Move assignment operator.
    ScopedLocalRef& operator=(ScopedLocalRef&& other) noexcept {
        if (this != &other) {
            reset(other.release());
            env_ = other.env_;
        }
        return *this;
    }

    // Copying is deleted to enforce unique ownership and prevent double-frees.
    ScopedLocalRef(const ScopedLocalRef&) = delete;
    ScopedLocalRef& operator=(const ScopedLocalRef&) = delete;

    /// @brief Replaces the managed reference with a new one, deleting the old one.
    void reset(T ptr = nullptr) {
        if (ref_ != ptr) {
            if (ref_ != nullptr) {
                env_->DeleteLocalRef(ref_);
            }
            ref_ = ptr;
        }
    }

    /// @brief Releases ownership of the reference and returns it. The caller is now responsible for
    /// it.
    [[nodiscard]] T release() {
        T temp = ref_;
        ref_ = nullptr;
        return temp;
    }

    /// @brief Returns the raw JNI reference without releasing ownership.
    T get() const { return ref_; }

    /// @brief Implicitly converts to the raw JNI reference type.
    operator T() const { return ref_; }

    /// @brief Checks if the managed reference is not null.
    operator bool() const { return ref_ != nullptr; }

private:
    template <JObject U>
    friend class ScopedLocalRef;

    JNIEnv* env_;
    T ref_;
};

/**
 * @brief A RAII wrapper for a JNI UTF string obtained via `GetStringUTFChars`.
 * @details Manages the lifecycle of a `const char*` representation of a Java string,
 *          ensuring `ReleaseStringUTFChars` is always called. This prevents memory leaks
 *          when working with strings passed from Java.
 */
class JUTFString {
public:
    JUTFString(JNIEnv* env, jstring jstr) : env_(env), jstr_(jstr), cstr_(nullptr) {
        if (env_ && jstr_) {
            cstr_ = env_->GetStringUTFChars(jstr_, nullptr);
        }
    }

    ~JUTFString() {
        if (env_ && jstr_ && cstr_) {
            env_->ReleaseStringUTFChars(jstr_, cstr_);
        }
    }

    // Prohibit copying and moving to keep ownership simple and safe.
    JUTFString(const JUTFString&) = delete;
    JUTFString& operator=(const JUTFString&) = delete;
    JUTFString(JUTFString&&) = delete;
    JUTFString& operator=(JUTFString&&) = delete;

    /// @brief Returns the raw `const char*` C-style string.
    const char* get() const { return cstr_; }
    /// @brief Implicitly converts to a `const char*`.
    operator const char*() const { return cstr_; }
    /// @brief Checks if the string was successfully retrieved (is not null).
    operator bool() const { return cstr_ != nullptr; }

private:
    JNIEnv* env_;
    jstring jstr_;
    const char* cstr_;
};

// --- CONCEPTS (PART 2 - DEPENDENT ON ScopedLocalRef) ---
/**
 * @brief A concept that checks if a type `T` is a specialization of `ScopedLocalRef`.
 *
 * @details of "template metaprogramming."
 *
 *          1. **The Default Rule (`is_scoped_local_ref_helper<T>`):** We first define a generic
 *             "helper" template that, by default, inherits from `std::false_type`.
 *
 *          2. **The Special Rule (template specialization):** We then provide a "specialization"
 *             of this helper: `is_scoped_local_ref_helper<ScopedLocalRef<T>>`.
 *
 *          3. **The Final Concept (`IsScopedLocalRef`):** The concept is the clean, readable
 *             interface to this logic. It checks the `::value` of our helper for any given type
 *             `T`.
 *
 *          This allows our code to intelligently change its behavior based on whether it's dealing
 *          with a raw JNI pointer or one of our safe `ScopedLocalRef` wrappers.
 */
template <typename T>
struct is_scoped_local_ref_helper : std::false_type {};
template <JObject T>
struct is_scoped_local_ref_helper<ScopedLocalRef<T>> : std::true_type {};
template <typename T>
concept IsScopedLocalRef = is_scoped_local_ref_helper<std::decay_t<T>>::value;

/// @brief A concept that allows a function parameter to be either a raw JNI pointer or a
/// `ScopedLocalRef`.
template <typename T, typename U>
concept ScopeOrRaw =
    std::is_convertible_v<T, U> ||
    (IsScopedLocalRef<T> && std::is_convertible_v<typename std::decay_t<T>::BaseType, U>);

/// @brief A convenience concept for `jclass` or a `ScopedLocalRef<jclass>`.
template <typename T>
concept ScopeOrClass = ScopeOrRaw<T, jclass>;

/// @brief A convenience concept for `jobject` or a `ScopedLocalRef<jobject>`.
template <typename T>
concept ScopeOrObject = ScopeOrRaw<T, jobject>;

//--- Automatic Exception Handling and Safe JNI Invocation ---
// Internal helper to get the raw pointer from a value, which might be a ScopedLocalRef.
template <typename T>
inline auto UnwrapScope(T&& x) {
    if constexpr (IsScopedLocalRef<T>) {
        return x.get();
    } else {
        return std::forward<T>(x);
    }
}

// Internal helper to wrap a raw jobject pointer in a ScopedLocalRef.
template <typename T>
inline auto WrapScope(JNIEnv* env, T&& x) {
    using DecayedT = std::decay_t<T>;
    if constexpr (JObject<DecayedT>) {
        return ScopedLocalRef<DecayedT>(env, std::forward<T>(x));
    } else {
        return std::forward<T>(x);
    }
}

/**
 * @brief The core invocation wrapper that makes all JNI calls safe.
 *
 * @details This template function is the heart of the library's safety mechanism.
 *          It wraps a call to a JNI function, providing automatic exception handling
 *          and resource management for the return value.
 *
 *          VISUAL EXPLANATION (Safety Net Pattern):
 *          +-----------+      +-----------------+      +---------------------------+
 *          | Your Code | ---> |   SafeInvoke    | ---> |  RAII ExceptionChecker    |
 *          +-----------+      | (takes JNI func |      | is created on the stack   |
 *                             |  and arguments) |      +---------------------------+
 *                             +-----------------+                  |
 *                                     |                            | makes the actual
 *                                     V                            V
 *                             +-----------------+      +---------------------------+
 *                             | Returns a safe  | <--- | (e.g., env->FindClass)    |
 *                             | value (wrapped  |      | JNI call is performed     |
 *                             | in ScopedLocal- |      +---------------------------+
 *                             | Ref or null/0)  |                    |
 *                             +-----------------+                    |
 *                                                                    V
 *                                                      +---------------------------+
 *                                                      | ExceptionChecker is       |
 *                                                      | destroyed (destructor     |
 *                                                      | checks/clears exception)  |
 *                                                      +---------------------------+
 *
 * @tparam Func The type of the JNI member function pointer (e.g., `jclass(const char*)`).
 * @tparam Args The types of the arguments to the JNI function.
 * @return The result of the JNI call, automatically wrapped in a `ScopedLocalRef` if it's
 *         an object, or a safe zero/null value if an exception occurred.
 */
template <typename Func, typename... Args>
    requires(std::is_function_v<Func>)
[[maybe_unused]] inline auto SafeInvoke(JNIEnv* env, Func JNIEnv::* f, Args&&... args) {
    // This RAII object's destructor guarantees the exception check happens.
    struct ExceptionChecker {
        JNIEnv* env;
        ~ExceptionChecker() {
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
        }
    } checker{env};

    using ReturnType = decltype((env->*f)(UnwrapScope(std::forward<Args>(args))...));

    if constexpr (!std::is_same_v<void, ReturnType>) {
        ReturnType result = (env->*f)(UnwrapScope(std::forward<Args>(args))...);
        using WrappedType = decltype(WrapScope(env, result));
        if (env->ExceptionCheck()) {
            if constexpr (IsScopedLocalRef<WrappedType>) {
                return WrappedType(env);  // Return a default-constructed (null) ScopedLocalRef
            } else {
                return ReturnType{};  // Return 0, nullptr, or false for primitive types
            }
        }
        return WrapScope(env, result);
    } else {
        (env->*f)(UnwrapScope(std::forward<Args>(args))...);
    }
}

//--- Expanded Set of Safe JNI Wrapper Functions ---
// These functions provide a clean, safe interface to the most common JNI operations.

// Class Operations
[[maybe_unused]] inline auto FindClass(JNIEnv* env, const char* name) {
    return SafeInvoke(env, &JNIEnv::FindClass, name);
}

// Field Operations
template <ScopeOrClass Class>
[[maybe_unused]] inline auto GetFieldID(JNIEnv* env, Class&& clazz, const char* name,
                                        const char* sig) {
    return SafeInvoke(env, &JNIEnv::GetFieldID, std::forward<Class>(clazz), name, sig);
}

template <ScopeOrClass Class>
[[maybe_unused]] inline auto GetStaticFieldID(JNIEnv* env, Class&& clazz, const char* name,
                                              const char* sig) {
    return SafeInvoke(env, &JNIEnv::GetStaticFieldID, std::forward<Class>(clazz), name, sig);
}

template <ScopeOrObject Object>
[[maybe_unused]] inline auto GetObjectField(JNIEnv* env, Object&& obj, jfieldID fieldId) {
    return SafeInvoke(env, &JNIEnv::GetObjectField, std::forward<Object>(obj), fieldId);
}

template <ScopeOrObject Object, ScopeOrObject Value>
[[maybe_unused]] inline void SetObjectField(JNIEnv* env, Object&& obj, jfieldID fieldId,
                                            Value&& value) {
    SafeInvoke(env, &JNIEnv::SetObjectField, std::forward<Object>(obj), fieldId,
               std::forward<Value>(value));
}

template <ScopeOrClass Class>
[[maybe_unused]] inline auto GetStaticIntField(JNIEnv* env, Class&& clazz, jfieldID fieldId) {
    return SafeInvoke(env, &JNIEnv::GetStaticIntField, std::forward<Class>(clazz), fieldId);
}

// Method Operations
template <ScopeOrClass Class>
[[maybe_unused]] inline auto GetMethodID(JNIEnv* env, Class&& clazz, const char* name,
                                         const char* sig) {
    return SafeInvoke(env, &JNIEnv::GetMethodID, std::forward<Class>(clazz), name, sig);
}

template <ScopeOrClass Class>
[[maybe_unused]] inline auto ToReflectedMethod(JNIEnv* env, Class&& clazz, jmethodID method,
                                               jboolean isStatic) {
    return SafeInvoke(env, &JNIEnv::ToReflectedMethod, std::forward<Class>(clazz), method,
                      isStatic);
}

template <ScopeOrObject Object, typename... Args>
[[maybe_unused]] inline void CallVoidMethod(JNIEnv* env, Object&& obj, jmethodID method,
                                            Args&&... args) {
    SafeInvoke(env, &JNIEnv::CallVoidMethod, std::forward<Object>(obj), method,
               std::forward<Args>(args)...);
}

template <ScopeOrObject Object, typename... Args>
[[maybe_unused]] inline auto CallObjectMethod(JNIEnv* env, Object&& obj, jmethodID method,
                                              Args&&... args) {
    return SafeInvoke(env, &JNIEnv::CallObjectMethod, std::forward<Object>(obj), method,
                      std::forward<Args>(args)...);
}

template <ScopeOrObject Object, typename... Args>
[[maybe_unused]] inline auto CallBooleanMethod(JNIEnv* env, Object&& obj, jmethodID method,
                                               Args&&... args) {
    return SafeInvoke(env, &JNIEnv::CallBooleanMethod, std::forward<Object>(obj), method,
                      std::forward<Args>(args)...);
}

template <ScopeOrObject Object, typename... Args>
[[maybe_unused]] inline auto CallIntMethod(JNIEnv* env, Object&& obj, jmethodID method,
                                           Args&&... args) {
    return SafeInvoke(env, &JNIEnv::CallIntMethod, std::forward<Object>(obj), method,
                      std::forward<Args>(args)...);
}

template <ScopeOrObject Object>
[[maybe_unused]] inline auto GetLongField(JNIEnv* env, Object&& obj, jfieldID fieldId) {
    return SafeInvoke(env, &JNIEnv::GetLongField, std::forward<Object>(obj), fieldId);
}

// Object & String Creation
template <ScopeOrClass Class, typename... Args>
[[maybe_unused]] inline auto NewObject(JNIEnv* env, Class&& clazz, jmethodID method,
                                       Args&&... args) {
    return SafeInvoke(env, &JNIEnv::NewObject, std::forward<Class>(clazz), method,
                      std::forward<Args>(args)...);
}

[[maybe_unused]] inline auto NewStringUTF(JNIEnv* env, const char* str) {
    return SafeInvoke(env, &JNIEnv::NewStringUTF, str);
}

/// @brief A safe way to cast between different `ScopedLocalRef` types (e.g., from `jobject` to
/// `jclass`).
template <JObject U, JObject T>
[[maybe_unused]] inline auto Cast(ScopedLocalRef<T>&& x) {
    return ScopedLocalRef<U>(std::move(x));
}

}  // namespace jni

namespace art {

/**
 * @brief A helper class for introspecting the internal ART 'ArtMethod' C++ struct.
 * @warning This utility is highly dependent on the internal implementation of the Android
 *          Runtime. It is not a public, stable API and is likely to break on future
 *          Android versions or on devices with unusual ART implementations. Use with caution.
 */
class ArtMethod {
public:
    /// @brief Gets the native data pointer from an ArtMethod, often pointing to the compiled code.
    void* GetData() {
        return *reinterpret_cast<void**>(reinterpret_cast<uintptr_t>(this) + data_offset);
    }

    /// @brief Gets a native pointer to an ArtMethod from a reflected Java method object.
    static ArtMethod* FromReflectedMethod(JNIEnv* env, jobject method) {
        if (!art_method_field_id_) return nullptr;
        jlong art_method_ptr = jni::GetLongField(env, method, art_method_field_id_);
        return reinterpret_cast<ArtMethod*>(art_method_ptr);
    }

    /**
     * @brief Initializes the helper by discovering the layout of the ArtMethod struct at runtime.
     * @details This function performs a clever trick to determine the size of the opaque
     *          ArtMethod struct. It fetches two consecutive methods from a known class
     *          (Throwable) and calculates the difference in their memory addresses.
     *
     *          VISUAL EXPLANATION (Memory Layout Calculation):
     *
     *          Memory Address
     *          Low  -> +----------------------------+
     *                  | ArtMethod for constructor 1|
     *                  | (size is unknown)          | <-- first_ctor_ptr
     *                  +----------------------------+
     *                  | ArtMethod for constructor 2|
     *                  | (immediately after)        | <-- second_ctor_ptr
     *                  +----------------------------+
     *          High -> | ...                        |
     *
     *          The calculation `second_ctor_ptr - first_ctor_ptr` reveals the size of one
     *          ArtMethod instance, allowing us to find field offsets from its end.
     *
     * @return True on success, false on failure.
     */
    static bool Init(JNIEnv* env) {
        if (art_method_field_id_) return true;  // Already initialized

        auto executable_class = jni::FindClass(env, "java/lang/reflect/Executable");
        if (!executable_class) {
            LOGE("could not find java.lang.reflect.Executable");
            return false;
        }

        art_method_field_id_ = jni::GetFieldID(env, executable_class, "artMethod", "J");
        if (!art_method_field_id_) {
            LOGE("failed to find field 'artMethod' in Executable class");
            return false;
        }

        auto throwable_class = jni::FindClass(env, "java/lang/Throwable");
        if (!throwable_class) {
            LOGE("could not find java.lang.Throwable");
            return false;
        }
        auto class_class = jni::FindClass(env, "java/lang/Class");
        jmethodID get_constructors_method = jni::GetMethodID(
            env, class_class, "getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;");
        auto constructors_array = jni::Cast<jobjectArray>(
            jni::CallObjectMethod(env, throwable_class, get_constructors_method));

        if (!constructors_array || env->GetArrayLength(constructors_array.get()) < 2) {
            LOGE("throwable has less than 2 constructors, cannot determine ArtMethod size.");
            return false;
        }

        auto first_ctor = jni::ScopedLocalRef<jobject>(
            env, env->GetObjectArrayElement(constructors_array.get(), 0));
        auto second_ctor = jni::ScopedLocalRef<jobject>(
            env, env->GetObjectArrayElement(constructors_array.get(), 1));

        auto* first = FromReflectedMethod(env, first_ctor.get());
        auto* second = FromReflectedMethod(env, second_ctor.get());

        if (!first || !second) {
            LOGE("failed to get ArtMethod pointers from constructors.");
            return false;
        }

        art_method_size = reinterpret_cast<uintptr_t>(second) - reinterpret_cast<uintptr_t>(first);
        constexpr auto kPointerSize = sizeof(void*);
        entry_point_offset = art_method_size - kPointerSize;
        data_offset = entry_point_offset - kPointerSize;

        LOGV("ArtMethod size: %zu, data offset: %zu", art_method_size, data_offset);
        return true;
    }

private:
    inline static jfieldID art_method_field_id_ = nullptr;
    inline static size_t art_method_size = 0;
    inline static size_t entry_point_offset = 0;
    inline static size_t data_offset = 0;
};

}  // namespace art
}  // namespace util
