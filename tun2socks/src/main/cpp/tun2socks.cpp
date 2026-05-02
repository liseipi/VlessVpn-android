#include <jni.h>
#include <string>
#include <cstdlib>
#include <pthread.h>
#include <unistd.h>
#include <android/log.h>
#include <tun2socks/tun2socks.h>

// Start threads to redirect stdout and stderr to logcat.
int pipe_stdout[2];
int pipe_stderr[2];
pthread_t thread_stdout;
pthread_t thread_stderr;
const char *ADBTAG = "tun2socks";

// ★ 关键修复：管道和重定向线程只初始化一次，避免第二次 start 时
//   dup2() 隐式关闭已被 fdsan 追踪的 fd，导致 SIGABRT 崩溃。
static bool pipes_initialized = false;

void *thread_stderr_func(void *) {
    ssize_t redirect_size;
    char buf[2048];
    while ((redirect_size = read(pipe_stderr[0], buf, sizeof buf - 1)) > 0) {
        if (buf[redirect_size - 1] == '\n') {
            --redirect_size;
        }
        buf[redirect_size] = 0;
        __android_log_write(ANDROID_LOG_ERROR, ADBTAG, buf);
    }
    return nullptr;
}

void *thread_stdout_func(void *) {
    ssize_t redirect_size;
    char buf[2048];
    while ((redirect_size = read(pipe_stdout[0], buf, sizeof buf - 1)) > 0) {
        if (buf[redirect_size - 1] == '\n') {
            --redirect_size;
        }
        buf[redirect_size] = 0;
        __android_log_write(ANDROID_LOG_INFO, ADBTAG, buf);
    }
    return nullptr;
}

int start_redirecting_stdout_stderr() {
    // ★ 已经初始化过则直接返回，不再重建管道和线程。
    //   重复调用 dup2() 会让 fdsan 检测到对其追踪的 fd 的非法关闭，
    //   触发 Fatal signal 6 (SIGABRT) 导致 App 在第二次 connect 时崩溃。
    if (pipes_initialized) {
        return 0;
    }

    setvbuf(stdout, nullptr, _IONBF, 0);
    pipe(pipe_stdout);
    dup2(pipe_stdout[1], STDOUT_FILENO);
    close(pipe_stdout[1]); // write end 已被 dup2 接管，关闭原始 fd

    setvbuf(stderr, nullptr, _IONBF, 0);
    pipe(pipe_stderr);
    dup2(pipe_stderr[1], STDERR_FILENO);
    close(pipe_stderr[1]); // write end 已被 dup2 接管，关闭原始 fd

    if (pthread_create(&thread_stdout, nullptr, thread_stdout_func, nullptr) == -1) {
        return -1;
    }
    pthread_detach(thread_stdout);

    if (pthread_create(&thread_stderr, nullptr, thread_stderr_func, nullptr) == -1) {
        return -1;
    }
    pthread_detach(thread_stderr);

    pipes_initialized = true;
    return 0;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_musicses_vlessvpn_Tun2Socks_start_1tun2socks(JNIEnv *env, jclass clazz,
                                                      jobjectArray args) {
    jsize argument_count = env->GetArrayLength(args);

    // 动态分配 argv 数组
    char **argv = (char **) calloc(argument_count + 1, sizeof(char *));
    if (argv == nullptr) {
        __android_log_write(ANDROID_LOG_ERROR, ADBTAG, "Failed to allocate argv");
        return -1;
    }

    for (jsize i = 0; i < argument_count; i++) {
        jstring jstr = (jstring) env->GetObjectArrayElement(args, i);
        const char *cstr = env->GetStringUTFChars(jstr, nullptr);
        argv[i] = strdup(cstr);
        env->ReleaseStringUTFChars(jstr, cstr);
    }
    argv[argument_count] = nullptr;

    if (start_redirecting_stdout_stderr() == -1) {
        __android_log_write(ANDROID_LOG_ERROR, ADBTAG,
                            "Couldn't start redirecting stdout and stderr to logcat.");
    }

    int result = tun2socks_start((int) argument_count, argv);

    for (jsize i = 0; i < argument_count; i++) {
        free(argv[i]);
    }
    free(argv);

    return jint(result);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_musicses_vlessvpn_Tun2Socks_stopTun2Socks(JNIEnv *env, jclass clazz) {
    tun2socks_terminate();
}

extern "C"
JNIEXPORT void JNICALL
Java_com_musicses_vlessvpn_Tun2Socks_printTun2SocksHelp(JNIEnv *env, jclass clazz) {
    tun2socks_print_help("badvpn-tun2socks");
}

extern "C"
JNIEXPORT void JNICALL
Java_com_musicses_vlessvpn_Tun2Socks_printTun2SocksVersion(JNIEnv *env, jclass clazz) {
    tun2socks_print_version();
}