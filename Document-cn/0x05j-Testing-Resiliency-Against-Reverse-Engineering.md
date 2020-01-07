## Android 反逆向 与 防御

### 越狱监测 测试 (MSTG-RESILIENCE-1)

#### 概述

在逆向这个话题中, 越狱检测机制的目的是为了让应用程序在越狱设备上运行变得更加困难, 这样可以屏蔽一些工具和逆向工程技术的使用. 和其他防御机制一样, 越狱检测本身并不是很有效, 但是整个应用实现多次越狱检测机制可以提高反篡改方案的有效性.

对于 Android 系统来说, 我们对 "越狱 检测" 的定义更为广泛, 其中包括自定义的 ROMs 检测, 例如., 确定设备是常规的 Android 版本还是自定义的版本.

#### 常见 越狱监测方法

在以下章节中, 我们将列出你会遇到的常见的越狱检测方法. 一些方法可以从这里找到样本 [破解我 样本](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes "OWASP 移动破解我") 以及 OWASP 移动测试指南.

越狱检测 可以通过执行程序库, 例如 [RootBeer](https://github.com/scottyab/rootbeer "RootBeer").

##### SafetyNet

SafetyNet 是 Android API 接口, 提供一系列的服务和根据软件和硬件信息, 创建设备的配置文件. 这个配置文件将会和通过 Android 兼容性测试的白名单设备型号列表对比. Google [建议](https://developers.google.com/android/reference/com/google/android/gms/safetynet/SafetyNet "SafetyNet 文档") 使用此功能当成 "一种额外的预防系统滥用的深入防御信号".

关于 SafetyNet 到底怎样工作的, 并没有很好的文档解释,也许以后会改变. 但是当你调用这个 API, SafetyNet 会下载一个二进制软件包, 软件包中有 Google 对设备验证的代码, 然后通过反射动态执行该代码. [分析报告 由 John Kozyrakis](https://koz.io/inside-safetynet/ "SafetyNet: Google's Android 篡改检测功能") 告知我们 SafetyNet 可以检测设备是否越狱, 但是关于怎样检测却没有明细说明.

为了使用此 API, 应用可以调用 `SafetyNetApi.attest` 方法 (将会返回带有 *认证结果* 的 JWS 消息) 然后检查以下字段:

- `ctsProfileMatch`: 如果返回值为 'true', 此设备配置文件匹配谷歌列出的设备之一.
- `basicIntegrity`: 如果返回值为 'true', 该设备运行的应用程序有可能没有被篡改.
- `nonces`: 将响应与他的请求相匹配.
- `timestampMs`: 查看 从发出请求到得到响应所使用的时间. 延迟的反应可能意味着可疑的活动.
- `apkPackageName`, `apkCertificateDigestSha256`, `apkDigestSha256`: 提供有关于 APK 的信息, 用来验证调用程序的身份. 如果 API 不能可靠的确定 APK 信息, 则不提供这些参数.

以下是认证结果的样本:

```json
{
  "nonce": "R2Rra24fVm5xa2Mg",
  "timestampMs": 9860437986543,
  "apkPackageName": "com.package.name.of.requesting.app",
  "apkCertificateDigestSha256": ["base64 encoded, SHA-256 hash of the
                                  certificate used to sign requesting app"],
  "apkDigestSha256": "base64 encoded, SHA-256 hash of the app's APK",
  "ctsProfileMatch": true,
  "basicIntegrity": true,
}
```

###### ctsProfileMatch Vs basicIntegrity

SafetyNet API 认证机制 最初提供了一个名为 `basicIntegrity` 的值, 用来帮助开发人员确定设备的完整性. 随着 API 的发展, 谷歌引入了一种新的, 更严格的检查, 其结果显示在一个名为 `ctsProfileMatch` 的值中, 该值准许开发人员更精确的评估其他应用程序锁运行的设备.

从广义上讲, `basicIntegrity` 给你一个关于设备及其 API 整体完整性的信号. 许多越狱设备无法实现 `basicIntegrity`, 即使是模拟器, 虚拟设备和带有篡改标记的设备 (如 API 挂钩) 也是如此.

另一方面, `ctsProfileMatch` 会给你一个关于设备兼容性的更严格的信号. 只有通过谷歌认证的未经过修改的设备才能通过 `ctsProfileMatch`. 包含在以下条件的设备将会被 `ctsProfileMatch` 否决:

- 设备无法通过 `basicIntegrity`
- 设备存在未锁定的应到加载程序
- 设备带有自定义系统镜像
- 设备没有通过, 或者申请谷歌认证
- 设备自带的系统镜像是从 Android 开源程序源文件构建的
- 设备自带系统镜像带有测试或者开发人员预览的程序

###### 使用 `SafetyNetApi.attest` 时的建议

- 创建一个大于 (16 字节 或者 更大) 任意数字在你的服务器上, 使用加密安全任意功能创建, 这样一个可疑的用户不能再重复使用成功认证的结果到一个不成功认证结果的设备中.
- 信任 APK 信息值 (`apkPackageName`, `apkCertificateDigestSha256` 和 `apkDigestSha256`) 只有当 `ctsProfileMatch` 的值为 true 的时候.
- 整个 JWS 响应过程应该被发送到服务器, 并且使用安全连接, 用于验证. 不建议在移动应用程序中直接执行验证, 因为在这种情况下, 不能保证验证逻辑本身没有被修改.
- `verify` 方法只验证 JWS 消息是由 SafetyNet 签名的. 它并不能验证 payload的判决符合你的期望. 尽管这个服务看起来很有用, 但是他是为测试的目的而设计的, 并且他有非常杨哥的使用限额, 每天有10,000 次请求, 每个项目不会根据请求增加. 因此, 你可以参考 [SafetyNet 认证 举例](https://github.com/googlesamples/android-play-safetynet/tree/master/server/java/src/main/java "Google SafetyNet 案例") 并在你的服务器上施行数字签名认证逻辑, 这样就不用依赖于谷歌的服务器了.
- SafetyNet 鉴证 API 提供了当你申请认证时候的设备状态的镜像. 成功的认证通过不代表设备在过去也通过的认证, 或者说在将来会通过认证. 建议计划一个策略, 使用最少数量的认证用例来满足要求.
- 为了预防无意的触及你的 `SafetyNetApi.attest` 配额和鉴证错误, 你应该建立一个系统来监控你的 API 使用情况, 并且提醒你当你将要超过你的限额. 你应该准备好处理由于配额超出导致的认证识别, 并避免这种情况下阻塞的所有用户. 如果你接近你的额度, 或者期望短期暴涨会超过你的额度, 你可以提交这个 [论坛](https://support.google.com/googleplay/android-developer/contact/safetynetqr "额度 申请") 来申请你的短期 或者 长期的 API 秘钥的额度. 这个流程, 就类似于额外的额度, 不收取任何费用.

参照这个 [清单](https://developer.android.com/training/safetynet/attestation-checklist "鉴证 清单") 来确定你完成了以下的每一步, 并且集成 `SafetyNetApi.attest` API 到你的应用程序当中.

##### 编程级别的 检测

###### 检查文件存在 

也许最广泛的使用方法是检查在越狱设备上的特定文件, 比如说共同越狱应用软件包文件 和 他们相关的文件和目录, 包含以下:

```text
/system/app/Superuser.apk
/system/etc/init.d/99SuperSUDaemon
/dev/com.koushikdutta.superuser.daemon/
/system/xbin/daemonsu
```

代码检测一般检测二进制文件, 这些文件在越狱后被安装到设备上.这些搜索的关键包含检测 Busybox 和尝试打开 *su* 二进制命令在不同的路径:

```text
/sbin/su  
/system/bin/su  
/system/bin/failsafe/su  
/system/xbin/su  
/system/xbin/busybox  
/system/sd/xbin/su  
/data/local/su  
/data/local/xbin/su  
/data/local/bin/su  
```

检查 `su` 命令是否存在在指定路径, 也可以通过代码的方式:

```java
    public static boolean checkRoot(){
        for(String pathDir : System.getenv("PATH").split(":")){
            if(new File(pathDir, "su").exists()) {
                return true;
            }
        }
        return false;
    }
```

文件检测机制能够很容易的在Java 和 原生代码上实现. 接下来的 JNI 实例 (改编自 [rootinspector](https://github.com/devadvance/rootinspector/ "rootinspector")) 使用 `stat` 系统调用获取相关文件信息, 并且如果文件存在时, 返回值为 "1".

```c
jboolean Java_com_example_statfile(JNIEnv * env, jobject this, jstring filepath) {
  jboolean fileExists = 0;
  jboolean isCopy;
  const char * path = (*env)->GetStringUTFChars(env, filepath, &isCopy);
  struct stat fileattrib;
  if (stat(path, &fileattrib) < 0) {
    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "NATIVE: stat error: [%s]", strerror(errno));
  } else
  {
    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "NATIVE: stat success, access perms: [%d]", fileattrib.st_mode);
    return 1;
  }

  return 0;
}
```

###### 执行 `su` 和 其他命令

判断 `su` 是否存在的另一种方法就是尝试通过 `Runtime.getRuntime.exec` 方法去执行它. 错误 IOException 会被程序抛出如果 `su` 不在指定的文件路径. 同样的方法可以使用在检查越狱过的设备的其他应用程序, 例如 busybox 和 指向它的符号链接.

###### 检测巡行进程

Supersu-by 至今为止最流行的越狱工具, 它运行一个名为 `daemonsu` 的身份验证守护进程, 所以这个进程的出现是越狱设备的另外一个标志. 正在运行的进程可以通过 `ActivityManager.getRunningAppProcesses` 和 `manager.getRunningServices` APIs 枚举, `ps` 命令, 和通过 `/proc` 文件夹来浏览. 以下是一个在 [rootinspector](https://github.com/devadvance/rootinspector/ "rootinspector") 实现的示例:

```java
    public boolean checkRunningProcesses() {

      boolean returnValue = false;

      // Get currently running application processes
      List<RunningServiceInfo> list = manager.getRunningServices(300);

      if(list != null){
        String tempName;
        for(int i=0;i<list.size();++i){
          tempName = list.get(i).process;

          if(tempName.contains("supersu") || tempName.contains("superuser")){
            returnValue = true;
          }
        }
      }
      return returnValue;
    }
```

###### 检测 已经安全的应用包

你也可以使用 Android 软件包管理 来获取已经安装的软件包列表. 下面是越狱设备的主流工具软件包名称:

```text
com.thirdparty.superuser
eu.chainfire.supersu
com.noshufou.android.su
com.koushikdutta.superuser
com.zachspong.temprootremovejb
com.ramdroid.appquarantine
com.topjohnwu.magisk
```

###### 检测 可写的分区 和 系统目录

系统目录上不正常的权限可能暗示此设备越狱或者是自定义修改过. 虽然系统和数据目录通常都是只读挂载的, 但是你有时候会发现越狱的设备挂载了读写权限. 寻找这些激活了 "rw" 标签的文件系统最简单的方式就是在其目录中创建一个文件.

###### 检测 自定义的 Android 版本

检查测试版本和自定义的ROMs 的标识也非常有用. 其中一种方法是检测 BUILD 标签作为测试关键, 通常 [indicate a custom Android image](https://resources.infosecinstitute.com/android-hacking-security-part-8-root-detection-evasion// "InfoSec Institute - Android Root Detection and Evasion"). [Check the BUILD tag as follows](https://www.joeyconway.com/blog/2014/03/29/android-detect-root-access-from-inside-an-app/ "Android - Detect Root Access from inside an app"):

```java
private boolean isTestKeyBuild()
{
String str = Build.TAGS;
if ((str != null) && (str.contains("test-keys")));
for (int i = 1; ; i = 0)
  return i;
}
```

缺少谷歌的 Over-The-Air (OTA) 证书也是自定义ROM的另外一个标志: 在 Android 原厂版本中, [OTA updates Google's public certificates](https://blog.netspi.com/android-root-detection-techniques/ "Android Root Detection Techniques").

##### 绕过 越狱检测

通过JDB 运行执行命令跟踪, DDMS, `strace`, 和/或内核模块,以找出应用程序正在做什么. 你通常将会看见各种各样的操作系统层面的可疑互动, 比如, 执行 `su` 命令来读取和获取进程列表. 这些互动是越狱成功的检测标志. 识别 和 停用越狱检测机制, 一步一步的操作. 如果你进行黑盒弹性评估, 关闭越狱检测机制是你的第一步.

为了绕过这些测试, 你可以使用几种技术, 最常见在 "逆向工程 和 篡改" 章节中已经被介绍:

- 二进制文件从命名. 举例, 在某些案例中, 简单的改变该 `su` 二进制就足够击败越狱 (尝试不要破坏了自己的环境.)
- 卸载 `/proc` 路径来防止读取进程列表. 某些时候, 路径 `/proc` 的不可用足够可以绕过类似检查.
- 使用 Frida 或者 Xposed 将 API 挂接到 Java 和 自身层上. 它隐藏了文件和进程, 隐藏文件的内容, 和返回应用程序请求的各种值.
- 通过使用内核模块挂接底层 API.
- 修补应用程序，以删除检查.

#### 有效性 评估

检查越狱检测机制, 包括以下标准:

- Multiple detection methods are scattered throughout the app (as opposed to putting everything into a single method).
- The root detection mechanisms operate on multiple API layers (Java APIs, native library functions, assembler/system calls).
- The mechanisms are somehow original (they're not copied and pasted from StackOverflow or other sources).

Develop bypass methods for the root detection mechanisms and answer the following questions:

- Can the mechanisms be easily bypassed with standard tools, such as RootCloak?
- Is static/dynamic analysis necessary to handle the root detection?
- Do you need to write custom code?
- How long did successfully bypassing the mechanisms take?
- What is your assessment of the difficulty of bypassing the mechanisms?

If root detection is missing or too easily bypassed, make suggestions in line with the effectiveness criteria listed above. These suggestions may include more detection mechanisms and better integration of existing mechanisms with other defenses.

### Testing Anti-Debugging Detection (MSTG-RESILIENCE-2)

#### Overview

Debugging is a highly effective way to analyze run-time app behavior. It allows the reverse engineer to step through the code, stop app execution at arbitrary points, inspect the state of variables, read and modify memory, and a lot more.

As mentioned in the "Reverse Engineering and Tampering" chapter, we have to deal with two debugging protocols on Android: we can debug on the Java level with JDWP or on the native layer via a ptrace-based debugger. A good anti-debugging scheme should defend against both types of debugging.

Anti-debugging features can be preventive or reactive. As the name implies, preventive anti-debugging prevents the debugger from attaching in the first place; reactive anti-debugging involves detecting debuggers and reacting to them in some way (e.g., terminating the app or triggering hidden behavior). The "more-is-better" rule applies: to maximize effectiveness, defenders combine multiple methods of prevention and detection that operate on different API layers and are distributed throughout the app.

##### Anti-JDWP-Debugging Examples

In the chapter "Reverse Engineering and Tampering", we talked about JDWP, the protocol used for communication between the debugger and the Java Virtual Machine. We showed that it is easy to enable debugging for any app by patching its manifest file, and changing the `ro.debuggable` system property which enables debugging for all apps. Let's look at a few things developers do to detect and disable JDWP debuggers.

###### Checking the Debuggable Flag in ApplicationInfo

We have already encountered the `android:debuggable` attribute. This flag in the Android Manifest determines whether the JDWP thread is started for the app. Its value can be determined programmatically, via the app's `ApplicationInfo` object. If the flag is set, the manifest has been tampered with and allows debugging.

```java
    public static boolean isDebuggable(Context context){

        return ((context.getApplicationContext().getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);

    }
```

###### isDebuggerConnected

The `Android Debug` system class offers a static method to determine whether a debugger is connected. The method returns a boolean value.

```java
    public static boolean detectDebugger() {
        return Debug.isDebuggerConnected();
    }
```

The same API can be called via native code by accessing the DvmGlobals global structure.

```c
JNIEXPORT jboolean JNICALL Java_com_test_debugging_DebuggerConnectedJNI(JNIenv * env, jobject obj) {
    if (gDvm.debuggerConnected || gDvm.debuggerActive)
        return JNI_TRUE;
    return JNI_FALSE;
}
```

###### Timer Checks

`Debug.threadCpuTimeNanos` indicates the amount of time that the current thread has been executing code. Because debugging slows down process execution, [you can use the difference in execution time to guess whether a debugger is attached](https://slides.night-labs.de/AndroidREnDefenses201305.pdf "Bluebox Security - Android Reverse Engineering & Defenses").

```java
static boolean detect_threadCpuTimeNanos(){
  long start = Debug.threadCpuTimeNanos();

  for(int i=0; i<1000000; ++i)
    continue;

  long stop = Debug.threadCpuTimeNanos();

  if(stop - start < 10000000) {
    return false;
  }
  else {
    return true;
  }
}
```

###### Messing with JDWP-Related Data Structures

In Dalvik, the global virtual machine state is accessible via the `DvmGlobals` structure. The global variable gDvm holds a pointer to this structure. `DvmGlobals` contains various variables and pointers that are important for JDWP debugging and can be tampered with.

```c
struct DvmGlobals {
    /*
     * Some options that could be worth tampering with :)
     */

    bool        jdwpAllowed;        // debugging allowed for this process?
    bool        jdwpConfigured;     // has debugging info been provided?
    JdwpTransportType jdwpTransport;
    bool        jdwpServer;
    char*       jdwpHost;
    int         jdwpPort;
    bool        jdwpSuspend;

    Thread*     threadList;

    bool        nativeDebuggerActive;
    bool        debuggerConnected;      /* debugger or DDMS is connected */
    bool        debuggerActive;         /* debugger is making requests */
    JdwpState*  jdwpState;

};
```

For example, [setting the gDvm.methDalvikDdmcServer_dispatch function pointer to NULL crashes the JDWP thread](https://slides.night-labs.de/AndroidREnDefenses201305.pdf "Bluebox Security - Android Reverse Engineering & Defenses"):

```c
JNIEXPORT jboolean JNICALL Java_poc_c_crashOnInit ( JNIEnv* env , jobject ) {
  gDvm.methDalvikDdmcServer_dispatch = NULL;
}
```

You can disable debugging by using similar techniques in ART even though the gDvm variable is not available. The ART runtime exports some of the vtables of JDWP-related classes as global symbols (in C++, vtables are tables that hold pointers to class methods). This includes the vtables of the classes `JdwpSocketState` and `JdwpAdbState`, which handle JDWP connections via network sockets and ADB, respectively. You can manipulate the behavior of the debugging runtime [by overwriting the method pointers in the associated vtables](https://www.vantagepoint.sg/blog/88-anti-debugging-fun-with-android-art "Vantage Point Security - Anti-Debugging Fun with Android ART").

One way to overwrite the method pointers is to overwrite the address of the function `jdwpAdbState::ProcessIncoming` with the address of `JdwpAdbState::Shutdown`. This will cause the debugger to disconnect immediately.

```c
#include <jni.h>
#include <string>
#include <android/log.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <jdwp/jdwp.h>

#define log(FMT, ...) __android_log_print(ANDROID_LOG_VERBOSE, "JDWPFun", FMT, ##__VA_ARGS__)

// Vtable structure. Just to make messing around with it more intuitive

struct VT_JdwpAdbState {
    unsigned long x;
    unsigned long y;
    void * JdwpSocketState_destructor;
    void * _JdwpSocketState_destructor;
    void * Accept;
    void * showmanyc;
    void * ShutDown;
    void * ProcessIncoming;
};

extern "C"

JNIEXPORT void JNICALL Java_sg_vantagepoint_jdwptest_MainActivity_JDWPfun(
        JNIEnv *env,
        jobject /* this */) {

    void* lib = dlopen("libart.so", RTLD_NOW);

    if (lib == NULL) {
        log("Error loading libart.so");
        dlerror();
    }else{

        struct VT_JdwpAdbState *vtable = ( struct VT_JdwpAdbState *)dlsym(lib, "_ZTVN3art4JDWP12JdwpAdbStateE");

        if (vtable == 0) {
            log("Couldn't resolve symbol '_ZTVN3art4JDWP12JdwpAdbStateE'.\n");
        }else {

            log("Vtable for JdwpAdbState at: %08x\n", vtable);

            // Let the fun begin!

            unsigned long pagesize = sysconf(_SC_PAGE_SIZE);
            unsigned long page = (unsigned long)vtable & ~(pagesize-1);

            mprotect((void *)page, pagesize, PROT_READ | PROT_WRITE);

            vtable->ProcessIncoming = vtable->ShutDown;

            // Reset permissions & flush cache

            mprotect((void *)page, pagesize, PROT_READ);

        }
    }
}
```

##### Anti-Native-Debugging Examples

Most Anti-JDWP tricks (which may be safe for timer-based checks) won't catch classical, ptrace-based debuggers, so other defenses are necessary. Many "traditional" Linux anti-debugging tricks are used in this situation.

###### Checking TracerPid

When the `ptrace` system call is used to attach to a process, the "TracerPid" field in the status file of the debugged process shows the PID of the attaching process. The default value of "TracerPid" is 0 (no process attached). Consequently, finding anything other than 0 in that field is a sign of debugging or other ptrace shenanigans.

The following implementation is from [Tim Strazzere's Anti-Emulator project](https://github.com/strazzere/anti-emulator/ "anti-emulator"):

```java
    public static boolean hasTracerPid() throws IOException {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(new FileInputStream("/proc/self/status")), 1000);
            String line;

            while ((line = reader.readLine()) != null) {
                if (line.length() > tracerpid.length()) {
                    if (line.substring(0, tracerpid.length()).equalsIgnoreCase(tracerpid)) {
                        if (Integer.decode(line.substring(tracerpid.length() + 1).trim()) > 0) {
                            return true;
                        }
                        break;
                    }
                }
            }

        } catch (Exception exception) {
            exception.printStackTrace();
        } finally {
            reader.close();
        }
        return false;
    }
```

**Ptrace variations***

On Linux, the [`ptrace` system call](http://man7.org/linux/man-pages/man2/ptrace.2.html "Ptrace man page") is used to observe and control the execution of a process (the "tracee") and to examine and change that process' memory and registers. ptrace is the primary way to implement breakpoint debugging and system call tracing. Many anti-debugging tricks include `ptrace`, often exploiting the fact that only one debugger at a time can attach to a process.

You can prevent debugging of a process by forking a child process and attaching it to the parent as a debugger via code similar to the following simple example code:

```c
void fork_and_attach()
{
  int pid = fork();

  if (pid == 0)
    {
      int ppid = getppid();

      if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0)
        {
          waitpid(ppid, NULL, 0);

          /* Continue the parent process */
          ptrace(PTRACE_CONT, NULL, NULL);
        }
    }
}
```

With the child attached, further attempts to attach to the parent will fail. We can verify this by compiling the code into a JNI function and packing it into an app we run on the device.

```shell
root@android:/ # ps | grep -i anti
u0_a151   18190 201   1535844 54908 ffffffff b6e0f124 S sg.vantagepoint.antidebug
u0_a151   18224 18190 1495180 35824 c019a3ac b6e0ee5c S sg.vantagepoint.antidebug
```

Attempting to attach to the parent process with gdbserver fails with an error:

```shell
root@android:/ # ./gdbserver --attach localhost:12345 18190
warning: process 18190 is already traced by process 18224
Cannot attach to lwp 18190: Operation not permitted (1)
Exiting
```

You can easily bypass this failure, however, by killing the child and "freeing" the parent from being traced. You'll therefore usually find more elaborate schemes, involving multiple processes and threads as well as some form of monitoring to impede tampering. Common methods include

- forking multiple processes that trace one another,
- keeping track of running processes to make sure the children stay alive,
- monitoring values in the `/proc` filesystem, such as TracerPID in `/proc/pid/status`.

Let's look at a simple improvement for the method above. After the initial `fork`, we launch in the parent an extra thread that continually monitors the child's status. Depending on whether the app has been built in debug or release mode (which is indicated by the `android:debuggable` flag in the manifest), the child process should do one of the following things:

- In release mode: The call to ptrace fails and the child crashes immediately with a segmentation fault (exit code 11).
- In debug mode: The call to ptrace works and the child should run indefinitely. Consequently, a call to `waitpid(child_pid)` should never return. If it does, something is fishy and we would kill the whole process group.

The following is the complete code for implementing this improvement with a JNI function:

```c
#include <jni.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <pthread.h>

static int child_pid;

void *monitor_pid() {

    int status;

    waitpid(child_pid, &status, 0);

    /* Child status should never change. */

    _exit(0); // Commit seppuku

}

void anti_debug() {

    child_pid = fork();

    if (child_pid == 0)
    {
        int ppid = getppid();
        int status;

        if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0)
        {
            waitpid(ppid, &status, 0);

            ptrace(PTRACE_CONT, ppid, NULL, NULL);

            while (waitpid(ppid, &status, 0)) {

                if (WIFSTOPPED(status)) {
                    ptrace(PTRACE_CONT, ppid, NULL, NULL);
                } else {
                    // Process has exited
                    _exit(0);
                }
            }
        }

    } else {
        pthread_t t;

        /* Start the monitoring thread */
        pthread_create(&t, NULL, monitor_pid, (void *)NULL);
    }
}

JNIEXPORT void JNICALL
Java_sg_vantagepoint_antidebug_MainActivity_antidebug(JNIEnv *env, jobject instance) {

    anti_debug();
}
```

Again, we pack this into an Android app to see if it works. Just as before, two processes show up when we run the app's debug build.

```shell
root@android:/ # ps | grep -I anti-debug
u0_a152   20267 201   1552508 56796 ffffffff b6e0f124 S sg.vantagepoint.anti-debug
u0_a152   20301 20267 1495192 33980 c019a3ac b6e0ee5c S sg.vantagepoint.anti-debug
```

However, if we terminate the child process at this point, the parent exits as well:

```shell
root@android:/ # kill -9 20301
130|root@hammerhead:/ # cd /data/local/tmp
root@android:/ # ./gdbserver --attach localhost:12345 20267
gdbserver: unable to open /proc file '/proc/20267/status'
Cannot attach to lwp 20267: No such file or directory (2)
Exiting
```

To bypass this, we must modify the app's behavior slightly (the easiest ways to do so are patching the call to `_exit` with NOPs and hooking the function `_exit` in `libc.so`). At this point, we have entered the proverbial "arms race": implementing more intricate forms of this defense as well as bypassing it are always possible.

##### Bypassing Debugger Detection

There's no generic way to bypass anti-debugging: the best method depends on the particular mechanism(s) used to prevent or detect debugging and the other defenses in the overall protection scheme. For example, if there are no integrity checks or you've already deactivated them, patching the app might be the easiest method. In other cases, a hooking framework or kernel modules might be preferable.
The following methods describe different approaches to bypass debugger detection:

- Patching the anti-debugging functionality: Disable the unwanted behavior by simply overwriting it with NOP instructions. Note that more complex patches may be required if the anti-debugging mechanism is well designed.
- Using Frida or Xposed to hook APIs on the Java and native layers: manipulate the return values of functions such as `isDebuggable` and `isDebuggerConnected` to hide the debugger.
- Changing the environment: Android is an open environment. If nothing else works, you can modify the operating system to subvert the assumptions the developers made when designing the anti-debugging tricks.

###### Bypassing Example: UnCrackable App for Android Level 2

When dealing with obfuscated apps, you'll often find that developers purposely "hide away" data and functionality in native libraries. You'll find an example of this in level 2 of the "UnCrackable App for Android".

At first glance, the code looks like the prior challenge. A class called `CodeCheck` is responsible for verifying the code entered by the user. The actual check appears to occur in the `bar` method, which is declared as a *native* method.

```java
package sg.vantagepoint.uncrackable2;

public class CodeCheck {
    public CodeCheck() {
        super();
    }

    public boolean a(String arg2) {
        return this.bar(arg2.getBytes());
    }

    private native boolean bar(byte[] arg1) {
    }
}

    static {
        System.loadLibrary("foo");
    }
```

Please see [different proposed solutions for the Android Crackme Level 2](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes#uncrackable-app-for-android-level-2 "Solutions Android Crackme Level 2") in GitHub.

#### Effectiveness Assessment

Check for anti-debugging mechanisms, including the following criteria:

- Attaching JDB and ptrace-based debuggers fails or causes the app to terminate or malfunction.
- Multiple detection methods are scattered throughout the app's source code (as opposed to their all being in a single method or function).
- The anti-debugging defenses operate on multiple API layers (Java, native library functions, assembler/system calls).
- The mechanisms are somehow original (as opposed to being copied and pasted from StackOverflow or other sources).

Work on bypassing the anti-debugging defenses and answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by hooking a single API function)?
- How difficult is identifying the anti-debugging code via static and dynamic analysis?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your subjective assessment of the difficulty of bypassing the mechanisms?

If anti-debugging mechanisms are missing or too easily bypassed, make suggestions in line with the effectiveness criteria above. These suggestions may include adding more detection mechanisms and better integration of existing mechanisms with other defenses.

### Testing File Integrity Checks (MSTG-RESILIENCE-3)

#### Overview

There are two topics related to file integrity:

 1. _Code integrity checks:_ In the "Tampering and Reverse Engineering" chapter, we discussed Android's APK code signature check. We also saw that determined reverse engineers can easily bypass this check by re-packaging and re-signing an app. To make this bypassing process more involved, a protection scheme can be augmented with CRC checks on the app byte-code, native libraries, and important data files. These checks can be implemented on both the Java and the native layer. The idea is to have additional controls in place so that the app only runs correctly in its unmodified state, even if the code signature is valid.
 2. _The file storage integrity checks:_ The integrity of files that the application stores on the SD card or public storage and the integrity of key-value pairs that are stored in `SharedPreferences` should be protected.

##### Sample Implementation - Application Source Code

Integrity checks often calculate a checksum or hash over selected files. Commonly protected files include

- AndroidManifest.xml,
- class files *.dex,
- native libraries (*.so).

The following [sample implementation from the Android Cracking blog](https://androidcracking.blogspot.com/2011/06/anti-tampering-with-crc-check.html "anti-tampering with crc check") calculates a CRC over `classes.dex` and compares it to the expected value.

```java
private void crcTest() throws IOException {
 boolean modified = false;
 // required dex crc value stored as a text string.
 // it could be any invisible layout element
 long dexCrc = Long.parseLong(Main.MyContext.getString(R.string.dex_crc));

 ZipFile zf = new ZipFile(Main.MyContext.getPackageCodePath());
 ZipEntry ze = zf.getEntry("classes.dex");

 if ( ze.getCrc() != dexCrc ) {
  // dex has been modified
  modified = true;
 }
 else {
  // dex not tampered with
  modified = false;
 }
}
```

##### Sample Implementation - Storage

When providing integrity on the storage itself, you can either create an HMAC over a given key-value pair (as for the Android `SharedPreferences`) or create an HMAC over a complete file that's provided by the file system.

When using an HMAC, you can [use a bouncy castle implementation or the AndroidKeyStore to HMAC the given content](https://cseweb.ucsd.edu/~mihir/papers/oem.html "Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm").

Complete the following procedure when generating an HMAC with BouncyCastle:

1. Make sure BouncyCastle or SpongyCastle is registered as a security provider.
2. Initialize the HMAC with a key (which can be stored in a keystore).
3. Get the byte array of the content that needs an HMAC.
4. Call `doFinal` on the HMAC with the byte-code.
5. Append the HMAC to the bytearray obtained in step 3.
6. Store the result of step 5.

Complete the following procedure when verifying the HMAC with BouncyCastle:

1. Make sure that BouncyCastle or SpongyCastle is registered as a security provider.
2. Extract the message and the HMAC-bytes as separate arrays.
3. Repeat steps 1-4 of the procedure for generating an HMAC.
4. Compare the extracted HMAC-bytes to the result of step 3.

When generating the HMAC based on the [Android Keystore](https://developer.android.com/training/articles/keystore.html "Android Keystore"), then it is best to only do this for Android 6.0 (API level 23) and higher.

The following is a convenient HMAC implementation without `AndroidKeyStore`:

```java
public enum HMACWrapper {
    HMAC_512("HMac-SHA512"), //please note that this is the spec for the BC provider
    HMAC_256("HMac-SHA256");

    private final String algorithm;

    private HMACWrapper(final String algorithm) {
        this.algorithm = algorithm;
    }

    public Mac createHMAC(final SecretKey key) {
        try {
            Mac e = Mac.getInstance(this.algorithm, "BC");
            SecretKeySpec secret = new SecretKeySpec(key.getKey().getEncoded(), this.algorithm);
            e.init(secret);
            return e;
        } catch (NoSuchProviderException | InvalidKeyException | NoSuchAlgorithmException e) {
            //handle them
        }
    }

    public byte[] hmac(byte[] message, SecretKey key) {
        Mac mac = this.createHMAC(key);
        return mac.doFinal(message);
    }

    public boolean verify(byte[] messageWithHMAC, SecretKey key) {
        Mac mac = this.createHMAC(key);
        byte[] checksum = extractChecksum(messageWithHMAC, mac.getMacLength());
        byte[] message = extractMessage(messageWithHMAC, mac.getMacLength());
        byte[] calculatedChecksum = this.hmac(message, key);
        int diff = checksum.length ^ calculatedChecksum.length;

        for (int i = 0; i < checksum.length && i < calculatedChecksum.length; ++i) {
            diff |= checksum[i] ^ calculatedChecksum[i];
        }

        return diff == 0;
    }

    public byte[] extractMessage(byte[] messageWithHMAC) {
        Mac hmac = this.createHMAC(SecretKey.newKey());
        return extractMessage(messageWithHMAC, hmac.getMacLength());
    }

    private static byte[] extractMessage(byte[] body, int checksumLength) {
        if (body.length >= checksumLength) {
            byte[] message = new byte[body.length - checksumLength];
            System.arraycopy(body, 0, message, 0, message.length);
            return message;
        } else {
            return new byte[0];
        }
    }

    private static byte[] extractChecksum(byte[] body, int checksumLength) {
        if (body.length >= checksumLength) {
            byte[] checksum = new byte[checksumLength];
            System.arraycopy(body, body.length - checksumLength, checksum, 0, checksumLength);
            return checksum;
        } else {
            return new byte[0];
        }
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}

```

Another way to provide integrity is to sign the byte array you obtained and add the signature to the original byte array.

##### Bypassing File Integrity Checks

###### Bypassing the application-source integrity checks

1. Patch the anti-debugging functionality. Disable the unwanted behavior by simply overwriting the associated byte-code or native code with NOP instructions.
2. Use Frida or Xposed to hook file system APIs on the Java and native layers. Return a handle to the original file instead of the modified file.
3. Use the kernel module to intercept file-related system calls. When the process attempts to open the modified file, return a file descriptor for the unmodified version of the file.

Refer to the "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)" chapter for examples of patching, code injection, and kernel modules.

###### Bypassing the storage integrity checks

1. Retrieve the data from the device, as described in the "[Testing Device Binding](#testing-device-binding-mstg-resilience-10 "Testing Device Binding")" section.
2. Alter the retrieved data and then put it back into storage.

#### Effectiveness Assessment

##### For application-source integrity checks

Run the app in an unmodified state and make sure that everything works. Apply simple patches to `classes.dex` and any .so libraries in the app package. Re-package and re-sign the app as described in the "Basic Security Testing" chapter, then run the app. The app should detect the modification and respond in some way. At the very least, the app should alert the user and/or terminate. Work on bypassing the defenses and answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by hooking a single API function)?
- How difficult is identifying the anti-debugging code via static and dynamic analysis?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?

##### For storage integrity checks

An approach similar to that for application-source integrity checks applies. Answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by changing the contents of a file or a key-value)?
- How difficult is getting the HMAC key or the asymmetric private key?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?

### Testing Reverse Engineering Tools Detection (MSTG-RESILIENCE-4)

#### Overview

Reverse engineers use a lot of tools, frameworks, and apps, many of which you've encountered in this guide. Consequently, the presence of such tools on the device may indicate that the user is attempting to reverse engineer the app. Users increase their risk by installing such tools.

#### Detection Methods

You can detect popular reverse engineering tools that have been installed in an unmodified form by looking for associated application packages, files, processes, or other tool-specific modifications and artifacts. In the following examples, we'll discuss different ways to detect the Frida instrumentation framework, which is used extensively in this guide. Other tools, such as Substrate and Xposed, can be detected similarly. Note that DBI/injection/hooking tools can often be detected implicitly, through run time integrity checks, which are discussed below.

For instance, in its default configuration on a rooted device, Frida runs on the device as frida-server. When you explicitly attach to a target app (e.g. via frida-trace or the Frida REPL), Frida injects a frida-agent into the memory of the app. Therefore, you may expect to find it there after attaching to the app (and not before). If you check `/proc/<pid>/maps` you'll find the frida-agent as frida-agent-64.so:

```bash
bullhead:/ # cat /proc/18370/maps | grep -i frida
71b6bd6000-71b7d62000 r-xp  /data/local/tmp/re.frida.server/frida-agent-64.so
71b7d7f000-71b7e06000 r--p  /data/local/tmp/re.frida.server/frida-agent-64.so
71b7e06000-71b7e28000 rw-p  /data/local/tmp/re.frida.server/frida-agent-64.so
```

The other method (which also works for non-rooted devices) consists of embedding a [frida-gadget](https://www.frida.re/docs/gadget/ "Frida Gadget") into the APK and _forcing_ the app to load it as one of its native libraries. If you inspect the app memory maps after starting the app (no need to attach explicitly to it) you'll find the embedded frida-gadget as libfrida-gadget.so.

```bash
bullhead:/ # cat /proc/18370/maps | grep -i frida

71b865a000-71b97f1000 r-xp  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
71b9802000-71b988a000 r--p  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
71b988a000-71b98ac000 rw-p  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
```

Looking at these two _traces_ that Frida _lefts behind_, you might already imagine that detecting those would be a trivial task. And actually, so trivial will be bypassing that detection. But things can get much more complicated. The following table shortly presents a set of some typical Frida detection methods and a short discussion on their effectiveness.

> Some of the following detection methods are presented in the article ["The Jiu-Jitsu of Detecting Frida" by Berdhard Mueller](http://www.vantagepoint.sg/blog/90-the-jiu-jitsu-of-detecting-frida "The Jiu-Jitsu of Detecting Frida"). Please refer to it for more details and for example code snippets.

| Method | Description | Discussion |
| --- | --- | --- |
| **Checking the App Signature** | In order to embed the frida-gadget within the APK, it would need to be repackaged and resigned. You could check the signature of the APK when the app is starting (e.g. [GET_SIGNING_CERTIFICATES](https://developer.android.com/reference/android/content/pm/PackageManager#GET_SIGNING_CERTIFICATES "GET_SIGNING_CERTIFICATES") since API level 28) and compare it to the one you pinned in your APK. | This is unfortunately too trivial to bypass, e.g. by patching the APK or performing system call hooking. |
| **Check The Environment For Related Artifacts**  |  Artifacts can be package files, binaries, libraries, processes, and temporary files. For Frida, this could be the frida-server running in the target (rooted) system (the daemon responsible for exposing Frida over TCP). Inspect the running services ([`getRunningServices`](https://developer.android.com/reference/android/app/ActivityManager.html#getRunningServices%28int%29 "getRunningServices")) and processes (`ps`) searching for one whose name is "frida-server". You could also walk through the list of loaded libraries and check for suspicious ones (e.g. those including "frida" in their names). | Since Android 7.0 (API level 24), inspecting the running services/processes won't show you daemons like the frida-server as it is not being started by the app itself. Even if it would be possible, bypassing this would be as easy just renaming the corresponding Frida artifact (frida-server/frida-gadget/frida-agent). |
| **Checking For Open TCP Ports** | The frida-server process binds to TCP port 27042 by default. Check whether this port is open is another method of detecting the daemon. | This method detects frida-server in its default mode, but the listening port can be changed via a command line argument, so bypassing this is a little too trivial. |
| **Checking For Ports Responding To D-Bus Auth** | `frida-server` uses the D-Bus protocol to communicate, so you can expect it to respond to D-Bus AUTH. Send a D-Bus AUTH message to every open port and check for an answer, hoping that `frida-server` will reveal itself. | This is a fairly robust method of detecting `frida-server`, but Frida offers alternative modes of operation that don't require frida-server. |
| **Scanning Process Memory for Known Artifacts** | Scan the memory for artifacts found in Frida's libraries, e.g. the string "LIBFRIDA" present in all versions of frida-gadget and frida-agent. For example, use `Runtime.getRuntime().exec` and iterate through the memory mappings listed in `/proc/self/maps` or `/proc/<pid>/maps` (depending on the Android version) searching for the string. | This method is a bit more effective, and it is difficult to bypass with Frida only, especially if some obfuscation has been added and if multiple artifacts are being scanned. However, the chosen artifacts might be patched in the Frida binaries. Find the source code on [Berdhard Mueller's GitHub](https://github.com/b-mueller/frida-detection-demo/blob/master/AntiFrida/app/src/main/cpp/native-lib.cpp "frida-detection-demo"). |

Please remember that this table is far from exhaustive. We could start talking about [named pipes](https://en.wikipedia.org/wiki/Named_pipe "Named Pipes") (used by frida-server for external communication), detecting [trampolines](https://en.wikipedia.org/wiki/Trampoline_%28computing%29 "Trampolines") (indirect jump vectors inserted at the prologue of functions), which would _help_ detecting Substrate or Frida's Interceptor but, for example, won't be effective against Frida's Stalker; and many other, more or less, effective detection methods. Each of them will depend on whether you're using a rooted device, the specific version of the rooting method and/or the version of the tool itself. At the end, this is part of the cat and mouse game of protecting data being processed on an untrusted environment (an app running in the user device).

**It is important to note that these methods are just increasing the complexity of the reverse engineer. If being used, the best approach is to combine them cleverly instead of using them individually. However, none of them can assure a 100% effectiveness, remember that the reverse engineer always wins! You also have to consider that integrating some of them into your app might increase the complexity of your app as well as considerably mine its performance.**

#### Effectiveness Assessment

Launch the app with various reverse engineering tools and frameworks installed in your test device. Include at least the following: Frida, Xposed, Substrate for Android, Drozer, RootCloak, Android SSL Trust Killer.

The app should respond in some way to the presence of those tools. For example by:

- Alerting the user and asking for accepting liability.
- Preventing execution by gracefully terminating.
- Securely wiping any sensitive data stored on the device.
- Reporting to a backend server, e.g, for fraud detection.

Next, work on bypassing the detection of the reverse engineering tools and answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by hooking a single API function)?
- How difficult is identifying the anti-debugging code via static and dynamic analysis?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?

The following steps should guide you when bypassing detection of reverse engineering tools:

1. Patch the anti-debugging functionality. Disable the unwanted behavior by simply overwriting the associated byte-code or native code with NOP instructions.
2. Use Frida or Xposed to hook file system APIs on the Java and native layers. Return a handle to the original file, not the modified file.
3. Use a kernel module to intercept file-related system calls. When the process attempts to open the modified file, return a file descriptor for the unmodified version of the file.

Refer to the "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)" chapter for examples of patching, code injection, and kernel modules.

### Testing Emulator Detection (MSTG-RESILIENCE-5)

#### Overview

In the context of anti-reversing, the goal of emulator detection is to increase the difficulty of running the app on an emulated device, which impedes some tools and techniques reverse engineers like to use. This increased difficulty forces the reverse engineer to defeat the emulator checks or utilize the physical device, thereby barring the access required for large-scale device analysis.

#### Emulator Detection Examples

There are several indicators that the device in question is being emulated. Although all these API calls can be hooked, these indicators provide a modest first line of defense.

The first set of indicators are in the file `build.prop`.

```text
API Method          Value           Meaning
Build.ABI           armeabi         possibly emulator
BUILD.ABI2          unknown         possibly emulator
Build.BOARD         unknown         emulator
Build.Brand         generic         emulator
Build.DEVICE        generic         emulator
Build.FINGERPRINT   generic         emulator
Build.Hardware      goldfish        emulator
Build.Host          android-test    possibly emulator
Build.ID            FRF91           emulator
Build.MANUFACTURER  unknown         emulator
Build.MODEL         sdk             emulator
Build.PRODUCT       sdk             emulator
Build.RADIO         unknown         possibly emulator
Build.SERIAL        null            emulator
Build.USER          android-build   emulator
```

You can edit the file `build.prop` on a rooted Android device or modify it while compiling AOSP from source. Both techniques will allow you to bypass the static string checks above.

The next set of static indicators utilize the Telephony manager. All Android emulators have fixed values that this API can query.

```text
API                                                     Value                   Meaning
TelephonyManager.getDeviceId()                          0's                     emulator
TelephonyManager.getLine1 Number()                      155552155               emulator
TelephonyManager.getNetworkCountryIso()                 us                      possibly emulator
TelephonyManager.getNetworkType()                       3                       possibly emulator
TelephonyManager.getNetworkOperator().substring(0,3)    310                     possibly emulator
TelephonyManager.getNetworkOperator().substring(3)      260                     possibly emulator
TelephonyManager.getPhoneType()                         1                       possibly emulator
TelephonyManager.getSimCountryIso()                     us                      possibly emulator
TelephonyManager.getSimSerial Number()                  89014103211118510720    emulator
TelephonyManager.getSubscriberId()                      310260000000000         emulator
TelephonyManager.getVoiceMailNumber()                   15552175049             emulator
```

Keep in mind that a hooking framework, such as Xposed or Frida, can hook this API to provide false data.

#### Bypassing Emulator Detection

1. Patch the emulator detection functionality. Disable the unwanted behavior by simply overwriting the associated byte-code or native code with NOP instructions.
2. Use Frida or Xposed APIs to hook file system APIs on the Java and native layers. Return innocent-looking values (preferably taken from a real device) instead of the telltale emulator values. For example, you can override the `TelephonyManager.getDeviceID` method to return an IMEI value.

Refer to the "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)" chapter for examples of patching, code injection, and kernel modules.

#### Effectiveness Assessment

Install and run the app in the emulator. The app should detect that it is being executed in an emulator and terminate or refuse to execute the functionality that's meant to be protected.

Work on bypassing the defenses and answer the following questions:

- How difficult is identifying the emulator detection code via static and dynamic analysis?
- Can the detection mechanisms be bypassed trivially (e.g., by hooking a single API function)?
- Did you need to write custom code to disable the anti-emulation feature(s)? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?

### Testing Run Time Integrity Checks (MSTG-RESILIENCE-6)

#### Overview

Controls in this category verify the integrity of the app's memory space to defend the app against memory patches applied during run time. Such patches include unwanted changes to binary code, byte-code, function pointer tables, and important data structures, as well as rogue code loaded into process memory. Integrity can be verified by

1. comparing the contents of memory or a checksum over the contents to good values,
2. searching memory for the signatures of unwanted modifications.

There's some overlap with the category "detecting reverse engineering tools and frameworks", and, in fact, we demonstrated the signature-based approach in that chapter when we showed how to search process memory for Frida-related strings. Below are a few more examples of various kinds of integrity monitoring.

##### Run Time Integrity Check Examples

###### Detecting tampering with the Java Runtime**

This detection code is from the [dead && end blog](https://d3adend.org/blog/?p=589 "dead && end blog - Android Anti-Hooking Techniques in Java").

```java
try {
  throw new Exception();
}
catch(Exception e) {
  int zygoteInitCallCount = 0;
  for(StackTraceElement stackTraceElement : e.getStackTrace()) {
    if(stackTraceElement.getClassName().equals("com.android.internal.os.ZygoteInit")) {
      zygoteInitCallCount++;
      if(zygoteInitCallCount == 2) {
        Log.wtf("HookDetection", "Substrate is active on the device.");
      }
    }
    if(stackTraceElement.getClassName().equals("com.saurik.substrate.MS$2") &&
        stackTraceElement.getMethodName().equals("invoked")) {
      Log.wtf("HookDetection", "A method on the stack trace has been hooked using Substrate.");
    }
    if(stackTraceElement.getClassName().equals("de.robv.android.xposed.XposedBridge") &&
        stackTraceElement.getMethodName().equals("main")) {
      Log.wtf("HookDetection", "Xposed is active on the device.");
    }
    if(stackTraceElement.getClassName().equals("de.robv.android.xposed.XposedBridge") &&
        stackTraceElement.getMethodName().equals("handleHookedMethod")) {
      Log.wtf("HookDetection", "A method on the stack trace has been hooked using Xposed.");
    }

  }
}
```

###### Detecting Native Hooks

By using ELF binaries, native function hooks can be installed by overwriting function pointers in memory (e.g., Global Offset Table or PLT hooking) or patching parts of the function code itself (inline hooking). Checking the integrity of the respective memory regions is one way to detect this kind of hook.

The Global Offset Table (GOT) is used to resolve library functions. During run time, the dynamic linker patches this table with the absolute addresses of global symbols. *GOT hooks* overwrite the stored function addresses and redirect legitimate function calls to adversary-controlled code. This type of hook can be detected by enumerating the process memory map and verifying that each GOT entry points to a legitimately loaded library.

In contrast to GNU `ld`, which resolves symbol addresses only after they are needed for the first time (lazy binding), the Android linker resolves all external functions and writes the respective GOT entries immediately after a library is loaded (immediate binding). You can therefore expect all GOT entries to point to valid memory locations in the code sections of their respective libraries during run time. GOT hook detection methods usually walk the GOT and verify this.

*Inline hooks* work by overwriting a few instructions at the beginning or end of the function code. During run time, this so-called trampoline redirects execution to the injected code. You can detect inline hooks by inspecting the prologues and epilogues of library functions for suspect instructions, such as far jumps to locations outside the library.

#### Bypass and Effectiveness Assessment

Make sure that all file-based detection of reverse engineering tools is disabled. Then, inject code by using Xposed, Frida, and Substrate, and attempt to install native hooks and Java method hooks. The app should detect the "hostile" code in its memory and respond accordingly.

Work on bypassing the checks with the following techniques:

1. Patch the integrity checks. Disable the unwanted behavior by overwriting the respective byte-code or native code with NOP instructions.
2. Use Frida or Xposed to hook the APIs used for detection and return fake values.

Refer to the "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)" chapter for examples of patching, code injection, and kernel modules.

### 测试 代码混淆 (MSTG-RESILIENCE-9)

#### 概述

混淆处理 是转换代码和数据使其更难被反编译理解的过程. 他是每一个软件保护方案的集成组成部分. 关键理解的是混淆不是一种能简单开启或者关闭的功能. 程序可以变得部分或者全部难以反被编译.

在这个测试案例中, 我们将描叙一些基础的 混淆技术 被常用语 Android 应用当中.

#### 有效性 评估

尝试反编译字节代码, 拆解所有库中的文件, 并执行静态分析. 至少, 应用的核功能 (i.e., 需要被混淆的功能) 不应该轻易的辨识. 验证

- 有意义的标识符, 比如, 类名, 方法名, 变量名,
- 字符串资源 和 二进制字符串 应该被加密,
- 与受保护功能相关的代码和数据应该被加密, 打包或者其他方式隐藏.

要进行更详细的评估，您需要详细了解相关威胁和使用混淆处理的方法。

工具: 
- ProGuard
- DashO Android & Java Obfuscator

(reference:https://www.owasp.org/index.php/Bytecode_obfuscation)

### 测试 设备绑定 (MSTG-RESILIENCE-10)

#### Overview

The goal of device binding is to impede an attacker who tries to both copy an app and its state from device A to device B and continue executing the app on device B. After device A has been determined trustworthy, it may have more privileges than device B. These differential privileges should not change when an app is copied from device A to device B.

Before we describe the usable identifiers, let's quickly discuss how they can be used for binding. There are three methods that allow device binding:

- Augmenting the credentials used for authentication with device identifiers. This make sense if the application needs to re-authenticate itself and/or the user frequently.

- Encrypting the data stored in the device with the key material which is strongly bound to the device can strengthen the device binding. The Android Keystore offers non-exportable private keys which we can use for this. When a malicious actor would then extract the data from a device, he would not have access to the key to decrypt the encrypted data. Implementing this, takes the following steps:

  - Generate the key pair in the Android Keystore using `KeyGenParameterSpec` API.

    ```java
    //Source: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html>
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
    keyPairGenerator.initialize(
            new KeyGenParameterSpec.Builder(
                    "key1",
                    KeyProperties.PURPOSE_DECRYPT)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .build());
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
    ...

    // The key pair can also be obtained from the Android Keystore any time as follows:
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);
    PrivateKey privateKey = (PrivateKey) keyStore.getKey("key1", null);
    PublicKey publicKey = keyStore.getCertificate("key1").getPublicKey();
    ```

  - Generating a secret key for AES-GCM:
  
    ```java
    //Source: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html>
    KeyGenerator keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
    keyGenerator.init(
            new KeyGenParameterSpec.Builder("key2",
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build());
    SecretKey key = keyGenerator.generateKey();

    // The key can also be obtained from the Android Keystore any time as follows:
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);
    key = (SecretKey) keyStore.getKey("key2", null);
    ```

  - Encrypt the authentication data and other sensitive data stored by the application using a secret key through AES-GCM cipher and use device specific parameters such as Instance ID, etc. as associated data:
  
    ```java
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    final byte[] nonce = new byte[GCM_NONCE_LENGTH];
    random.nextBytes(nonce);
    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
    cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    byte[] aad = "<deviceidentifierhere>".getBytes();;
    cipher.updateAAD(aad);
    cipher.init(Cipher.ENCRYPT_MODE, key);

    //use the cipher to encrypt the authentication data see 0x50e for more details.
    ```

  - Encrypt the secret key using the public key stored in Android Keystore and store the encrypted secret key in the private storage of the application.
  - Whenever authentication data such as access tokens or other sensitive data is required, decrypt the secret key using private key stored in Android Keystore and then use the decrypted secret key to decrypt the ciphertext.

- Use token-based device authentication (Instance ID) to make sure that the same instance of the app is used.

#### Static Analysis

In the past, Android developers often relied on the `Settings.Secure.ANDROID_ID` (SSAID) and MAC addresses. This [changed with the release of Android 8.0 (API level 26)](https://android-developers.googleblog.com/2017/04/changes-to-device-identifiers-in.html "Changes in the Android device identifiers"). As the MAC address is now often randomized when not connected to an access point and the SSAID is no longer a device bound ID. Instead, it became a value bound to the user, the device and the app signing key of the application which requests the SSAID.
In addition, there are new [recommendations for identifiers](https://developer.android.com/training/articles/user-data-ids.html "Developer Android documentation - User data IDs") in Google's SDK documentation. Basically, Google recommends to:

- use the Advertising ID (`AdvertisingIdClient.Info`) when it comes to advertising -so that the user has the option to decline.
- use the Instance ID (`FirebaseInstanceId`) for device identification.
- use the SSAID only for fraud detection and for sharing state between apps signed by the same developer.

Note that the Instance ID and the Advertising ID are not stable across device upgrades and device-resets. However, the Instance ID will at least allow to identify the current software installation on a device.

There are a few key terms you can look for when the source code is available:

- Unique identifiers that will no longer work:
  - `Build.SERIAL` without `Build.getSerial`
  - `htc.camera.sensor.front_SN` for HTC devices
  - `persist.service.bdroid.bdadd`
  - `Settings.Secure.bluetooth_address`, unless the system permission LOCAL_MAC_ADDRESS is enabled in the manifest
- `ANDROID_ID` used only as an identifier. This will influence the binding quality over time for older devices.
- The absence of Instance ID, `Build.SERIAL`, and the IMEI.

```java
  TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
  String IMEI = tm.getDeviceId();
```

- The creation of private keys in the `AndroidKeyStore` using the `KeyPairGeneratorSpec` or `KeyGenParameterSpec` APIs.

To be sure that the identifiers can be used, check `AndroidManifest.xml` for usage of the IMEI and `Build.Serial`. The file should contain the permission `<uses-permission android:name="android.permission.READ_PHONE_STATE"/>`.

> Apps for Android 8.0 (API level 26) will get the result "UNKNOWN" when they request `Build.Serial`.

#### Dynamic Analysis

There are several ways to test the application binding:

##### Dynamic Analysis with an Emulator

1. Run the application on an emulator.
2. Make sure you can raise the trust in the application instance (e.g., authenticate in the app).
3. Retrieve the data from the emulator according to the following steps:
   - SSH into your simulator via an ADB shell.
   - Execute `run-as <your app-id>`. Your app-id is the package described in the AndroidManifest.xml.
   - `chmod 777` the contents of cache and shared-preferences.
   - Exit the current user from the the app-id.
   - Copy the contents of `/data/data/<your appid>/cache` and `shared-preferences` to the SD card.
   - Use ADB or the DDMS to pull the contents.
4. Install the application on another emulator.
5. In the application's data folder, overwrite the data from step 3.
   - Copy the data from step 3 to the second emulator's SD card.
   - SSH into your simulator via an ADB shell.
   - Execute `run-as <your app-id>`. Your app-id is the package described in  `AndroidManifest.xml`.
   - `chmod 777` the folder's cache and shared-preferences.
   - Copy the older contents of the SD card `to /data/data/<your appid>/cache` and `shared-preferences`.
6. Can you continue in an authenticated state? If so, binding may not be working properly.

##### Google Instance ID

[Google Instance ID](https://developers.google.com/instance-id/ "Google Instance ID documentation") uses tokens to authenticate the running application instance. The moment the application is reset, uninstalled, etc., the Instance ID is reset, meaning that you'll have a new "instance" of the app.
Go through the following steps for Instance ID:

1. Configure your Instance ID for the given application in your Google Developer Console. This includes managing the PROJECT_ID.

2. Setup Google Play services. In the file `build.gradle`, add

    ```groovy
    apply plugin: 'com.android.application'
        ...

        dependencies {
            compile 'com.google.android.gms:play-services-gcm:10.2.4'
        }
    ```

3. Get an Instance ID.

    ```java
    String iid = Instance ID.getInstance(context).getId();
    //now submit this iid to your server.
    ```

4. Generate a token.

    ```java
    String authorizedEntity = PROJECT_ID; // Project id from Google Developer Console
    String scope = "GCM"; // e.g. communicating using GCM, but you can use any
                        // URL-safe characters up to a maximum of 1000, or
                        // you can also leave it blank.
    String token = Instance ID.getInstance(context).getToken(authorizedEntity,scope);
    //now submit this token to the server.
    ```

5. Make sure that you can handle callbacks from Instance ID, in case of invalid device information, security issues, etc. This requires extending `Instance IDListenerService` and handling the callbacks there:

    ```java
    public class MyInstance IDService extends Instance IDListenerService {
    public void onTokenRefresh() {
        refreshAllTokens();
    }

    private void refreshAllTokens() {
        // assuming you have defined TokenList as
        // some generalized store for your tokens for the different scopes.
        // Please note that for application validation having just one token with one scopes can be enough.
        ArrayList<TokenList> tokenList = TokensList.get();
        Instance ID iid = Instance ID.getInstance(this);
        for(tokenItem : tokenList) {
        tokenItem.token =
            iid.getToken(tokenItem.authorizedEntity,tokenItem.scope,tokenItem.options);
        // send this tokenItem.token to your server
        }
    }
    };

    ```

6. Register the service in your Android manifest:

    ```xml
    <service android:name=".MyInstance IDService" android:exported="false">
    <intent-filter>
            <action android:name="com.google.android.gms.iid.Instance ID"/>
    </intent-filter>
    </service>
    ```

When you submit the Instance ID (iid) and the tokens to your server, you can use that server with the Instance ID Cloud Service to validate the tokens and the iid. When the iid or token seems invalid, you can trigger a safeguard procedure (e.g., informing the server of possible copying or security issues or removing the data from the app and asking for a re-registration).

Please note that [Firebase also supports Instance ID](https://firebase.google.com/docs/reference/android/com/google/firebase/iid/FirebaseInstanceId "Firebase Instance ID documentation").

##### IMEI & Serial

Google recommends not using these identifiers unless the application is at a high risk.

For Android devices before Android 8.0 (API level 26), you can request the serial as follows:

```java
   String serial = android.os.Build.SERIAL;
```

For devices running Android version O and later, you can request the device's serial as follows:

1. Set the permission in your Android manifest:

    ```xml
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    ```

2. Request the permission at run time from the user: See [https://developer.android.com/training/permissions/requesting.html](https://developer.android.com/training/permissions/requesting.html "Request App Permissions") for more details.
3. Get the serial:

    ```java
    String serial = android.os.Build.getSerial();
    ```

Retrieve the IMEI:

1. Set the required permission in your Android manifest:

    ```xml
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    ```

2. If you're using Android version Android 6 (API level 23) or later, request the permission at run time from the user: See [https://developer.android.com/training/permissions/requesting.html](https://developer.android.com/training/permissions/requesting.html "Request App Permissions") for more details.

3. Get the IMEI:

    ```java
    TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
    String IMEI = tm.getDeviceId();
    ```

##### SSAID

Google recommends not using these identifiers unless the application is at a high risk. You can retrieve the SSAID as follows:

```java
  String SSAID = Settings.Secure.ANDROID_ID;
```

The behavior of the SSAID and MAC addresses have [changed since Android 8.0 (API level 26)](https://android-developers.googleblog.com/2017/04/changes-to-device-identifiers-in.html "Changes in the Android device identifiers"). In addition, there are [new recommendations](https://developer.android.com/training/articles/user-data-ids.html "Developer Android documentation") for identifiers in Google's SDK documentation. Because of this new behavior, we recommend that developers not rely on the SSAID alone. The identifier has become less stable. For example, the SSAID may change after a factory reset or when the app is reinstalled after the upgrade to Android 8.0 (API level 26). There are devices that have the same `ANDROID_ID` and/or have an `ANDROID_ID` that can be overridden. Therefore it is better to encrypt the `ANDROID_ID` with a randomly generated key from the `AndroidKeyStore` using `AES_GCM` encryption. The encrypted `ANDROID_ID` should then be stored in the `SharedPreferences` (privately). The moment the app-signature changes, the application can check for a delta and register the new `ANDROID_ID`. The moment this changes without a new application signing key, it should indicate that something else is wrong.

#### Effectiveness Assessment

There are a few key terms you can look for when the source code is available:

- Unique identifiers that will no longer work:
  - `Build.SERIAL` without `Build.getSerial`
  - `htc.camera.sensor.front_SN` for HTC devices
  - `persist.service.bdroid.bdadd`
  - `Settings.Secure.bluetooth_address` or `WifiInfo.getMacAddress` from `WifiManager`, unless the system permission `LOCAL_MAC_ADDRESS` is enabled in the manifest.

- Usage of ANDROID_ID as an identifier only. Over time, this will influence the binding quality on older devices.
- The absence of Instance ID, `Build.SERIAL`, and the IMEI.

```java
  TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
  String IMEI = tm.getDeviceId();
```

To make sure that the identifiers can be used, check `AndroidManifest.xml` for usage of the IMEI and `Build.Serial`. The manifest should contain the permission `<uses-permission android:name="android.permission.READ_PHONE_STATE"/>`.

There are a few ways to test device binding dynamically:

##### Using an Emulator

See section "[Dynamic Analysis with an Emulator](#dynamic-analysis-with-an-emulator "Dynamic Analysis with an Emulator")" above.

##### Using two different rooted devices

1. Run the application on your rooted device.
2. Make sure you can raise the trust (e.g., authenticate in the app) in the application instance.
3. Retrieve the data from the first rooted device.
4. Install the application on the second rooted device.
5. In the application's data folder, overwrite the data from step 3.
6. Can you continue in an authenticated state? If so, binding may not be working properly.

### References

#### OWASP Mobile Top 10 2016

- M9 - Reverse Engineering - <https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering>

#### OWASP MASVS

- MSTG-RESILIENCE-1: "The app detects, and responds to, the presence of a rooted or jailbroken device either by alerting the user or terminating the app."
- MSTG-RESILIENCE-2: "The app prevents debugging and/or detects, and responds to, a debugger being attached. All available debugging protocols must be covered."
- MSTG-RESILIENCE-3: "The app detects, and responds to, tampering with executable files and critical data within its own sandbox."
- MSTG-RESILIENCE-4: "The app detects, and responds to, the presence of widely used reverse engineering tools and frameworks on the device."
- MSTG-RESILIENCE-5: "The app detects, and responds to, being run in an emulator."
- MSTG-RESILIENCE-6: "The app detects, and responds to, tampering the code and data in its own memory space."
- MSTG-RESILIENCE-9: "Obfuscation is applied to programmatic defenses, which in turn impede de-obfuscation via dynamic analysis."
- MSTG-RESILIENCE-10: "The app implements a 'device binding' functionality using a device fingerprint derived from multiple properties unique to the device."

#### SafetyNet Attestation

- Developer Guideline - <https://developer.android.com/training/safetynet/attestation.html>
- SafetyNet Attestation Checklist - <https://developer.android.com/training/safetynet/attestation-checklist>
- Do's & Don'ts of SafetyNet Attestation - <https://android-developers.googleblog.com/2017/11/10-things-you-might-be-doing-wrong-when.html>
- SafetyNet Verification Samples - <https://github.com/googlesamples/android-play-safetynet/>
- SafetyNet Attestation API - Quota Request - <https://support.google.com/googleplay/android-developer/contact/safetynetqr>

#### Tools

- adb - <https://developer.android.com/studio/command-line/adb>
- Frida  - <https://www.frida.re>
- DDMS - <https://developer.android.com/studio/profile/monitor>
