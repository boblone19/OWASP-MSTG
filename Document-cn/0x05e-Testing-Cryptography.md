## Android 加密 APIs 接口

在本章节中 "[Cryptography for Mobile Apps](0x04g-Testing-Cryptography.md)", 我们将介绍`普通密码学的最佳实践`和`常见的移动软件缺陷`（缺陷是因为通过使用不正确的加密方式导致的）. 在本章节当中, 我们将更加详细的介绍 Android's 加密 APIs 接口功能. 我们将展示如何在源代码中识别这些 API 的使用，以及如何解释配置信息。在进行代码检查的时候，确保与本指南中提到的加密参数最佳实践进行对比.

### 测试 密码标准算法的配置 (MSTG-CRYPTO-2, MSTG-CRYPTO-3 and MSTG-CRYPTO-4)

#### 概述

Android 加密 APIs 接口是基于 Java 加密机构 及(JCA). JCA 将接口和执行分开,这样可以使用多个可执行的加密算法 [security providers](https://developer.android.com/reference/java/security/Provider.html "Android Security Providers"). 大多数的 JCA 接口 和 Java类 都定义在以下两个包中. `java.security.*` 和 `javax.crypto.*` . 此外, 还有特定于 Android 软件包的 `android.security.*` 和 `android.security.keystore.*`.

不同的Android 版本和 OEM 厂商所提供的加密算法列表不同. 某些供应商执行了老版本的已经被定义为容易受到攻击的算法. 所以, Android 应用不仅仅是选择正确的算法和提供适当的配置,在某种情况下也应该注意执行加密机制的强度.

你可以列出现有的加密提供选如下:

```Java 案例
StringBuilder builder = new StringBuilder();
for (Provider provider : Security.getProviders()) {
    builder.append("provider: ")
            .append(provider.getName())
            .append(" ")
            .append(provider.getVersion())
            .append("(")
            .append(provider.getInfo())
            .append(")\n");
}
String providers = builder.toString();
//现在将字符串显示在屏幕上或日志中以供调试。
```

下面你可以参考一个基于Android 4.4 (API 版本 19) 在Google 模拟器中运行的输出结果, 此结果已经修复过安全加密补丁包:

```text
provider: GmsCore_OpenSSL1.0 (Android's OpenSSL-backed security provider)
provider: AndroidOpenSSL1.0 (Android's OpenSSL-backed security provider)
provider: DRLCertFactory1.0 (ASN.1, DER, PkiPath, PKCS7)
provider: BC1.49 (BouncyCastle Security Provider v1.49)
provider: Crypto1.0 (HARMONY (SHA1 digest; SecureRandom; SHA1withDSA signature))
provider: HarmonyJSSE1.0 (Harmony JSSE Provider)
provider: AndroidKeyStore1.0 (Android AndroidKeyStore security provider)
```

对于某些只支持老版本的 Android 的应用, (e.g.: 只使用低于 Android 7.0 (API 版本 24)), 绑定一个最新的库可能是唯一的选择. Spongy Castle (重新包装版本的 Bouncy Castle) 是这些情况下最常见的选择. 重新封包是必要的,因为 Bouncy Castle 被包含在 Android SDK. 最新版本的 [Spongy Castle](https://rtyley.github.io/spongycastle/ "Spongy Castle") 修复了早期版本中可能遇到的问题 [Bouncy Castle](https://www.cvedetails.com/vulnerability-list/vendor_id-7637/Bouncycastle.html "CVE Details Bouncy Castle") 并且包含在 Android 系统中. 注意, 绑定了Android 的 Bouncy Castle 库通常不来自于 [legion of the Bouncy Castle](https://www.bouncycastle.org/java.html "Bouncy Castle in Java"). 最后:请记住，打包像 Spongy Castle 这样的大型库通常会导致一个多目录的Android应用程序。

针对于现代 API 版本的应用,经历了以下变化:

- 从 Android 7.0 (API 版本 24) 或者更高版本 [the Android Developer blog shows that](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html "Security provider Crypto deprecated in Andorid N"):
  - 建议停止使用特定的安全供应方式, 相反, 总是使用一个已经打了补丁的安全供应方式.
  - 对 `Crypto` 的支持已经被取消,并且强烈不建议使用.
  - 不在支持通过 `SHA1PRNG` 实现随机数字, 而是提供了一个实时的 `OpenSSLRandom` 实例.
- 从 Android 8.1 (API 版本 27) 或者更高 [Developer Documentation](https://developer.android.com/about/versions/oreo/android-8.1 "Cryptography updates") 显示:
  - Conscrypt, 被称为 `AndroidOpenSSL`, 是首选使用 Bouncy Castle 和新的实现方式 : `AlgorithmParameters:GCM` , `KeyGenerator:AES`, `KeyGenerator:DESEDE`, `KeyGenerator:HMACMD5`, `KeyGenerator:HMACSHA1`, `KeyGenerator:HMACSHA224`, `KeyGenerator:HMACSHA256`, `KeyGenerator:HMACSHA384`, `KeyGenerator:HMACSHA512`, `SecretKeyFactory:DESEDE`, 和 `Signature:NONEWITHECDSA`.
  - 你应该不在对 GCM 继续使用 `IvParameterSpec.class` , 而是使用 `GCMParameterSpec.class` 来替代.
  - Sockets 已经由 `OpenSSLSocketImpl` 衍生到 `ConscryptFileDescriptorSocket`, 和 `ConscryptEngineSocket`.
  - `SSLSession` 使用 null 参数给出一个 NullPointerException。
  - 您需要有足够大的数组作为输入字节来生成密钥，否则将抛出 InvalidKeySpecException 错误。
  - 如果一个 Socket 读取被中断, 你会得到一个 `SocketException`.
- 基于 Android 9 (API level 28) 并且更高的版本 [Android Developer Blog](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html "Cryptography Changes in Android P") 显示出更激进的变化:
  - 如果你仍然使用 `getInstance` 方法来 并且你的 API 版本低于 28, 你讲得到一个警告消息. 如果你的 Android 9 (API 版本 28) 或者更高, 你将得到一个错误消息.
  - `Crypto` 提供方式已经被移除. 调用会最终出现 `NoSuchProviderException` 的结果.

Android SDK 提供了指定安全密钥生成 和使用的机制. Android 6.0 (API 版本 23) 引入 `KeyGenParameterSpec` 类, 此类可以确保应用程序中正确的使用密钥.

以下是一个基于API版本 23+ 使用 AES/CBC/PKCS7Padding 的实例:

```Java 实例
String keyAlias = "MySecretKey";

KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(keyAlias,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .setRandomizedEncryptionRequired(true)
        .build();

KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
        "AndroidKeyStore");
keyGenerator.init(keyGenParameterSpec);

SecretKey secretKey = keyGenerator.generateKey();
```

`KeyGenParameterSpec` 功能指定密钥可以用来加密 和 解密, 但是不能用作其他用途, 比如说签名 或者 校正. 而且更近一步的指定了block 模式 (CBC), padding (PKCS #7), 并明确指定随机加密的必要性. (机制是默认的). `"AndroidKeyStore"` 是加密服务提供者的名称. 这将自动确保密钥存储在 `AndroidKeyStore` 中,以利于密钥的保护.

GCM 是另一种 AES block 模式 与其他老的模式相比, 它提供了额外的安全优势. 除了加密方面更加安全意外, 它还提供了身份验证. 当使用CBC (和其他模式)的时候, 认证需要额外执行,通过使用 HMACs (具体参考 "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)" 章节). 注意 GCM 是唯一的AES 模式 [does not support paddings](https://developer.android.com/training/articles/keystore.html#SupportedCiphers "Supported Ciphers in AndroidKeyStore").

试图违反上述规范使用或生成的密钥,将导致安全异常错误。

下面是一个使用该密钥加密的例子:

```Java 实例
String AES_MODE = KeyProperties.KEY_ALGORITHM_AES
        + "/" + KeyProperties.BLOCK_MODE_CBC
        + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7;
KeyStore AndroidKeyStore = AndroidKeyStore.getInstance("AndroidKeyStore");

// byte[] input
Key key = AndroidKeyStore.getKey(keyAlias, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
cipher.init(Cipher.ENCRYPT_MODE, key);

byte[] encryptedBytes = cipher.doFinal(input);
byte[] iv = cipher.getIV();
// save both the IV and the encryptedBytes
```

 IV (initialization vector) 和加密字节两者都需要保存; 否则无法解密. 

下面演示密码文件如何被解密. `input` 是加密后的字节数组 和 `iv` 初始化矢量, 加密步骤如下:

```Java
// byte[] input
// byte[] iv
Key key = AndroidKeyStore.getKey(AES_KEY_ALIAS, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
IvParameterSpec params = new IvParameterSpec(iv);
cipher.init(Cipher.DECRYPT_MODE, key, params);

byte[] result = cipher.doFinal(input);
```

由于 IV 每次都是随机生成, 所以应该将其与密码文本 (`encryptedBytes`) 一起保存,以便以后对其进行解密操作. 

在 Android 6.0 (API 版本 23)之前, AES 密钥生成不被支持. 因此, 通过 `KeyPairGeneratorSpec` 许多执行方式通过使用 RSA 和 生成一个 公钥-私钥 密钥对用来做不对称加密 或者使用 `SecureRandom` 来生成 AES 密钥.

下面是一个利用 `KeyPairGenerator` 和 `KeyPairGeneratorSpec` 来创建 RSA 密钥对的实例:

```Java 实例
Date startDate = Calendar.getInstance().getTime();
Calendar endCalendar = Calendar.getInstance();
endCalendar.add(Calendar.YEAR, 1);
Date endDate = endCalendar.getTime();
KeyPairGeneratorSpec keyPairGeneratorSpec = new KeyPairGeneratorSpec.Builder(context)
        .setAlias(RSA_KEY_ALIAS)
        .setKeySize(4096)
        .setSubject(new X500Principal("CN=" + RSA_KEY_ALIAS))
        .setSerialNumber(BigInteger.ONE)
        .setStartDate(startDate)
        .setEndDate(endDate)
        .build();

KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",
        "AndroidKeyStore");
keyPairGenerator.initialize(keyPairGeneratorSpec);

KeyPair keyPair = keyPairGenerator.generateKeyPair();
```

此案例创建密钥大小为 4096比特 的RSA 密钥对.(i.e. 模数大小).

注意: 人们普遍错误的相信 NDK 应该用来隐藏加密操作和硬编码密钥生成. 然而, 使用这种机制并不有效. 攻击者仍然可以使用工具来查找所使用的机制, 并在内存当中转存密钥. 接下来, 控制流可以通过类似分析工具来分析: e.g. radare2 通过 Frida 的帮助来提取密钥, 详细请参考: r2frida (看章节 "[Disassembling Native Code](0x05c-Reverse-Engineering-and-Tampering.md#disassembling-native-code "Disassembling Native Code")", "[Memory Dump](0x05c-Reverse-Engineering-and-Tampering.md#memory-dump "Memory Dump")" 和 "[In-Memory Search](0x05c-Reverse-Engineering-and-Tampering.md#in-memory-search "In-Memory Search")" 在章节 "篡改 与 Android 逆向工程" 获取更多的细节). 从 Android 7.0 (API 版本 24) 更早, 私有 APIs 是不被准许使用的, 相反: 公用 APIs 被调用, 影响了隐藏它的有效性,相关描述参考 [Android Developers Blog](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html "Android changes for NDK developers")

#### 静态 分析

查找代码中密码参数的使用. 一些最常见使用的 类 和 接口 如下:

- `Cipher`
- `Mac`
- `MessageDigest`
- `Signature`
- `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- 还有另外一些存在于 `java.security.*` 和 `javax.crypto.*` 包中.

确保遵循了 "移动应用程序密码学" 章节中的最佳实践. 验证所有使用的密码算法的配置是否与以下最佳实践一致 [NIST](https://www.keylength.com/en/4/ "NIST recommendations - 2016") 和 [BSI](https://www.keylength.com/en/8/ "BSI recommendations - 2017"). 确保 `SHA1PRNG` 的算法不在使用, 因为它在密码上是不安全的.
最后, 确保密钥不是在本地代码中硬编码中, 并且在这个级别上没有使用不安全的机制.

### 测试 随机数生成 方法 (MSTG-CRYPTO-6)

#### 概述

密码学-加密需要安全的生成任意数字(PRNG). 标准 Java 类无法提供足够强度的任意数, 事实上,攻击者有猜到下一个任意数字的可能性, 最终使用此猜测结果来模拟其他用户或者访问铭感信息.

一般情况下, `SecureRandom` 应该被使用. 然而, 如果Android 版本低于 4.4 (API 版本 19), 额外的加固需要执行,为了绕过 Android 4.1-4.3 (API 版本 16-18) 中的故障, 细节参考: [failed to properly initialize the PRNG](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html "Some SecureRandom Thoughts").

大多数开发人员应该使用不带有任何参数的,默认的构造器来实例化 `SecureRandom` . 而其他的构造器用于更高级用途, 如果使用不当, 可能导致随机性和安全性的下降. PRNG 提供了默认 `SecureRandom` 使用 `/dev/urandom` 设备文件作为随机性数字的来源 [#nelenkov].

#### 静态 分析

识别所有关于随机生成数字的所有实例, 并且插在自定义或者已知不安全的 `java.util.Random` 类. 这个类生成相同的序列数字; 最终,导致数字的顺序可以被推测出来.

下面的样本源代码演示了一个弱的随机数字生成方式:

```Java 实例
import java.util.Random;
// ...

Random number = new Random(123L);
//...
for (int i = 0; i < 20; i++) {
  // 在 [0, 20] 中生成其他任意整数值
  int n = number.nextInt(21);
  System.out.println(n);
}
```

相反, 一种经过严格审核的算法应该被本领域中的专家考虑, 并且通过足够长度的种子,选择良好测试的实施方式.

识别所有 `SecureRandom` 中没有通过默认构造器创建的实例. 特定函数种子值会减少随机性. 推荐 [no-argument constructor of `SecureRandom`](https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers "Generation of Strong Random Numbers") 使用系统特定的函数种子值来生成一个 128-byte-long 任意数字.

一般来说, 如果 PRNG 没有被宣传成为加密安全性 (e.g. `java.util.Random`), 则有可能是统计 PRNG 并且不应该在敏感内容中使用.
Pseudo-任意数字生成器 [can produce predictable numbers](https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded "Proper seeding of SecureRandom") 如果生成器被知道,那么函数种子就能够被猜出. 对于生成 "足够安全的随机数字" , 128字节大小的函数种子是一个很好的起点.

以下源代码演示了一个安全的任意数字生成方式: 

```Java 实例
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
// ...

public static void main (String args[]) {
  SecureRandom number = new SecureRandom();
  // 生成 20 以内的任意整数 0..20
  for (int i = 0; i < 20; i++) {
    System.out.println(number.nextInt(21));
  }
}
```

#### 动态分析方式 (Dynamic Analysis)

一定攻击者知道应用使用了哪种 pseudo-任意数字生成器(PRNG), 它可以很轻易通过概念验证的方式来生成下一个随机数字.参考 [done for Java Random](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/ "Predicting the next Math.random() in Java"). 在非常弱的自定义随机生成器的情况下, 在使用非常弱的自定义任意数字方法的情况下,利用统计学可以观察到数字. 尽管推荐方法是远离反编译APK 文件和检查算法. (see Static Analysis).

如果你想测试你的任意数强度, 你可以尝试抓取大量的数字,通过 Burp's 工具 [sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer "Burp's Sequencer") 来查看任意数字的强度性.

### 测试密钥管理 (MSTG-STORAGE-1, MSTG-CRYPTO-1 and MSTG-CRYPTO-5)

#### 概览

在本章节中，我们将会讨论加密密钥存储的不同方式，以及如何测试它们的安全性。我们将从最安全的方法来讨论，衍生到不太安全的，生成和存储密钥的方法。

最安全的处理密钥的方式是'永远不要将它们存储在设备上'。这意味着用户每次都要通过输入密码提示的方式来实现加密操作。虽然从用户体验角度来说，这不是一种理想的实现方式，但是它是处理关键密钥的最安全的方法。其原因是密钥的信息在使用的时候，只会在内存中的数组中找到。一旦密钥不再被需要的情况下， 内存数组将归零。这样尽可能的降低了攻击窗口. 没有密钥关键资料接触文件系统，也不会存储任何密码。但是，值得注意的是，不是所有的密码算法正确的清理它们的字节组数。例如，在 BouncyCastle 中的AES 密码并不总是清理最新的工作密钥。接下来，以 BigInteger 为基础的密钥 (e.g. 私有密钥) 无法从堆（heap）或者清零来移除密钥。最后, 小心处理清理密钥的情况。请参考章节 "[Data Storage on Android](0x05d-Testing-Data-Storage.md)" 如何确保密钥相关内容被清零.

对称加密密钥可以通过使用基于密码的密钥衍生函数来实现(PBKDF2). 这种加密协议的目的是生成安全的，不可篡改的密钥。下面的代码案例演示了“如何根据密码生成更强的加密密钥。” 

```JAVA 语言
public static SecretKey generateStrongAESKey(char[] password, int keyLength)
{
    //对象 和 变量的初始化 提供后续的调用
    int iterationCount = 10000;
    int saltLength     = keyLength / 8;
    SecureRandom random = new SecureRandom();

    //生成 盐 对象
    byte[] salt = new byte[saltLength];
    random.nextBytes(salt);

    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
    return new SecretKeySpec(keyBytes, "AES");
}
```

上面的方法需要一组字符数组(byte[])，数组中包含了密码和所需要的密钥长度（以 ‘二进制’ 为长度）。例如，128 或者 256 位的AES密钥。我们通过PBKDF2算法，定义 10000 次的重复计数. 这个大大增加了暴力破解的攻击难度。我们定义了盐的大小长度，并且除以8来处理二进制到字节的转换。我们使用 `SecureRandom` 类来任意生成‘盐’对象。显然, 盐对象 将保持不变，以确保在每次密码替代的时候生成同样的加密密钥。值得注意是你可以通过 `SharedPreferences` 文件私密的存储‘盐’对象. 根据安全建议，盐对象应该被排出在Android备份机制中，来防止同步高风险的数据。获取更多的信息 "[Data Storage on Android](0x05d-Testing-Data-Storage.md)".
值得注意，如果你包括越狱设备，或者微打布丁的设备，或者补丁过的 (e.g. 重新打包) 应用视为堆数据的威胁, 那么最好使用 `AndroidKeystore` 中的密钥堆 盐对象进行加密. 然后，使用推荐的方法生成 以密码-为基础的加密密钥 (PBE) `PBKDF2WithHmacSHA1` 算法，支持版本从 Android 8.0 (API 等级 26). 在这个基础上, 最好使用 `PBKDF2withHmacSHA256`, 它将生成不同的密钥大小.

至此, 很明显的，经常提示用户输入密码并不适用于每个应用程序. 在这种情况下，请务必使用 [Android KeyStore API](https://developer.android.com/reference/java/security/KeyStore.html "Android AndroidKeyStore API"). 此 API 是专门为密钥素材提供安全存储而开发的。只有你的应用程序恶意访问自身的密钥。从 Android 6.0 (API 等级23)开始，AndroidKeyStore 被强制提供硬件支持，以防止指纹传感器的出现。 这意味着一个专属的加密芯片 或者 守信平台模块(TPM)将会用来保护密钥素材。

但是, 值得注意的是 `AndroidKeyStore` 的API在不同Android版本中发生来很大的变化。在早期的版本中, `AndroidKeyStore` API 只支持存储公共密钥/私有密钥/密钥对(e.g., RSA). 对称密钥从Android 6.0(API level 23)开始添加来支持. 因此，开发人员需要额外注意，通过不同Android API版本来实现对称密钥的安全存储。

为了在 Android 5.1 (API 版本 22) 或者更低的版本上实现安全存储 对称密钥，我们需要生成一个公密钥/私钥的密钥对. 我们使用公钥来加密对称密钥并且把私钥存储在文件 `AndroidKeyStore`中. 已经加密的对称密钥安全的存储在 `SharedPreferences`. 当我们需要对称密钥的时候，应用程序通过 `AndroidKeyStore` 中的私钥来解密对称密钥。

当密钥生成并且使用在 `AndroidKeyStore` 和 `KeyInfo.isinsideSecureHardware` 中，我们可以通过返回值 `true` 来确认, 由此我们可以判断，我们不能通过密钥dump的方式，或者监控加密操作过程来获取。 最终什么方式更加安全还具有争议: 使用 `PBKDF2withHmacSHA256` 生成密钥仍然可以通过可以访问内存中获取，或者使用 `AndroidKeyStore` 密钥可能永远不会进入内存。在 Android 9 (API 版本 28) 中，我们看到了而外的安全增强功能被实现，为了更好的把 TEE 从 `AndroidKeyStore` 区分， 这使得使用 `PBKDF2withHmacSHA256` 更加有利. 然而, 对于这个问题将来会进行更多的测试和调查。

#### 安全密钥导入到 Keystore

Android 9 (API 版本 28) 添加了导入安全密钥的能力，通过功能 `AndroidKeystore`. 首先 `AndroidKeystore` 通过 `PURPOSE_WRAP_KEY` 生成一对密钥，这对密钥的目的是为了保护导入到 `AndroidKeystore` 的密钥，并且通过认证证书被保护. 加密的密钥通过 `SecureKeyWrapper` 格式生成asn.1 编码消息，该格式还包含通过导入密钥的方式的描述。密钥在 特定设备的 `AndroidKeystore` 硬件中被解密，这样它们就不会以明文的形式出现在设备的主机内存当中。 

<img src="Images/Chapters/0x5e/Android9_secure_key_import_to_keystore.png" alt="Secure key import into Keystore" width="500">

```JAVA 案例
KeyDescription ::= SEQUENCE {
    keyFormat INTEGER,
    authorizationList AuthorizationList
}

SecureKeyWrapper ::= SEQUENCE {
    wrapperFormatVersion INTEGER,
    encryptedTransportKey OCTET_STRING,
    initializationVector OCTET_STRING,
    keyDescription KeyDescription,
    secureKey OCTET_STRING,
    tag OCTET_STRING
}
```

上面的代码给出了在以 SecureKeyWrapper 格式生成加密密钥时需要设置的不同参数。查看 Android 文档 [`WrappedKeyEntry`](https://developer.android.com/reference/android/security/keystore/WrappedKeyEntry "WrappedKeyEntry") 获取更多的消息.

定义密钥描述授权列表时，以下参数将影响加密密钥的安全性:

- `algorithm` 该参数指使用密钥的加密算法。
- `keySize` 该参数指密钥大小，并以bit为单位，通过常规的方式来侧拉密钥算法。
- `digest` 该参数特指完整性算法 - 及通过使用密钥来进行签名和验证操作。

#### 密钥认证 (Key Attestation)

对于依赖于 Android Keystore 来实现重要业务运作的应用, 比如说 通过加密原语的多因素认证, 安全存储在客户端的敏感数据, 等等. Android 提供一个功能 [Key Attestation](https://developer.android.com/training/articles/security-key-attestation "Key Attestation") 有助于分析通过Android Keystore 管理的加密材料的安全性. 从 Android 8.0 (API 版本 26), 密钥认证机制在所有新设备中被强制执行 (Android 7.0 或者更高), 这些设备通过使用由 [Google hardware attestation root certificate](https://developer.android.com/training/articles/security-key-attestation#root_certificate "Google Hardware Attestation Root Certificate") 密钥认证签名和密钥认证过程进行验证.

在 密钥认证过程中, 我们可以指定密钥对的别名, 作为回应,获得一个证书链, 我们可以使用他来验证密钥对的属性. 如果 根 证书链是 [Google Hardware Attestation Root certificate](https://developer.android.com/training/articles/security-key-attestation#root_certificate "Google Hardware Attestation Root certificate") 和检查在硬件中相关密钥存储机制,确保设备支持硬件级别的密钥认证,密钥在Google认为安全的密钥库中. 或者, 如果认证链有任何其他根证书, 那么谷歌不会对硬件安全性做出任何声明. 

虽然密钥认证过程可以通过应用程序直接实现,但是出于安全的考虑,建议在服务器端实现它. 以下是安全实施密钥证明的高级指南:

- 服务器必须触发密钥认证流程 - 通过创建任意数字安全的使用 CSPRNG(Cryptographically Secure Random Number Generator) 并且应将其作为质问发送给用户.
- 客户端应该调用 `setAttestationChallenge` 来自服务器端的质问 API 并且, 使用 `KeyStore.getCertificateChain` 方法来检索认证证书链.
- 认证响应应该发送到服务器进行验证,并应执行以下检查来验证密钥认证响应:
  - 验证证书链, 直到根证书的完整性检查,列如有效性,完整性,和可信赖性.
  - 检查是否是否使用Google 认证根密钥对证书进行签名,这样使得认证过程称为受信的. 
  - 提取认证证书的扩展数据, 一般显示在证书链的第一个元素中,并执行以下检查: 
    - 验证认证质问拥有与服务器初始化认证流程相同的值.
    - 验证密钥认证响应中的签名.
    - 再检查 Keymaster 的安全级别, 来确定设备是否存在安全密钥存储机制. Keymaster 是在安全上下文中运行,并且提供所有安全密钥库操作的软件. 安全级别将是 `Software`, `TrustedEnvironment` 或者 `StrongBox` 之一.
    - 此外, 你可以检查认证安全级别, 该级别将是软件 TrustedEnvironment 或 StrongBox 中一种, 以检查认证证书的生成方式. 另外, 可以进行一些其他与密钥相关的检查, 列如目的, 访问时间, 身份验证要求等, 以验证密钥的属性.

经典实例如下 - Android Keystore 认证响应:

```json
{
    "fmt": "android-key",
    "authData": "9569088f1ecee3232954035dbd10d7cae391305a2751b559bb8fd7cbb229bd...",
    "attStmt": {
        "alg": -7,
        "sig": "304402202ca7a8cfb6299c4a073e7e022c57082a46c657e9e53...",
        "x5c": [
            "308202ca30820270a003020102020101300a06082a8648ce3d040302308188310b30090603550406130...",
            "308202783082021ea00302010202021001300a06082a8648ce3d040302308198310b300906035504061...",
            "3082028b30820232a003020102020900a2059ed10e435b57300a06082a8648ce3d040302308198310b3..."
        ]
    }
}
```

在上述 JSON 代码段中, 密钥具有以下含义: 
        `fmt`: 认证格式标识符
        `authData`: 用来认证的认证者数据
        `alg`: 用于签名的算法
        `sig`: 签名
        `x5c`: 认证证书链

注意: `sig` 通过串联 `authData` 和 `clientDataHash` (服务器发送质询) 生成的, 并使用 `alg` 凭据私钥签名, 签名算法将和服务器端的第一个证书中使用公钥验证算法一样.

要进一步了解实施准则,可以参考. [Google Sample Code](https://github.com/googlesamples/android-key-attestation/blob/master/server/src/main/java/com/android/example/KeyAttestationExample.java "Google Sample Code For Android Key Attestation")

从安全分析的角度来看，安全分析师可以对密钥认证的安全实施进行以下检查：

- 检查密钥认证是否完全在客户端上执行. 在这种情况下, 可以通过篡改应用程序，挂钩方法等轻松地绕过它们。
- 检查服务器是否使用了任意数字质询. 假设没有做,将导致不安全的重放攻击. 另外, 执行 Challenge 的随机性安全检查.
- 检查服务器是否验证密钥认证响应的完整性.
- 检查服务器是否对证书链进行简单的完整性校正,受信验证, 有效性, 等等. 

#### 在解锁设备上 解密

为了提高安全性 Android 9 (API 版本 28) 引入了 `unlockedDeviceRequied` 标签. 通过将 `true` 传递给 `setUnlockedDeviceRequired` 方法, 该应用程序可以防止设备锁定时候对其存储在 `AndroidKeystore` 中的密钥进行解密, 并且要求在只准许将屏幕解锁后解密.

#### StrongBox 硬件安全模块

运行在 Android 9 (API 版本 28) 及更高版本的设备具有 `StrongBox Keymaster`, Keymaster HAL 的实现通过依赖于自己硬件安全模块中的CPU, 安全存储, 真正随机数生成器和防篡改机制. 使用这个机制, `true` 值必须传递给 `setIsStrongBoxBacked` 方法在任意 `KeyGenParameterSpec.Builder` 类或者 `KeyProtection.Builder` 类中, 每次生成或者导入密钥使用 `AndroidKeystore`. 为了确保 StrongBox 在使用时做实时监测, 方法 `isInsideSecureHardware` 必须返回 `true` 并且系统不会抛出 `StrongBoxUnavailableException` 错误, StrongBox Keymaster 对于指定算法和密钥管理大小不可用.

#### 密钥使用 授权

为了减少 Android 设备上未授权使用密钥, Android KeyStore 准许应用程序在生成或者导入密钥的时候使用指定密钥权限. 一定授权,就无法修改.

另外一个 API 供给 Android 使用的是 `KeyChain`, 提供在凭据存储中访问私钥和对应的证书链, 因为交互作用和对Keychian共享特性, 所以通常情况下不是用它. 请参考 [Developer Documentation](https://developer.android.com/reference/android/security/KeyChain "Keychain") 获取更多细节.

一种不太安全的存储加密密钥的方法,是保存在 Android 的 SharedPreferences 文件中. 在 [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences.html "Android SharedPreference API") 时 [MODE_PRIVATE](https://developer.android.com/reference/android/content/Context.html#MODE_PRIVATE "MODE_PRIVATE"), 只有创建该文件的应用程序才可以读取该文件. 但是, 在越狱的设备中,任何拥有 root 权限的应用能够读取 其他应用程序的 SharedPreference 文件, 不管是否使用了 `MODE_PRIVATE` . AndroidKeyStore 却并非如此. 由于 AndroidKeyStore 访问时在内核管理级别, 因此需要大量的工作和技术来绕过它, 无需 AndroidKeyStore 清除或销毁密钥. 

最后三个选项是在源代码中使用硬编码的加密密钥, 具有基于稳定属性的可预测的密钥派生功能，以及将生成的密钥存储在 `/sdcard/` 等公共场所. 显然, 硬编码的加密密钥方式不是推荐的方式. 这意味着应用程序的每个实例都使用相同的加密密钥. 攻击者只需做一次工作即可从源代码中提取密钥-无论是本地存储还是Java / Kotlin存储。 因此，他可以解密他获得的任何应用程序加密数据。

接下来，当您具有基于其他应用程序可访问的标识符的可预测密钥派生功能时，攻击者只需找到 KDF 并将其应用于设备即可找到密钥。 最后，强烈不建议公开存储加密密钥，因为其他应用程序可以读取公共分区并窃取密钥。

#### 静态 分析

在代码中找到加密 语言的使用。 一些最常用的 类 和 接口：

- `Cipher`
- `Mac`
- `MessageDigest`
- `Signature`
- `AndroidKeyStore`
- `Key`, `PrivateKey`, `PublicKey`, `SecretKeySpec`, `KeyInfo`
- And a few others in the `java.security.*` and `javax.crypto.*` packages.

作为实例,我们将演示怎样定位硬件编码加密密钥. 第一步,反编译 DEX 字节代码文件获取 使用Smali 字节代码文件的集合, 通过工具 ```[Baksmali](https://github.com/JesusFreke/smali)```.

```shell
$ baksmali d file.apk -o smali_output/
```

现在我们有了Smali 字节代码文件集合, 我们可以搜索文件中的 ```SecretKeySpec``` 类的用法. 我们只需要轮训的对获得的 Smali 源代码进行 grep 过滤扫描. 注意, Smali中的类描述符以 `L` 开头,以 `;`结尾:

```shell
$ grep -r "Ljavax\crypto\spec\SecretKeySpec;"
```

这将突出显示所有使用 `SecretKeySpec` 类, 我们现在检查所有标记显示的文件并跟踪哪些字节用于传递密钥材料. 下图显示了在生产就绪应用程序上执行此评估的结果。 为了便于阅读，我们将 DEX 字节码反向工程为Java代码。 我们可以清楚地找到在静态加密密钥 `Encrypt.keyBytes`.

![Use of a static encryption key in a production ready application.](Images/Chapters/0x5e/static_encryption_key.png).

当您有权访问源代码时，请至少检查以下内容：

- 检查用于存储密钥的机制：与所有其他解决方案相比，首选 `AndroidKeyStore`.
- Check if defense in depth mechanisms are used to ensure usage of a TEE. For instance: is temporal validity enforced? Is hardware security usage evaluated by the code? See the [KeyInfo documentation](https://developer.android.com/reference/android/security/keystore/KeyInfo "KeyInfo") for more details.
- In case of whitebox cryptography solutions: study their effectiveness or consult a specialist in that area.
- Take special care on verifying the purposes of the keys, for instance:
  - make sure that for asymmetric keys, the private key is exclusively used for signing and the public key is only used for encryption.
  - make sure that symmetric keys are not reused for multiple purposes. A new symmetric key should be generated if it's used in a different context.

#### 动态 分析

加密挂钩方法 和 分析被使用的密钥. 在执行加密操作时监视文件系统访问，以评估密钥文件的 写入 或 读取位置。

### 参考文献

- [#nelenkov] - N. Elenkov, Android 安全性内部, No Starch Press, 2014, Chapter 5.

#### 密码学参考

- Android Developer blog: Changes for NDK Developers - <https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html>
- Android Developer blog: Crypto Provider Deprecated - <https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html>
- Android Developer blog: Cryptography Changes in Android P - <https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html>
- Android Developer documentation - <https://developer.android.com/guide>
- BSI Recommendations - 2017 - <https://www.keylength.com/en/8/>
- Ida Pro - <https://www.hex-rays.com/products/ida/>
- Legion of the Bouncy Castle - <https://www.bouncycastle.org/java.html>
- NIST Key Length Recommendations - <https://www.keylength.com/en/4/>
- Security Providers -  <https://developer.android.com/reference/java/security/Provider.html>
- Spongy Castle  - <https://rtyley.github.io/spongycastle/>

#### SecureRandom 参考

- Burpproxy its Sequencer - <https://portswigger.net/burp/documentation/desktop/tools/sequencer>
- Proper Seeding of SecureRandom - <https://www.securecoding.cert.org/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded>

#### 测试密钥管理 参考

- Android Keychain API - <https://developer.android.com/reference/android/security/KeyChain>
- Android KeyStore API - <https://developer.android.com/reference/java/security/KeyStore.html>
- Android Keystore system - <https://developer.android.com/training/articles/keystore#java>
- Android Pie features and APIs - <https://developer.android.com/about/versions/pie/android-9.0#secure-key-import>
- KeyInfo Documentation - <https://developer.android.com/reference/android/security/keystore/KeyInfo>
- SharedPreferences - <https://developer.android.com/reference/android/content/SharedPreferences.html>

#### 密钥认证 参考

- Android Key Attestation - <https://developer.android.com/training/articles/security-key-attestation>
- Attestation and Assertion - <https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion>
- FIDO Alliance TechNotes - <https://fidoalliance.org/fido-technotes-the-truth-about-attestation/>
- FIDO Alliance Whitepaper - <https://fidoalliance.org/wp-content/uploads/Hardware-backed_Keystore_White_Paper_June2018.pdf>
- Google Sample Codes - <https://github.com/googlesamples/android-key-attestation/tree/master/server>
- Verifying Android Key Attestation - <https://medium.com/@herrjemand/webauthn-fido2-verifying-android-keystore-attestation-4a8835b33e9d>
- W3C Android Key Attestation - <https://www.w3.org/TR/webauthn/#android-key-attestation>

##### OWASP 移动 Top 10 2016

- M5 - 加密机制不足 - <https://www.owasp.org/index.php/Mobile_Top_10_2016-M5-Insufficient_Cryptography>

##### OWASP MASVS

- MSTG-STORAGE-1: "System credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys."
- MSTG-CRYPTO-1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption."
- MSTG-CRYPTO-2: "The app uses proven implementations of cryptographic primitives."
- MSTG-CRYPTO-3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices."
- MSTG-CRYPTO-4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes."
- MSTG-CRYPTO-5: "The app doesn't reuse the same cryptographic key for multiple purposes."
- MSTG-CRYPTO-6: "All random values are generated using a sufficiently secure random number generator."

##### CWE

- CWE-321 - Use of Hard-coded Cryptographic Key
- CWE-326 - Inadequate Encryption Strength
- CWE-330 - Use of Insufficiently Random Values
