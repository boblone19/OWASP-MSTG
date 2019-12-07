## 移动应用的加密

加密在保护用户数据方面发挥着特别重要的作用，尤其是在移动环境中，攻击者对用户设备进行物理访问可能是一种情况。本章概述了与移动应用相关的加密概念和最佳实践。这些最佳实践与移动操作系统无关。

### 关键概念

加密的目标是提供恒定的机密性、数据完整性和真实性，即使在面临攻击时也是如此。机密性包括使用加密确保数据隐私。数据完整性处理数据一致性和检测数据篡改和修改。真实性确保数据来自受信任的源。

加密算法将纯文本数据转换为隐藏原始内容的密文文本。纯文本数据可以通过解密从密码文本还原。加密可以是 [对称]（密钥加密）或 [非对称]（公钥加密）。通常，加密操作不保护完整性，但某些对称加密模式也具有这种保护功能。

**Symmetric-key encryption algorithms** 对加密和解密使用相同的密钥。这种类型的加密速度快，适合批量数据处理。由于有权访问密钥的每个人都能够解密加密的内容，因此此方法需要仔细的密钥管理。
**Public-key encryption algorithms** 使用两个单独的密钥运行：公钥和私钥。公钥可以自由分发，而私钥不应与任何人共享。使用公钥加密的邮件只能使用私钥解密。由于非对称加密比对称操作慢好几倍，它通常仅用于加密少量数据，例如用于批量加密的对称密钥。

**Hashing** 不是加密的一种形式，但它确实使用加密。哈希函数确定地将任意数据片段映射到固定长度的值。从输入中轻松计算哈希，但很难（即不可行）从哈希确定原始输入。哈希函数用于完整性验证，但不提供真实性保证。

**Message Authentication Codes** （MACs） 将其他加密机制（如对称加密或哈希）与密钥相结合，以提供完整性和真实性保护。但是，为了验证 MAC，多个实体必须共享同一个密钥，并且其中任何一个实体都可以生成有效的 MAC。HMACs 是最常用的 MAC 类型，它依赖于哈希作为基础加密基元。HMAC 算法的全名通常包括基础哈希函数的类型（例如，HMAC-SHA256 使用 SHA-256 哈希函数）。

**Signatures** 将非对称加密（即使用公钥/私钥对）与哈希相结合，通过使用私钥加密消息的哈希，提供完整性和真实性。但是，与 MC 不同，签名还提供不可否认属性，因为私钥应保持数据签名者的唯一。

**Key Derivation Functions**[密钥派生函数] （KDFs） 从机密值（如密码）派生密钥，用于将密钥转换为其他格式或增加其长度。KDF 类似于哈希函数，但也具有其他用途（例如，它们用作多方密钥协议协议的组件）。虽然哈希函数和 KDF 都必须难以反转，但 KDF 还有一个额外的要求，即它们生产的键必须具有随机性级别。

<br/>
<br/>
<br/>

### 识别不安全和/或已弃用的加密算法 (MSTG-CRYPTO-4)

评估移动应用时，应确保它不使用具有显著已知弱点或满足现代安全要求的加密算法和协议。过去被视为安全的算法可能会随着时间的推移变得不安全;因此，定期检查当前的最佳做法并相应地调整配置非常重要。

验证加密算法是否最新且符合行业标准。易受攻击的算法包括过时的块密码（如 DES 和 3DES）、流密码（如 RC4）、哈希函数（如 MD5 和 SHA1）和中断的随机数生成器（如Dual_EC_DRBG和 SHA1PRNG）。请注意，即使经过认证的算法（例如，由 NIST 认证）也会随着时间的推移变得不安全。认证不能取代对算法的健全性的定期验证。具有已知弱点的算法应替换为更安全的替代方法。

检查应用的源代码，以识别已知为弱的加密算法实例，例如：

- [DES, 3DES](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014")
- RC2
- RC4
- [BLOWFISH](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014")
- MD4
- MD5
- SHA1

加密 API 的名称取决于特定的移动平台。

请确保：

- 加密算法是最新的，符合行业标准。这包括（但不限于过时的块密码）、流密码（例如 RC4）以及哈希函数（例如 MD5）和Dual_EC_DRBG（即使它们经过 NIST 认证）的中断随机数生成器。所有这些应标记为不安全，并且不应使用和从应用程序和服务器中删除。
- 密钥长度符合行业标准，可为足够时间提供保护。考虑到摩尔定律，可以比较不同的密钥长度和保护[在线](https://www.keylength.com/ "Keylength comparison").
- 加密手段不会相互混合：例如，您不使用公钥签名，或尝试重用用于签名以执行加密的密钥对。
- 加密参数在合理范围内定义良好。这包括，但不限于：加密盐，它应该至少与哈希函数输出的长度相同，密码派生函数和迭代计数的合理选择（例如，PBKDF2，scrypt 或 bcrypt），IV 是随机和唯一的，适合用途的块加密模式（例如，不应使用 ECB，但特定情况除外）、密钥管理正确执行（例如 3DES 应具有三个独立密钥）等。

建议采用以下算法：

- 保密算法：AES-GCM-256 或 ChaCha20-Poly1305
- 完整性算法：SHA-256、SHA-384、SHA-512、布雷克2、SHA-3系列
- 数字签名算法：RSA（3072位及以上），ECDSA与NIST P-384
- 密钥建立算法：RSA（3072位及以上），DH（3072位或更高），ECDH与NIST P-384

此外，应始终依赖安全硬件（如果可用）来存储加密密钥、执行加密操作等。

有关算法选择和最佳实践的详细信息，请参阅以下资源：

- [商业国家安全算法套件和量子计算常见问题](https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf "Commercial National Security Algorithm Suite and Quantum Computing FAQ")
- [NIST 建议 (2016)](https://www.keylength.com/en/4/ "NIST recommendations")
- [BSI 建议 (2017)](https://www.keylength.com/en/8/ "BSI recommendations")

### 常见配置问题 (MSTG-CRYPTO-1, MSTG-CRYPTO-2 and MSTG-CRYPTO-3)

#### 密钥长度不足

即使最安全的加密算法也容易受到暴力攻击，当该算法使用的密钥大小不足时。

确保密钥长度符合 [公认行业标准](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014").

#### 具有硬编码加密密钥的对称加密

对称加密和密钥哈希 （MC） 的安全性取决于密钥的保密性。如果密钥被泄露，则加密获得的安全性将丢失。为了防止这种情况，切勿将密钥存储在与它们帮助创建的加密数据相同的位置。开发人员经常错误地使用静态硬编码加密密钥加密本地存储的数据，并将该密钥编译到应用程序中。这使得可以使用拆解器的任何人都可以访问密钥。

首先，确保源代码中未存储任何密钥或密码。这意味着您应该检查本机代码、JavaScript/Dart 代码、Android 上的 Java/Kotlin 代码以及 iOS 中的目标 C/Swift。请注意，即使源代码被混淆，硬编码的密钥也是有问题的，因为动态检测很容易绕过模糊处理。

如果应用使用双向 SSL（验证服务器和客户端证书），请确保：

1. 客户端证书的密码不会存储在本地或锁定在设备钥匙串中。
    2. 客户端证书并非在所有安装之间共享。

如果应用依赖于存储在应用数据中的其他加密容器，请检查加密密钥的使用方式。如果使用密钥包装方案，请确保为每个用户初始化主密钥，或者使用新密钥重新加密容器。如果可以使用主密码或以前的密码解密容器，请检查如何处理密码更改。

每当移动应用中使用对称加密时，密钥必须存储在安全设备存储中。有关特定于平台的 API 的详细信息，请参阅"[Android 上的数据存储](0x05d-Testing-Data-Storage.md)" 和 "[iOS 上的数据存储](0x06d-Testing-Data-Storage.md)" 章节。

#### 弱密钥生成函数

加密算法（如对称加密或某些 MAC）需要给定大小的秘密输入。例如，AES 使用正好为 16 字节的键。本机实现可能直接使用用户提供的密码作为输入密钥。使用用户提供的密码作为输入密钥存在以下问题：

- 如果密码小于密钥，则不使用完整的密钥空间。剩余空间是填充的（空间有时用于填充）。
- 用户提供的密码实际上主要由可显示和可发音的字符组成。因此，只使用了部分可能的 256 个 ASCII 字符，熵大约减少了 4 倍。

确保密码不会直接传递到加密功能中。相反，用户提供的密码应传递到 KDF 以创建加密密钥。使用密码派生函数时，请选择适当的迭代计数。例如，[NIST 建议和迭代计数至少为 10，000 的 PBKDF2](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5 "NIST Special Publication 800-63B").

#### 弱随机数生成器

在任何确定性设备上生成真正的随机数从根本上是不可能的。伪随机数生成器 （RNG） 通过生成伪随机数流来补偿这一点 - 数字流 [出现] ，就好像它们是随机生成的一样。生成的数字的质量因所使用的算法类型而异。[加密安全] RNG 生成通过统计随机性测试的随机数，并且对预测攻击具有弹性（例如，在统计上无法预测生成的下一个数字）。

移动 SDK 提供 RNG 算法的标准实现，这些算法可产生具有足够人工随机性的数字。我们将在 Android 和 iOS 特定部分中介绍可用的 API。

#### 加密的自定义实现

发明专有的加密函数既耗时又困难，而且很可能失败。相反，我们可以使用众所周知的算法，这些算法被广泛认为是安全的。移动操作系统提供实现这些算法的标准加密 API。

仔细检查源代码中使用的所有加密方法，尤其是直接应用于敏感数据的方法。所有加密操作都应为 Android 和 iOS 使用标准加密 API（我们将在特定于平台的章节中更详细地介绍这些 API）。应仔细检查任何不从已知提供程序调用标准例程的加密操作。密切注意已修改的标准算法。请记住，编码与加密不同！当您发现像 XOR（独占 OR）这样的位操作运算符时，始终进一步调查。

在所有加密实现中，您需要确保始终发生以下情况：

- 使用后，辅助键（如 AES/DES/Rijndael 中的中间键/派生密钥）从内存中正确删除。
- 应尽快从内存中删除密码的内部状态。

#### AES 配置不足

高级加密标准 （AES） 是移动应用中广泛接受的对称加密标准。它是一个迭代块密码，基于一系列链接的数学运算。AES 对输入执行可变数的回合数，每个回合都涉及输入块中字节的替代和排列。每舍使用从原始 AES 键派生的 128 位圆形键。

在撰写本文时，尚未发现针对 AES 的有效密码分析攻击。但是，实现详细信息和可配置参数（如块密码模式）会留下一些误差空间。

##### 弱块密码模式

基于块的加密在离散输入块上执行（例如，AES 具有 128 位块）。如果纯文本大于块大小，则纯文本在内部拆分为给定输入大小的块，并在每个块上执行加密。块密码的操作模式（或块模式）确定加密前一个块的结果是否会影响后续块。

[ECB (Electronic Codebook)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29 "Electronic Codebook (ECB)") 将输入划分为固定大小的块，这些块使用相同的密钥单独加密。如果多个分割的块包含相同的纯文本，它们将被加密为相同的密文块，这使得数据中的模式更易于识别。在某些情况下，攻击者可能还能够重播加密的数据。

![加密模式的差异](Images/Chapters/0x07c/EncryptionMode.png)

验证是否使用了密码块链接 （CBC） 模式，而不是 ECB。在 CBC 模式下，纯文本块与以前的密文块为 XORed。这可确保每个加密块都是唯一和随机的，即使块包含相同的信息。请注意，最好将 CBC 与 HMAC 结合，并且/或确保未给出任何错误，如"填充错误"、"MAC 错误"、"解密失败"等错误，以便对填充 oracle 攻击具有更强的抵抗力。

存储加密数据时，我们建议使用块模式，该模式还可以保护存储数据的完整性，例如 Galois/计数器模式 （GCM）。后者具有额外的好处，即算法对于每个 TLSv1.2 实现都是必填的，因此在所有现代平台上都可用。

F或有关有效块模式的更多信息，请参阅 [NIST 块模式选择指南](https://csrc.nist.gov/groups/ST/toolkit/BCM/modes_development.html "NIST Modes Development, Proposed Modes").

##### 可预测的初始化矢量

CBC、OFB、CFB、PCBC模式需要初始化向量（IV）作为密码的初始输入。IV不必保密，但不应该是可预测的。确保使用加密安全的随机数生成器生成 IV。有关 IV 的详细信息，请参阅 [加密失败的初始化向量文章](http://www.cryptofails.com/post/70059609995/crypto-noobs-1-initialization-vectors "Crypto Noobs #1: Initialization Vectors").

##### 有状态操作模式下的初始化矢量

请注意，使用 CTR 和 GCM 模式时，IV 的使用是不同的，其中初始化矢量通常是计数器（在 CTR 中与 nonce 结合）。因此，在这里使用可预测的 IV 和它自己的有状态模型正是需要的。在 CTR 中，您有一个新的 nonce 加计数器作为每个新块操作的输入。例如：对于 5120 位长的纯文本：您有 20 个块，因此需要 20 个输入矢量，由 nonce 和计数器组成。而在 GCM 中，每个加密操作都有一个 IV，不应使用相同的密钥重复。参见[NIST 关于 GCM 的文档]的第 8 节](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf "关于数据块密码操作模式的建议：Galois/计数器模式和GMAC，以了解有关IV的更多详细信息和建议。

#### 由于较弱的填充或块操作实现而导致的填充 Oracle 攻击

在旧时代， [PKCS1.5](https://tools.ietf.org/html/rfc2313 "PCKS1.5 in RFC2313") 填充（代码中："PKCS1Padding"）在进行非对称加密时用作填充机制。此机制容易受到填充的预言攻击。因此，最好使用 [PKCS_1 v2.0] 中捕获的 OAEP（最佳非对称加密填充）(https://tools.ietf.org/html/rfc2437 "PKCS1 v2.0 in RFC 2437") (in code: `OAEPPadding`, `OAEPwithSHA-256andMGF1Padding`, `OAEPwithSHA-224andMGF1Padding`, `OAEPwithSHA-384andMGF1Padding`, `OAEPwithSHA-512andMGF1Padding`). 请注意，即使使用 OAEP，您仍可能遇到一个最广为人知的问题，如 [在库德尔斯基安全博客中](https://research.kudelskisecurity.com/2018/04/05/breaking-rsa-oaep-with-mangers-attack/ "Kudelskisecurity").

注意：具有 PKCS #5的 AES-CBC 也显示容易受到填充 oracle 攻击，因为实现会发出警告，例如"填充错误"，"MAC 错误"或"解密失败"。。请参阅 [填充 Oracle 攻击](https://robertheaton.com/2013/07/29/padding-oracle-attack/ "The Padding Oracle Attack") and [The CBC Padding Oracle Problem](https://eklitzke.org/the-cbc-padding-oracle-problem "The CBC Padding Oracle Problem") 举一个例子。接下来，最好确保在加密纯文本后添加 HMAC：毕竟，具有失败 MAC 的密文不必解密，可以丢弃。

#### 保护内存中的密钥

当内存转储是威胁模型的一部分时，可以在密钥被主动使用时访问密钥。内存转储要么需要根访问（例如，根设备或越狱设备），要么需要使用 Frida 修补的应用程序（因此您可以使用 Fridump 等工具）。
因此，如果设备仍然需要密钥，则最好考虑以下事项：

- 确保所有加密操作和密钥本身都保留在受信任的执行环境（例如，使用 Android 密钥存储）或安全安全区（例如，使用钥匙串，当您签名时，请使用 ECDHE）。
- 如果需要密钥在 TEE / SE 之外，请确保混淆/加密它们，并且仅在使用过程中将其解模糊。无论是否使用本机代码，在释放内存之前始终将键归零。这意味着：覆盖内存结构（例如，取消数组），并知道 Android 中的大多数不可改变类型（如"BigInteger"和"String"）都保留在堆中。

注意：由于内存转储的便利性，除了用于签名验证或加密的公钥外，切勿在帐户和/或设备之间共享相同的密钥。

#### 保护传输中的密钥

当密钥需要从一个设备传输到另一个设备或从应用传输到后端时，请确保通过传输密钥对或其他机制实现适当的密钥保护。通常，密钥与模糊处理方法共享，这些方法很容易逆转。相反，请确保使用非对称加密或包装密钥。

### Android 和 iOS 上的加密 API

虽然相同的基本加密原则独立于特定的操作系统应用，但每个操作系统都提供自己的实现和 API。特定于平台的数据存储加密 API 在"[Android 上的数据存储]中进行了更详细的介绍。(0x05d-Testing-Data-Storage.md)" and "[Testing Data Storage on iOS](0x06d-Testing-Data-Storage.md)" 章。网络流量的加密，特别是传输层安全 （TLS），在"[安卓网络 API](0x05g-Testing-Network-Communication.md)" 章节.

### 加密策略

在大型组织中，或在创建高风险应用程序时，通常最好采用基于 [NIST 密钥管理建议]等框架的加密策略。(https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf "NIST 800-57 Rev4"). 当在应用加密时发现基本错误时，它可以是设置经验教训/加密密钥管理策略的良好起点。

#### 参考资料

##### 加密参考资料

- [PKCS #7: Cryptographic Message Syntax Version 1.5](https://tools.ietf.org/html/rfc2315 "PKCS #7")
- [Breaking RSA with Mangers Attack]( https://research.kudelskisecurity.com/2018/04/05/breaking-rsa-oaep-with-mangers-attack/ "Mangers attack")
- [NIST 800-38d](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf "NIST 800-38d")
- [NIST 800-57Rev4](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-4/final "NIST 800-57Rev4")
- [PKCS #1: RSA Encryption Version 1.5](https://tools.ietf.org/html/rfc2313 "PKCS #1: RSA Encryption Version 1.5")
- [PKCS #1: RSA Cryptography Specifications Version 2.0](https://tools.ietf.org/html/rfc2437 "PKCS #1: RSA Cryptography Specifications Version 2.0")
- [The Padding Oracle Attack](https://robertheaton.com/2013/07/29/padding-oracle-attack "The Padding Oracle Attack")
- [The CBC Padding Oracle Problem](https://eklitzke.org/the-cbc-padding-oracle-problem "The CBC Padding Oracle Problem")

##### OWASP 移动 Top 10 2016

- M5 - Insufficient Cryptography - <https://www.owasp.org/index.php/Mobile_Top_10_2016-M5-Insufficient_Cryptography>

##### OWASP MASVS

- MSTG-ARCH-8: "There is an explicit policy for how cryptographic keys (if any) are managed, and the lifecycle of cryptographic keys is enforced. Ideally, follow a key management standard such as NIST SP 800-57."
- MSTG-CRYPTO-1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption."
- MSTG-CRYPTO-2: "The app uses proven implementations of cryptographic primitives."
- MSTG-CRYPTO-3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices."
- MSTG-CRYPTO-4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes."

##### CWE

- CWE-326 - Inadequate Encryption Strength
- CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
- CWE-329 - Not Using a Random IV with CBC Mode
