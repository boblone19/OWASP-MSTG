## 测试代码质量

移动应用程序开发人员使用各种编程语言和框架。 因此，当忽略安全编程实践时，常见漏洞（例如SQL注入，缓冲区溢出和跨站点脚本（XSS））可能会出现在应用程序中。

相同的编程漏洞可能在一定程度上影响Android和iOS应用程序，因此，我们将在指南的常规部分中概述最常见的漏洞类别。 在后面的部分中，我们将介绍特定于操作系统的实例并利用缓解功能。

### 注射缺陷 (MSTG-ARCH-2 and MSTG-PLATFORM-2)

*注入漏洞*描述了将用户输入插入后端查询或命令时发生的一类安全漏洞。 通过注入元字符，攻击者可以执行无意中将其解释为命令或查询一部分的恶意代码。 例如，通过操纵SQL查询，攻击者可以检索任意数据库记录或操纵后端数据库的内容。

此类漏洞在服务器端Web服务中最为普遍。 移动应用程序中也存在可利用的实例，但是这种情况很少见，而且攻击面更小。

例如，虽然应用程序可能查询本地SQLite数据库，但此类数据库通常不存储敏感数据（假设开发人员遵循基本的安全惯例）。 这使SQL注入成为不可行的攻击手段。 但是，有时会出现可利用的注入漏洞，这意味着正确的输入验证对于程序员是必要的最佳实践。

#### SQL注入

“ SQL注入”攻击涉及将SQL命令集成到输入数据中，模仿预定义SQL命令的语法。 成功的SQL注入攻击使攻击者可以读取或写入数据库，并可能执行管理命令，具体取决于服务器授予的权限。

Android和iOS上的应用程序都使用SQLite数据库来控制和组织本地数据存储。 假设Android应用通过将用户凭据存储在本地数据库中来处理本地用户身份验证（在本示例中，我们将忽略这种不良的编程习惯）。 登录后，该应用程序查询数据库以搜索包含用户输入的用户名和密码的记录：

```java
SQLiteDatabase db;

String sql = "SELECT * FROM users WHERE username = '" +  username + "' AND password = '" + password +"'";

Cursor c = db.rawQuery( sql, null );

return c.getCount() != 0;
```

让我们进一步假设攻击者在“用户名”和“密码”字段中输入以下值：

```sql
username = 1' or '1' = '1
password = 1' or '1' = '1
```

这将导致以下查询：

```sql
SELECT * FROM users WHERE username='1' OR '1' = '1' AND Password='1' OR '1' = '1'
```

因为条件'1'='1'始终计算为true，所以此查询返回数据库中的所有记录，即使没有输入有效的用户帐户，登录函数也将返回true。

Ostorlab利用了的sort参数[Yahoo的天气移动应用程序](https://blog.ostorlab.co/android-sql-contentProvider-sql-injections.html "Android, SQL and ContentProviders or Why SQL injections aren't dead yet ?") 使用此SQL注入有效负载的adb。

Mark Woods在运行于QNAP NAS存储设备上的“ Qnotes”和“ Qget” Android应用程序中发现了客户端SQL注入的另一个实际实例。 这些应用程序导出了容易受到SQL注入攻击的内容提供程序，从而使攻击者可以检索NAS设备的凭据。 有关此问题的详细说明，请参见[Nettitude博客](https://blog.nettitude.com/uk/qnap-android-dont-provide "Nettitude Blog - QNAP Android: Don't Over Provide").

#### XML注入

在 *XML注入* 攻击中，攻击者注入XML元字符以在结构上更改XML内容。 这可以用来破坏基于XML的应用程序或服务的逻辑，也可以允许攻击者利用XML解析器处理内容的操作。

此攻击的一个流行变种是[XML eXternal Entity（XXE）](https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing "XML eXternal Entity attack (XXE)"). 在这里，攻击者将包含URI的外部实体定义注入到输入XML中。 在解析期间，XML解析器通过访问URI指定的资源来扩展攻击者定义的实体。 解析应用程序的完整性最终决定了提供给攻击者的功能，恶意用户可以执行以下任何（或全部）操作：访问本地文件，触发对任意主机和端口的HTTP请求，启动[跨站点请求伪造 （CSRF）](https://goo.gl/UknMCj "Cross-Site Request Forgery (CSRF)") 攻击，并导致拒绝服务状况。 OWASP Web测试指南包含[XXE的以下示例](https://goo.gl/QGQkEX "Testing for XML Injection (OTG-INPVAL-008)"):

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>
```

在此示例中，打开了本地文件“ / dev / random”，并在其中返回了无尽的字节流，这有可能导致拒绝服务。

随着XML越来越不普遍，应用程序开发中的当前趋势主要集中在基于REST / JSON的服务上。 但是，在极少数情况下，使用用户提供的内容或其他不受信任的内容来构造XML查询时，可以由本地XML解析器（例如iOS上的NSXMLParser）解释。 这样，所述输入应该总是被验证并且元字符应该被转义。

#### 注入攻击向量

移动应用程序的攻击面与典型的Web和网络应用程序完全不同。移动应用程序并不经常在网络上公开服务，并且在应用程序用户界面上可行的攻击媒介很少见。对应用程序的注入攻击最有可能通过进程间通信（IPC）界面发生，恶意应用程序在该接口上攻击设备上运行的另一个应用程序。

查找潜在漏洞的方法之一是：

-确定不受信任的输入的可能入口点，然后从这些位置进行跟踪以查看目的地是否包含潜在的易受攻击的功能。
-识别已知的，危险的库/ API调用（例如SQL查询），然后检查未检查的输入是否成功与相应的查询进行了接口。

在手动安全审查期间，您应该结合使用两种技术。通常，不受信任的输入通过以下渠道进入移动应用程序：

- IPC通话
- 自定义网址方案
- QR码
- 通过蓝牙，NFC或其他方式接收的输入文件
- 粘贴板
- 用户界面

验证是否遵循以下最佳做法：

-使用可接受值的白名单对不可信输入进行类型检查和/或验证。
-执行数据库查询时，使用具有变量绑定的预准备语句（即参数化查询）。如果定义了准备好的语句，则用户提供的数据和SQL代码将自动分离。
-解析XML数据时，请确保将解析器应用程序配置为拒绝外部实体的解析，以防止XXE攻击。
-使用x509格式的证书数据时，请确保使用安全的解析器。例如，低于1.6版的Bouncy Castle允许通过不安全的反射进行远程代码执行。

我们将在特定于操作系统的测试指南中介绍与每个移动操作系统的输入源和潜在易受攻击的API相关的详细信息。

### 跨站点脚本缺陷 (MSTG-PLATFORM-2)

跨站点脚本（XSS）问题使攻击者可以将客户端脚本注入用户查看的网页中。 此类漏洞在Web应用程序中很普遍。 当用户在浏览器中查看注入的脚本时，攻击者可以获得绕过同一原始策略的能力，从而可以进行多种利用（例如，窃取会话Cookie，记录按键，执行任意操作等）。

在“本机应用程序”的上下文中，由于此类应用程序不依赖于Web浏览器的简单原因，XSS风险远不那么普遍。 但是，使用WebView组件（例如iOS上的“ WKWebView”或已弃用的“ UIWebView”和Android上的“ WebView”）的应用可能容易受到此类攻击。

一个较老但众所周知的例子是[Phil Purviance首次发现的iOS版Skype应用中的本地XSS问题](https://superevr.com/blog/2011/xss-in-skype-for-ios "XSS in Skype for iOS"). Skype应用程序未能正确编码消息发件人的名称，从而使攻击者可以在用户查看消息时注入恶意JavaScript来执行。 在概念验证中，Phil展示了如何利用此问题并窃取用户的通讯簿。

#### 静态分析

仔细查看存在的所有WebView，并调查该应用提供的不受信任的输入。

如果WebView打开的URL部分由用户输入确定，则可能存在XSS问题。 下面的XSS问题示例来自[LinusSärud报告的[Zoho Web服务](https://labs.detectify.com/2015/02/20/finding-an-xss-in-an-html-based-android-application/ "Finding an XSS in an HTML-based Android application").

Java

```java
webView.loadUrl("javascript:initialize(" + myNumber + ");");
```

Kotlin

```kotlin
webView.loadUrl("javascript:initialize($myNumber);")
```

由用户输入确定的XSS问题的另一个示例是公共重写方法。

Java

```java
@Override
public boolean shouldOverrideUrlLoading(WebView view, String url) {
  if (url.substring(0,6).equalsIgnoreCase("yourscheme:")) {
    // parse the URL object and execute functions
  }
}
```

Kotlin

```kotlin
    fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
        if (url.substring(0, 6).equals("yourscheme:", ignoreCase = true)) {
            // parse the URL object and execute functions
        }
    }
```

Sergey Bobrov 可以利用此优势 [HackerOne报告](https://hackerone.com/reports/189793 "[Android] XSS via start ContentActivity"). Quora的ActionBarContentActivity中将信任HTML参数的任何输入。 使用adb，通过ModalContentActivity的剪贴板数据以及来自第三方应用程序的Intents成功完成了有效负载。

- ADB

  ```shell
  $ adb shell
  $ am start -n com.quora.android/com.quora.android.ActionBarContentActivity \
  -e url 'http://test/test' -e html 'XSS<script>alert(123)</script>'
  ```

- Clipboard Data

  ```shell
  $ am start -n com.quora.android/com.quora.android.ModalContentActivity  \
  -e url 'http://test/test' -e html \
  '<script>alert(QuoraAndroid.getClipboardData());</script>'
  ```

- 3rd party Intent in Java or Kotlin:

  ```java
  Intent i = new Intent();
  i.setComponent(new ComponentName("com.quora.android",
  "com.quora.android.ActionBarContentActivity"));
  i.putExtra("url","http://test/test");
  i.putExtra("html","XSS PoC <script>alert(123)</script>");
  view.getContext().startActivity(i);
  ```

  ```kotlin
  val i = Intent()
  i.component = ComponentName("com.quora.android",
  "com.quora.android.ActionBarContentActivity")
  i.putExtra("url", "http://test/test")
  i.putExtra("html", "XSS PoC <script>alert(123)</script>")
  view.context.startActivity(i)
  ```

如果使用WebView来显示远程网站，则转义HTML的负担将转移到服务器端。 如果Web服务器上存在XSS漏洞，则可以使用它在WebView上下文中执行脚本。 因此，对Web应用程序源代码执行静态分析非常重要。

验证是否遵循以下最佳做法：

-除非绝对必要，否则不会在HTML，JavaScript或其他解释的上下文中呈现不受信任的数据。
-适当的编码应用于转义字符，例如HTML实体编码。 注意：当HTML嵌套在其他代码中时，例如，呈现位于JavaScript块内的URL，转义规则变得复杂。

考虑如何在响应中呈现数据。 例如，如果数据是在HTML上下文中呈现的，则必须转义六个控制字符：

| Character  | Escaped      |
| :-------------: |:-------------:|
| & | &amp;amp;|
| < | &amp;lt; |
| > | &amp;gt;|
| " | &amp;quot;|
| ' | &amp;#x27;|
| / | &amp;#x2F;|

有关转义规则和其他预防措施的完整列表，请参阅[OWASP XSS预防备忘单](https://goo.gl/motVKX "OWASP XSS Prevention Cheat Sheet").

#### 动态分析

可以使用手动和/或自动输入模糊测试来最好地检测XSS问题，即将HTML标签和特殊字符注入所有可用的输入字段中，以验证Web应用程序拒绝无效输入或在其输出中转义HTML元字符。

[反映的XSS攻击](https://goo.gl/eqqiHV "Testing for Reflected Cross site scripting (OTG-INPVAL-001)") 指通过恶意链接注入恶意代码的攻击。 为了测试这些攻击，自动输入模糊测试被认为是一种有效的方法。 例如，[BURP扫描仪](https://portswigger.net/burp/ "Burp Suite") 在识别反映的XSS漏洞方面非常有效。 与自动分析一样，请确保手动检查测试参数覆盖所有输入向量。

### 内存损坏错误 (MSTG-CODE-8)

内存损坏错误是黑客流行的中流main柱。此类错误是由于编程错误导致的，该错误导致程序访问意外的内存位置。在适当的条件下，攻击者可以利用此行为劫持易受攻击的程序的执行流并执行任意代码。此类漏洞通过多种方式发生：

- 缓冲区溢出：这描述了编程错误，其中应用程序为特定操作写入了超出分配的内存范围的内容。攻击者可以利用此漏洞覆盖位于相邻内存中的重要控制数据，例如函数指针。缓冲区溢出以前是最常见的内存损坏缺陷类型，但是由于许多因素，近年来它们的流行程度有所降低。值得注意的是，开发人员之间意识到使用不安全的C库函数的风险现在已成为常见的最佳实践，此外，捕获缓冲区溢出错误也相对简单。但是，仍然值得对这些缺陷进行测试。

- 越界访问：错误的指针算法可能导致指针或索引引用超出预期内存结构（例如缓冲区或列表）范围的位置。当应用尝试写入越界地址时，会发生崩溃或意外行为。如果攻击者可以控制目标偏移量并在一定程度上操纵写入的内容，则[可能执行代码执行漏洞](https://www.zerodayinitiative.com/advisories/ZDI-17-110/ "Adobe Flash Mediaplayer example").

- 悬空指针：当具有对内存位置的传入引用的对象被删除或释放，但对象指针未重置时，将发生这些情况。如果程序以后使用 *dangling*指针来调用已释放对象的虚函数，则可以通过覆盖原始vtable指针来劫持执行。或者，可以读取或写入对象变量或悬挂指针引用的其他存储结构。

- 释放后使用：这是指悬空指针引用已释放（释放）内存的特殊情况。清除内存地址后，所有引用该位置的指针都将变为无效，从而导致内存管理器将地址返回到可用内存池中。当最终重新分配此内存位置时，访问原始指针将读取或写入新分配的内存中包含的数据。这通常会导致数据损坏和不确定的行为，但是狡猾的攻击者可以设置适当的内存位置，以利用对指令指针的控制。

- 整数溢出：当算术运算的结果超过程序员定义的整数类型的最大值时，这将导致值“环绕”最大整数值，不可避免地会导致存储一个较小的值。相反，当算术运算的结果小于整数类型的最小值时，在结果大于预期的情况下会发生“整数下溢”。是否可以利用特定的整数溢出/下溢错误取决于整数的使用方式-例如，如果整数类型表示缓冲区的长度，则可能会产生缓冲区溢出漏洞。

- 格式字符串漏洞：当未经检查的用户输入传递给C函数`printf`系列的格式字符串参数时，攻击者可能会注入诸如'％c'和'％n'之类的格式令牌来访问内存。格式字符串错误由于具有灵活性而很容易利用。如果程序输出字符串格式化操作的结果，则攻击者可以任意对内存进行读写，从而绕过了ASLR等保护功能。

利用内存破坏的主要目的通常是将程序流重定向到攻击者放置了汇编程序指令的位置，这些指令称为 *shellcode*。在iOS上，数据执行保护功能（顾名思义）可防止从定义为数据段的内存中执行数据。为了绕过这种保护，攻击者利用面向返回的编程（ROP）。此过程涉及将文本段中的小块预先存在的代码块（“小工具”）链接在一起，这些小工具可以执行对攻击者有用的功能，或者调用“ mprotect”更改攻击者存储位置的内存保护设置 *shellcode*。

Android应用程序大多数情况下是用Java实现的，因此从本质上来说，它可以避免内存损坏问题。但是，利用JNI库的本机应用程序容易受到此类错误的影响。
同样，iOS应用程序可以将C / C ++调用包装在Obj-C或Swift中，从而使它们容易受到此类攻击。

#### 缓冲区和整数溢出

以下代码段显示了导致缓冲区溢出漏洞的条件的简单示例。

```c
 void copyData(char *userId) {  
    char  smallBuffer[10]; // size of 10  
    strcpy(smallBuffer, userId);
 }  
```

为了确定潜在的缓冲区溢出情况，请寻找不安全的字符串函数（“ strcpy”，“ strcat”，其他以“ str”前缀开头的函数等）的使用以及可能存在漏洞的编程构造，例如将用户输入复制到 大小缓冲区。 对于不安全的字符串函数，应将以下内容视为危险信号：

- `strcat`
- `strcpy`
- `strncat`
- `strlcat`
- `strncpy`
- `strlcpy`
- `sprintf`
- `snprintf`
- `gets`

另外，查找实现为“ for”或“ while”循环的复制操作实例，并验证长度检查是否正确执行。

验证是否遵循以下最佳做法：

- 将整数变量用于数组索引，缓冲区长度计算或任何其他对安全性要求较高的操作时，请验证是否使用了无符号整数类型并执行前提条件测试以防止整数包装的可能性。
- 该应用程序不使用不安全的字符串函数，例如`strcpy`，大多数其他以“ str”前缀，`sprint`，`vsprintf`，`gets`等开头的函数；
- 如果应用包含C ++代码，则使用ANSI C ++字符串类；
- 如果是`memcpy`，请确保检查目标缓冲区的大小至少与源缓冲区大小相等，并且两个缓冲区没有重叠。
- 用Objective-C编写的iOS应用使用NSString类。 iOS上的C应用程序应使用CFString（字符串的核心基础表示形式）。
- 不会将任何不受信任的数据连接到格式字符串中。

#### 静态分析

低级代码的静态代码分析是一个复杂的主题，可以轻松地填满自己的书。 自动化工具，例如 [RATS](https://code.google.com/archive/p/rough-auditing-tool-for-security/downloads "RATS - Rough auditing tool for security") 结合有限的人工检查工作，通常足以识别低垂的果实。 但是，内存损坏情况通常是由复杂的原因引起的。 例如，释放后使用的错误实际上可能是由于复杂的，违反直觉的竞态条件并未立即显现而导致的。 通常，通过动态分析或测试人员投入大量时间来深入了解该程序，从而发现了被忽视的代码缺陷的深层实例所导致的错误。

#### 动态分析

最好通过输入模糊检测来发现内存损坏错误：这是一种自动化的黑盒软件测试技术，该技术将格式错误的数据连续发送到应用程序以调查潜在的漏洞状况。在此过程中，将监视应用程序的故障和崩溃。如果发生崩溃，（至少对于安全测试人员而言）希望造成崩溃的条件揭示出可利用的安全漏洞。

模糊测试技术或脚本（通常称为“模糊器”）通常会以半正确的方式生成结构化输入的多个实例。本质上，生成的值或自变量至少部分地被目标应用程序接受，但还包含无效元素，从而可能触发输入处理缺陷和意外的程序行为。一个好的模糊器会暴露大量可能的程序执行路径（即高覆盖率输出）。输入要么从头开始生成（“基于生成”），要么从已知的有效输入数据变异（“基于突变”）派生。

有关模糊测试的更多信息，请参阅[OWASP Fuzzing Guide](https://www.owasp.org/index.php/Fuzzing "OWASP Fuzzing Guide").

### 参考文献

#### OWASP Mobile Top 10 2016

- M7 - Poor Code Quality - <https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality>

#### OWASP MASVS

- MSTG-ARCH-2: "Security controls are never enforced only on the client side, but on the respective remote endpoints."
- MSTG-PLATFORM-2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."
- MSTG-CODE-8: "In unmanaged code, memory is allocated, freed and used securely."

#### CWE

- CWE-20 - Improper Input Validation

#### XSS via start ContentActivity

- <https://hackerone.com/reports/189793>
