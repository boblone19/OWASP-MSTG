# 移动应用身份验证体系结构

身份验证和授权问题是普遍存在的安全漏洞。 实际上，他们一直是世界上排名第二的 [OWASP Top 10](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project).

大多数移动应用程序都实现某种类型的用户身份验证。 即使身份验证和状态管理逻辑的一部分由后端服务执行，身份验证还是大多数移动应用程序体系结构的组成部分，因此了解其常见实现很重要。

由于iOS和Android的基本概念相同，因此在本通用指南中我们将讨论普遍的身份验证和授权架构以及陷阱。 特定于操作系统的身份验证问题，例如本地身份验证和生物特征认证，将在相应的特定于操作系统的章节中进行讨论。

## 测试身份验证的一般准则

没有一种万能的身份验证方法。在查看应用程序的身份验证体系结构时，您应该首先考虑在给定上下文中使用的身份验证方法是否合适。身份验证可以基于以下一项或多项：

* 用户知道的信息（密码，PIN码，图案等）
* 用户拥有的东西（SIM卡，一次性密码生成器或硬件令牌）
* 用户的生物识别属性（指纹，视网膜，语音）

移动应用程序执行的身份验证过程的数量取决于功能或所访问资源的敏感性。查看身份验证功能时，请参考行业最佳实践。通常认为，用户名/密码认证（结合合理的密码策略）对于具有用户登录名但不太敏感的应用程序就足够了。大多数社交媒体应用程序都使用这种身份验证形式。

对于敏感的应用程序，通常需要添加第二个身份验证因素。这包括可访问非常敏感的信息（例如信用卡号）或允许用户转移资金的应用。在某些行业中，这些应用还必须符合某些标准。例如，金融应用必须确保遵守支付卡行业数据安全标准（PCI DSS），《格莱姆·里奇·布利利法案》和《萨班斯-奥克斯利法案》（SOX）。美国医疗保健部门的合规性考虑因素包括《健康保险流通与责任法案》（HIPAA）和《患者安全规则》。

您也可以使用[OWASP Mobile AppSec验证标准](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x09-V4-Authentication_and_Session_Management_Requirements.md) 作为指导。 对于非关键应用程序（“级别1”），MASVS列出以下身份验证要求：

* 如果该应用为用户提供了访问远程服务的权限，则在远程端点执行可接受的身份验证形式，例如用户名/密码身份验证。
* 存在密码策略，并且该密码策略在远程端点上强制执行。
* 当错误的身份验证凭证提交过多次数时，远程端点实施指数补偿，或临时锁定用户帐户。

对于敏感应用程序（“级别2”），MASVS添加以下内容：

* 远程端点存在身份验证的第二个因素，并且始终执行2FA要求。
* 需要逐步验证才能启用处理敏感数据或事务的操作。
* 当他们登录时，该应用会通过其帐户通知用户最近的活动。

您可以在以下各节中找到有关如何测试上述要求的详细信息。

### 有状态与无状态认证

通常，您会发现移动应用程序使用HTTP作为传输层。 HTTP协议本身是无状态的，因此必须有一种将用户的后续HTTP请求与该用户相关联的方法-否则，必须随每个请求一起发送该用户的登录凭据。另外，服务器和客户端都需要跟踪用户数据（例如，用户的特权或角色）。这可以通过两种不同的方式完成：

-使用_状态_身份验证，当用户登录时会生成一个唯一的会话ID。在后续请求中，此会话ID用作对存储在服务器上的用户详细信息的引用。会话ID为_opaque_；它不包含任何用户数据。

-通过无状态认证，所有用户识别信息都存储在客户端令牌中。令牌可以传递到任何服务器或微服务，从而无需维护服务器上的会话状态。无状态身份验证通常会分解到授权服务器，授权服务器会在用户登录时生成，签名并可选地加密令牌。

Web应用程序通常将状态认证与存储在客户端Cookie中的随机会话ID一起使用。尽管移动应用程序有时会以类似方式使用状态会话，但是基于多种原因的无状态基于令牌的方法正变得越来越流行：

-通过消除将会话状态存储在服务器上的需要，它们提高了可伸缩性和性能。 -令牌使开发人员能够将身份验证与应用程序分离。令牌可以由身份验证服务器生成，并且身份验证方案可以无缝更改。

作为移动安全测试人员，您应该熟悉两种身份验证。

### 补充认证

认证方案有时通过[被动上下文认证](https://pdfs.semanticscholar.org/13aa/7bf53070ac8e209a84f6389bab58a1e2c888.pdf), 可以包含：

* 地理位置
* IP地址
* 一天中的时间
* 正在使用的设备

理想地，在这样的系统中，将用户的上下文与先前记录的数据进行比较，以识别可能指示帐户滥用或潜在欺诈的异常。 此过程对用户是透明的，但可以对攻击者起到强大的威慑作用。

## 验证适当的身份验证是否到位 \(MSTG-ARCH-2 and MSTG-AUTH-1\)

测试身份验证和授权时，请执行以下步骤：

-确定应用使用的其他身份验证因素。 -找到所有提供关键功能的端点。 -验证是否在所有服务器端端点上都严格执行了其他因素。

当在服务器上未一致地执行身份验证状态并且客户端可以篡改该状态时，将存在身份验证绕过漏洞。 当后端服务正在处理来自移动客户端的请求时，它必须一致地执行授权检查：每次请求资源时，验证用户是否已登录并获得授权。

考虑以下示例 [OWASP Web Testing Guide](https://www.owasp.org/index.php/Testing_for_Bypassing_Authentication_Schema_%28OTG-AUTHN-004%29). 在该示例中，通过URL访问Web资源，并通过GET参数传递身份验证状态：

```markup
http://www.site.com/page.asp?authenticated=no
```

客户端可以随意更改随请求发送的GET参数。 没有什么可以阻止客户端将“ authenticated”参数的值简单地更改为“ yes”，从而有效地绕过身份验证。

尽管这是一个简单的示例，您可能在野外找不到，但是程序员有时还是依靠“隐藏的”客户端参数（例如cookie）来维护身份验证状态。 他们认为这些参数不能被篡改。 例如，考虑以下[Nortel Contact Center Manager中的经典漏洞](http://seclists.org/bugtraq/2009/May/251). 北电设备的管理Web应用程序依靠cookie“ isAdmin”来确定是否应授予登录用户管理权限。 因此，可以通过简单地如下设置cookie值来获得管理员访问权限：

```markup
isAdmin=True
```

安全专家过去通常建议使用基于会话的身份验证，并仅在服务器上维护会话数据。 这样可以防止任何形式的客户端篡改会话状态。 但是，使用无状态身份验证而不是基于会话的身份验证的全部目的_是_在服务器上没有会话状态。 相反，状态存储在客户端令牌中，并随每个请求一起传输。 在这种情况下，看到客户端参数（例如“isAdmin”）是完全正常的。

为了防止篡改，将加密签名添加到客户端令牌。 当然，事情可能会出错，无状态身份验证的流行实现很容易受到攻击。 例如，可以通过\[将签名类型设置为“无”）停用某些JSON Web令牌（JWT）实现的签名验证。\([https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) "JSON Web令牌库中的严重漏洞”\). 我们将在“测试JSON Web令牌”一章中更详细地讨论这种攻击。

## 测试密码最佳实践 \(MSTG-AUTH-5 and MSTG-AUTH-6\)

当密码用于身份验证时，密码强度是一个关键问题。密码策略定义最终用户应遵守的要求。密码策略通常指定密码长度、密码复杂性和密码拓扑。"强"密码策略使手动或自动密码破解变得困难或不可能。以下各节将介绍有关密码最佳做法的各个领域。欲了解更多信息，请查阅[OWASP Authentication Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md#implement-proper-password-strength-controls).

### 静态分析

确认是否存在密码策略，并根据 [OWASP Authentication Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md#implement-proper-password-strength-controls) 侧重于长度和无限字符集。识别源代码中的所有与密码相关的功能，并确保在其中每个函数中执行验证检查。查看密码验证功能，并确保它拒绝违反密码策略的密码。

#### zxcvbn

[zxcvbn](https://github.com/dropbox/zxcvbn) 是一个公共库，可用于估计密码强度，灵感来自密码破解程序。它在 JavaScript 中可用，但也可用于服务器端的许多其他编程语言。有不同的安装方法，请检查 Github 存储库，了解您的首选方法。安装后，zxcvbn 可用于计算破解密码的复杂性和猜测量。

将 zxcvbn JavaScript 库添加到 HTML 页面后，您可以在浏览器控制台中执行命令"zxcvbn"，以获取有关破解密码（包括分数）的可能性的详细信息。

![A successful attack in Burp Suite](../.gitbook/assets/zxcvbn.png)

分数定义如下，可用于密码强度栏，例如：

```markup
0 # too guessable: risky password. (guesses < 10^3)

1 # very guessable: protection from throttled online attacks. (guesses < 10^6)

2 # somewhat guessable: protection from unthrottled online attacks. (guesses < 10^8)

3 # safely unguessable: moderate protection from offline slow-hash scenario. (guesses < 10^10)

4 # very unguessable: strong protection from offline slow-hash scenario. (guesses >= 10^10)
```

请注意，zxcvbn 可以由应用开发人员实现，也可以使用 Java（或其他）实现来引导用户创建强密码。

### Have I been pwned: PwnedPasswords

为了进一步降低针对单一因素身份验证方案（例如仅密码）成功攻击字典的可能性，您可以验证密码是否在数据泄露中泄露。这可以使用特洛伊亨特基于 Pwned 密码 API 的服务完成（可在api.pwnedpasswords.com中提供）。例如，"\[Have I been pwned?\]\([https://haveibeenpwned.com](https://haveibeenpwned.com) "';--have i been pwned?"\)" 配套网站。 根据可能的密码候选项的 SHA-1 哈希值，API 返回在服务收集的各种漏洞中找到给定密码哈希的次数。工作流执行以下步骤：

1. 将用户输入编码到 UTF-8（例如：密码"测试"）。
2. 取步骤 1 结果的 SHA-1 哈希值（例如："测试"的哈希值为"A94A8FE5CCB19BA61C4C0873D391E987982FBBD3"）。
3. 复制前 5 个字符（哈希前缀），并将它们用于范围搜索："http GET [https://api.pwnedpasswords.com/range/A94A8](https://api.pwnedpasswords.com/range/A94A8)"
4. 遍迭代结果并查找其余哈希值（例如，返回列表的"FE5CCB19BA61C4C0873D391E987982FBBD3"部分）。如果它不是返回列表的一部分，则找不到给定哈希的密码。否则，如"FE5CCB19BA61C4C0873D391E987982FBBD3"，它将返回一个计数器，显示在违规时发现的多少次（例如："FE5CCB19BA61CC4C0873D391E9997982BD3：76479"）。

有关密码 API 的进一步文档，可以 \[在线\] 找到\([https://haveibeenpwned.com/API/v3](https://haveibeenpwned.com/API/v3) "Api Docs V3"\).

请注意，当用户需要注册并输入密码以检查它是否为建议的密码时，应用开发人员最好使用此 API。

#### 登录限制

检查源代码，了解限制过程：在短时间内尝试使用给定用户名登录的计数器，以及一种在达到最大尝试次数后防止登录尝试的方法。授权登录尝试后，应重置错误计数器。

实施抗暴力控制时，请遵守以下最佳做法：

* 几次不成功的登录尝试后，目标帐户应锁定（临时或永久），并且应拒绝其他登录尝试。
* 五分钟的帐户锁定通常用于临时帐户锁定。
* 必须在服务器上实现控件，因为客户端控件很容易被绕过。
* 未经授权的登录尝试必须记录与目标帐户有关，而不是特定会话。

OWASP 页面上介绍了其他暴力缓解技术 [阻止暴力攻击](https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks).

### 动态测试 \(MSTG-AUTH-6\)

可以使用多种工具执行自动密码猜测攻击。对于 HTTP（S） 服务，使用拦截代理是一个可行的选项。例如，您可以使用 [Burp Suite Intruder](https://portswigger.net/burp/help/intruder_using.html) 执行基于单词列表的攻击和暴力攻击。

> 请记住，Burp Suite 社区版除了无法保存项目外，还有重大限制。例如，在几个请求之后，将激活限制机制，这将显著减慢使用 Burp 入侵者的攻击速度。此外，此版本中没有可用的内置密码列表。如果你想执行真正的暴力攻击，请使用Burp套房专业或OWASP ZAP。

对于基于单词列表的具有 Burp 入侵者的强力攻击，请执行以下步骤：

* 开始Burp Suite Professional。
* 创建新项目（或打开现有项目）。
* 将移动设备设置为将 Burp 用作 HTTP/HTTPS 代理。登录到移动应用并拦截发送到后端服务的身份验证请求。
* 在 **Proxy/HTTP History** 选项卡上右键单击此请求，并在上下文菜单中选择 **Send to Intruder**。
* 选择 **Intruder** 选项 卡. 有关如何使用的详细信息 [Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/using) 阅读官方关于Portswigger.
* 确保正确设置 **Target**, **Positions**, 和 **Options** 选项卡中的所有参数，然后选择 **Payload** 选项卡。
* 加载或粘贴要尝试的密码列表。提供密码列表的有多种可用资源，例如 [FuzzDB](https://github.com/fuzzdb-project/fuzzdb/), 在 Burp Intruder 中的内置列表文件也存在于 `/usr/share/wordlists` Kali Linux.

一旦一切配置，你选择了一个单词列表，你就可以开始攻击了！

![List of passwords in Burp Suite](../.gitbook/assets/burpintruderinputlist.png)

* 点击 **Start attack** 按钮来攻击身份验证。

将打开一个新窗口。站点请求按顺序发送，每个请求对应于列表中的密码。为每个请求提供有关响应的信息（长度、状态代码等），使您能够区分成功尝试和失败尝试：

![A successful attack in Burp Suite](../.gitbook/assets/burpintrudersuccessfulattack%20%281%29.png)

在此示例中，您可以根据不同的长度和 HTTP 状态代码（显示密码 12345）来标识成功尝试。

要测试您自己的测试帐户是否容易受到暴力攻击，请将测试帐户的正确密码追加到密码列表的末尾。该列表的密码不应超过 25 个。如果无需永久或临时锁定帐户或解决具有特定密码的请求后的 CAPTCHA 攻击，则意味着该帐户无法抵御暴力攻击。

> 提示：仅在渗透测试结束时执行此类测试。您不想在测试的第一天锁定您的帐户，并且可能必须等待帐户解锁。对于某些项目，解锁帐户可能比您想象的要困难得多。

## 测试有状态会话管理 \(MSTG-AUTH-2\)

有状态（或"基于会话"）身份验证的特点是客户端和服务器上的身份验证记录。身份验证流如下所示：

1. 应用将包含用户凭据的请求发送到后端服务器。
2. 服务器验证凭据 如果凭据有效，服务器将创建一个新会话以及一个随机会话 ID。
3. 服务器向客户端发送包含会话 ID 的响应。
4. 客户端发送会话 ID 以及所有后续请求。服务器验证会话 ID 并检索关联的会话记录。
5. 用户注销后，服务器端会话记录将销毁，客户端将丢弃会话 ID。

当会话管理不当时，它们容易受到各种攻击，这些攻击可能会危及合法用户的会话，从而允许攻击者模拟用户。这可能会导致数据丢失、机密性泄露和非法操作。

### 会话管理最佳实践

找到提供敏感信息或功能的任何服务器端端，并验证授权的一致性实施。后端服务必须验证用户的会话 ID 或令牌，并确保用户具有足够的权限来访问资源。如果会话 ID 或令牌丢失或无效，则必须拒绝请求。

确保：

* 会话 D 在服务器端随机生成。
* 无法轻易猜到这些 ID（使用适当的长度和熵）。
* 会话 ID 始终通过安全连接（例如 HTTPS）交换。
* 移动应用不会将会话 D 保存在永久存储中。
* 每当用户尝试访问特权应用程序元素时，服务器都会验证会话（会话 ID 必须有效，并且必须对应于正确的授权级别）。
* 会话在服务器端终止，会话信息在超时或用户注销后在移动应用中删除。

身份验证不应从头开始实现，而应该建立在经过验证的框架之上。许多流行的框架提供现成的身份验证和会话管理功能。如果应用使用框架 API 进行身份验证，请查看框架安全文档以了解最佳做法。通用框架的安全指南可在以下链接中找到：

* [Spring \(Java\)](https://projects.spring.io/spring-security)
* [Struts \(Java\)](https://struts.apache.org/security/)
* [Laravel \(PHP\)](https://laravel.com/docs/5.4/authentication)
* [Ruby on Rails](https://guides.rubyonrails.org/security.html)

OWASP Web 测试指南是测试服务器端身份验证的一大资源，特别是 [Testing Authentication](https://www.owasp.org/index.php/Testing_for_authentication) 和 [Testing Session Management](https://www.owasp.org/index.php/Testing_for_Session_Management) 章节.

## 测试会话超时 \(MSTG-AUTH-7\)

最小化会话标识符和令牌的生存期可降低帐户劫持成功的可能性。

### 静态分析

在大多数常用框架中，您可以通过配置选项设置会话超时。应根据框架文档中指定的最佳做法设置此参数。建议的超时时间可能在 10 分钟到两个小时之间，具体取决于应用的敏感度。有关会话超时配置的示例，请参阅框架文档：

* [Spring \(Java\)](https://docs.spring.io/spring-session/docs/current/reference/html5/)
* [Ruby on Rails](https://guides.rubyonrails.org/security.html#session-expiry)
* [PHP](https://php.net/manual/en/session.configuration.php#ini.session.gc-maxlifetime)
* [ASP.Net](https://goo.gl/qToQuL)

### 动态分析

要验证是否实现了会话超时，请通过拦截代理代理您的请求，并执行以下步骤：

1. 登录到应用程序。
2. 访问需要身份验证的资源，通常是对属于您的帐户的私人信息的请求。
3. 在超过 5 分钟的延迟（5、10、15 等）后，尝试访问数据。
4. 一旦资源不再可用，您将知道会话超时。

标识会话超时后，请验证它是否具有适合应用程序的长度。如果超时太长，或者超时不存在，则此测试用例失败。

> 使用 Burp 代理时，可以使用 [会话超时测试扩展](https://portswigger.net/bappstore/c4bfd29882974712a1d69c6d8f05874e) 自动执行此测试.

## 测试用户注销 \(MSTG-AUTH-4\)

此测试用例的目的是验证注销功能，并确定它是否有效地终止客户端和服务器上的会话，并使无状态令牌无效。

未能销毁服务器端会话是最常见的注销功能实现错误之一。此错误使会话或令牌保持活动状态，即使在用户注销应用程序后也是如此。获取有效身份验证信息的攻击者可以继续使用它并劫持用户帐户。

许多移动应用不会自动注销用户。可能有多种原因，例如：因为对客户不方便，或者由于在实现无状态身份验证时所做的决策。应用程序仍应具有注销功能，并且应根据最佳做法实现，销毁所有本地存储的令牌或会话标识符。如果会话信息存储在服务器上，则还应通过向该服务器发送注销请求来销毁该信息。如果是高风险应用程序，令牌应列入黑名单。不删除令牌或会话标识符可能会导致未经授权访问应用程序，以防令牌泄露。 请注意，其他敏感类型的信息也应被删除，因为任何未正确清除的信息可能会在以后泄露，例如在设备备份期间。

### 静态分析

如果服务器代码可用，请确保注销功能正确终止会话。此验证将取决于技术。以下是用于正确服务器端注销的会话终止的不同示例：

* [Spring \(Java\)](https://docs.spring.io/autorepo/docs/spring-security/4.1.x/apidocs/org/springframework/security/web/authentication/logout/SecurityContextLogoutHandler.html)
* [Ruby on Rails](https://guides.rubyonrails.org/security.html)
* [PHP](https://php.net/manual/en/function.session-destroy.php)

如果访问和刷新令牌与无状态身份验证一起使用，则应从移动设备中删除它们。[刷新令牌应在服务器上失效](https://auth0.com/blog/blacklist-json-web-token-api-keys/).

### 动态分析

使用拦截代理进行动态应用程序分析，并执行以下步骤来检查注销是否正确实现：

1. 登录到应用程序。
2. 访问需要身份验证的资源，通常是对属于您的帐户的私人信息的请求。
3. 注销应用程序。
4. 尝试通过从步骤 2 重新发送请求来再次访问数据。

如果在服务器上正确实现注销，则错误消息或重定向到登录页将发送回客户端。另一方面，如果您收到步骤 2 中相同的响应，则令牌或会话 ID 仍然有效，并且尚未在服务器上正确终止。 OWASP Web 测试指南 \([OTG-SESS-006](https://www.owasp.org/index.php/Testing_for_logout_functionality_%28OTG-SESS-006%29)\) 包括详细的解释和更多的测试用例。

## 测试双重身份验证和逐步身份验证 \(MSTG-AUTH-9 and MSTG-AUTH-10\)

双重身份验证 （2FA） 是允许用户访问敏感功能和数据的应用的标准配置。常见实现使用密码作为第一个因子，而以下任一因素用作第二个因子：

* 通过短信（SMS-OTP）输入一次性密码
* 通过电话拨打的一次性代码
* 硬件或软件令牌
* 将通知与 PKI 和本地身份验证结合使用

辅助身份验证可以在登录时执行，也可以在用户会话的更高版本中执行。例如，使用用户名和 PIN 登录到银行应用后，用户有权执行非敏感任务。用户尝试执行银行转账后，必须显示第二个因素（"逐步身份验证"）。

### 短信-OTP 的危险

尽管通过 SMS 发送的一次性密码 （OTP） 是双重身份验证的常见第二个因素，但此方法有其缺点。2016 年，NIST 建议："由于 SMS 消息可能被拦截或重定向的风险，新系统的实施者应仔细考虑其他身份验证器。下面您将找到一些相关威胁和建议的列表，以避免对 SMS-OTP 的成功攻击。

威胁：

* 无线拦截：攻击者可以通过滥用 femtocell 和电信网络中的其他已知漏洞来拦截 SMS 消息。
* 特洛伊木马：已安装的具有文本消息访问权限的恶意应用程序可能会将 OTP 转发到另一个号码或后端。
* SIM SWAP 攻击：在这次攻击中，攻击者呼叫电话公司或为他们工作，并将受害者的号码移动到攻击者拥有的 SIM 卡上。如果成功，攻击者可以看到发送到受害者电话号码的 SMS 消息。这包括双重身份验证中使用的消息。
* 验证码转发攻击：此社交工程攻击依赖于用户对提供 OTP 的公司的信任。在此攻击中，用户接收代码，然后被要求使用接收信息的相同方式中继该代码。
* 语音信箱：某些双重身份验证方案允许在 SMS 不再首选或不可用时通过电话呼叫发送 OTP。其中许多呼叫（如果未应答）会将信息发送到语音邮件。如果攻击者能够访问语音邮件，他们也可以使用 OTP 访问用户帐户。

在使用 SMS 进行 OTP 时，您可以找到以下几条降低利用的可能性的建议：

* **消息**：通过短信发送 OTP 时，请务必包含一条消息，让用户知道 1） 如果他们不请求代码 2） 您的公司绝不会呼叫或发短信要求他们中继其密码或代码。
* **专用通道**：当使用操作系统推送通知功能（iOS 上的 APN 和 Android 上的 FCM）时，OTP 可以安全地发送到注册的应用程序。与 SMS 相比，此信息无法被其他应用程序访问。或者，在 OTP 中，推送通知可能会触发一个弹出窗口来批准请求的访问。 
* **Entropy**：使用具有高熵的验证器，使OTP更难破解或猜测，并使用至少6位数字。确保数字在较小的组中是分开的，以防人们必须记住这些数字才能将其复制到你的应用。
* **避免语音邮件**：如果用户喜欢接听电话，请勿将 OTP 信息作为语音邮件保留。

### 使用推送通知和PKI进行 往来签名

实现第二个因素的另一个替代和强大机制是事务签名。

事务签名需要验证用户对关键事务的批准。非对称加密是实现事务签名的最佳方式。当用户注册时，应用将生成公共/私有密钥对，然后在后端注册公钥。私钥安全地存储在密钥商店 （安卓） 或钥匙串 （iOS） 中。要授权事务，后端向移动应用发送包含事务数据的推送通知。然后要求用户确认或拒绝事务。确认后，系统会提示用户解锁钥匙串（通过输入 PIN 或指纹），并且数据使用用户的私钥进行签名。然后，签名的事务将发送到服务器，服务器使用用户的公钥验证签名。

### 静态分析

有多种双重身份验证机制可供选择，从第三方库、外部应用程序的使用到开发人员的自我实现检查。这些机制都包括第三方库。

首先使用应用，并确定工作流中需要 2FA 的位置（通常在登录期间或执行关键事务时）。还要与开发人员和/或架构师面谈，以了解有关 2FA 实现的更多情况。如果使用第三方库或外部应用，请验证实现是否根据安全最佳实践进行了相应完成。

### 动态测试

广泛使用应用（遍历所有 UI 流），同时使用拦截代理捕获发送到远程终结点的请求。接下来，重播对需要 2FA（例如，执行财务事务）的终结点的请求，同时使用尚未通过 2FA 或升级身份验证提升的令牌或会话 ID。如果终结点仍在发送仅应在 2FA 或逐步身份验证后可用的请求数据，则该终结点尚未正确实施身份验证检查。

使用 OTP 身份验证时，请考虑大多数 OTP 都是短数值。如果在此阶段 N 次尝试失败后未锁定帐户，攻击者可以通过在 OTP 的生命周期内暴力强制范围内的值来绕过第二个因素。在 72 小时内查找具有 30 秒时间步长的 6 位值匹配的概率超过 90%。

为了测试这一点，在提供正确的 OTP 之前，捕获的请求应发送到具有随机 OTP 值的终结点 10-15 次。如果 OTP 仍然被接受，则 2FA 实现容易遭到暴力攻击，OTP 可以被猜到。

• OTP 的有效期应仅为一定时间（通常为 30 秒），在 OTP 中键入错误几次（通常为 3 次）后，提供的 OTP 应失效，用户应重定向到着陆页或注销。

咨询 [OWASP Testing Guide](https://www.owasp.org/index.php/Testing_for_Session_Management) 有关测试会话管理的详细信息。

## 测试无状态（基于令牌）身份验证 \(MSTG-AUTH-3\)

基于令牌的身份验证是通过向每个 HTTP 请求发送签名令牌（由服务器验证）来实现的。最常用的令牌格式是 JSON Web 令牌，在 [RFC7519](https://tools.ietf.org/html/rfc7519). JWT 可以将完整的会话状态编码为 JSON 对象。因此，服务器不必存储任何会话数据或身份验证信息。

JWT 标记由三个由点分隔的 Base64 编码部件组成。下面的示例显示 [Base64-encoded JSON Web Token](https://jwt.io/#debugger):

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

_header_ 通常由两个部分组成：令牌类型（即 JWT）和用于计算签名的哈希算法。在上面的示例中，标头解码如下：

```javascript
{"alg":"HS256","typ":"JWT"}
```

令牌的第二部分是 _payload_, 其中包含所谓的声明。声明是关于实体（通常是用户）和其他元数据的语句。例如：

```javascript
{"sub":"1234567890","name":"John Doe","admin":true}
```

通过将 JWT 标头中指定的算法应用于编码标头、编码的有效负载和机密值，可以创建签名。例如，使用 HMAC SHA256 算法时，签名以下列方式创建：

```java
HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)
```

请注意，密钥在身份验证服务器和后端服务之间共享 - 客户端不知道它。这证明令牌是从合法的身份验证服务中获得的。它还可防止客户端篡改令牌中包含的声明。

### 静态分析

标识服务器和客户端使用的 JWT 库。了解正在使用的 JWT 库是否有任何已知的漏洞。

验证实现是否符合 JWT [best practices](https://stormpath.com/blog/jwt-the-right-way):

* 验证是否检查了包含令牌的所有传入请求的 HMAC;
* 验证专用签名密钥或 HMAC 密钥的位置。密钥应保留在服务器上，并且不应与客户端共享。它应仅适用于颁发者和验证者。
* 验证 JWT 中未嵌入任何敏感数据（如个人身份信息）。如果由于某种原因，体系结构需要在令牌中传输此类信息，请确保应用有效负载加密。请参阅有关的示例 Java 实现 [OWASP JWT Cheat Sheet](https://goo.gl/TGzA5z).
* 确保使用"jti"（JWT ID）声明处理重播攻击，该声明为 JWT 提供了唯一的标识符。
* 验证令牌是否安全地存储在手机上，例如，钥匙串 （iOS） 或钥匙商店 （Android）。

#### 强制执行哈希算法

攻击者通过更改令牌来执行此规定，并使用"none"关键字更改签名算法以指示令牌的完整性已经过验证。如上链接所述，某些库将使用 none 算法签名的令牌视为具有已验证签名的有效令牌，因此应用程序将信任已更改的令牌声明。

例如，在 Java 应用程序中，在创建验证上下文时应显式请求预期的算法：

```java
// HMAC key - Block serialization and storage as String in JVM memory
private transient byte[] keyHMAC = ...;

//Create a verification context for the token requesting explicitly the use of the HMAC-256 HMAC generation

JWTVerifier verifier = JWT.require(Algorithm.HMAC256(keyHMAC)).build();

//Verify the token; if the verification fails then an exception is thrown

DecodedJWT decodedToken = verifier.verify(token);
```

#### 令牌过期

签名后，无状态身份验证令牌将永久有效，除非签名密钥发生更改。限制令牌有效性的常用方法是设置到期日期。确保令牌包含 ["exp" expiration claim](https://tools.ietf.org/html/rfc7519#section-4.1.4) 后端不处理过期的令牌。

授予令牌的常用方法组合 [access tokens and refresh tokens](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/). 当用户登录时，后端服务将发出短期的 \[访问令牌\] 和长期存在的 \[刷新令牌\]。然后，如果访问令牌过期，应用程序可以使用刷新令牌获取新的访问令牌。

对于处理敏感数据的应用，请确保刷新令牌在合理的时间段后过期。以下示例代码显示检查刷新令牌的颁发日期的刷新令牌 API。如果令牌不超过 14 天，将颁发新的访问令牌。否则，访问将被拒绝，并提示用户再次登录。

```java
 app.post('/renew_access_token', function (req, res) {
  // verify the existing refresh token
  var profile = jwt.verify(req.body.token, secret);

  // if refresh token is more than 14 days old, force login
  if (profile.original_iat - new Date() > 14) { // iat == issued at
    return res.send(401); // re-login
  }

  // check if the user still exists or if authorization hasn't been revoked
  if (!valid) return res.send(401); // re-logging

  // issue a new access token
  var renewed_access_token = jwt.sign(profile, secret, { expiresInMinutes: 60*5 });
  res.json({ token: renewed_access_token });
});
```

### 动态分析

在执行动态分析时调查以下 JWT 漏洞：

* 客户端上的令牌存储：
  * 对于使用 JWT 的移动应用，应验证令牌存储位置。
* 破解签名密钥：
  * 令牌签名通过服务器上的私钥创建。获取 JWT 后，选择一个工具 [brute forcing the secret key offline](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/).
* 信息披露：
  * 解码 Base64 编码的 JWT，并找出它传输的数据类型以及该数据是否加密。
* 篡改哈希算法：
  * 关于 [asymmetric algorithms](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) 的用法. JWT 提供了多个非对称算法，如 RSA 或 ECDSA。使用这些算法时，使用私钥对令牌进行签名，使用公钥进行验证。如果服务器希望使用非对称算法对令牌进行签名，并接收使用 HMAC 签名的令牌，它将将公钥视为 HMAC 密钥。然后，可以误用公钥，用作 HMAC 密钥来对令牌进行签名。
  * 修改令牌标头中的"alg"属性，然后删除"HS256"，将其设置为"无"，并使用空签名（例如，签名 ="）。"使用此令牌并在请求中重播它。某些库将使用 none 算法签名的令牌视为具有已验证签名的有效令牌。这允许攻击者创建自己的"签名"令牌。

有两种不同的 Burp 插件可以帮助您测试上面列出的漏洞：

* [JSON Web Token Attacker](https://portswigger.net/bappstore/82d6c60490b540369d6d5d01822bdf61)
* [JSON Web Tokens](https://portswigger.net/bappstore/f923cbf91698420890354c1d8958fee6)

此外，请确保查看 [OWASP JWT Cheat Sheet](https://goo.gl/TGzA5z) 有关其他信息。

## 测试 OAuth 2.0 流\(MSTG-AUTH-1 and MSTG-AUTH-3\)

[OAuth 2.0 定义一个委派协议，用于跨 API 和启用 Web 的应用程序网络传递授权决策](https://oauth.net/articles/authentication/). 它用于各种应用程序，包括用户身份验证应用程序。

OAuth2 的常见用途包括：

* 获得用户使用其帐户访问在线服务的权限。
* 代表用户对在线服务进行身份验证。
* 处理身份验证错误。

根据 OAuth 2.0，寻求访问用户资源的移动客户端必须首先要求用户对 \[身份验证服务器\] 进行身份验证。在用户批准后，授权服务器将发出允许应用代表用户执行操作的令牌。请注意，OAuth2 规范不定义任何特定类型的身份验证或访问令牌格式。

OAuth 2.0 定义了四个角色：

* 资源所有者：帐户所有者
* 客户端：希望使用访问令牌访问用户帐户的应用程序
* 资源服务器：托管用户帐户
* 授权服务器：验证用户身份并颁发对应用程序的访问令牌

注意：API 同时履行资源所有者和授权服务器角色。因此，我们将两者称为 API。

![Abstract Protocol Flow](../.gitbook/assets/abstract_oath2_flow.png)

这里是一个更多的 [detailed explanation](https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2) 图中的步骤：

1. 应用程序请求用户授权访问服务资源。
2. 如果用户授权请求，应用程序将收到授权授权。授权授予可以采用多种形式（显式、隐式等）。
3. 应用程序通过提供其自身标识的身份验证以及授权授予，从授权服务器 （API） 请求访问令牌。
4. 如果应用程序标识经过身份验证且授权授予有效，则授权服务器 （API） 会向应用程序颁发访问令牌，从而完成授权过程。访问令牌可能具有配套刷新令牌。
5. 应用程序从资源服务器 （API） 请求资源，并提供用于身份验证的访问令牌。访问令牌可能以多种方式使用（例如，作为承载令牌）。
6. 如果访问令牌有效，资源服务器 （API） 会将资源提供给应用程序。

### OAUTH 2.0 最佳实践

验证是否遵循以下最佳做法：

用户代理：

* 用户应具有直观地验证信任的方法（例如，传输层安全 （TLS） 确认、网站机制）。
* 为了防止中间人攻击，客户端应使用建立连接时服务器提供的公钥验证服务器的完全限定域名。

赠款类型：

* 在本机应用中，应使用代码授予而不是隐式授予。
* 使用代码授予时，应实现 PKCE（代码交换验证密钥）以保护代码授予。确保服务器也实现它。
* auth \[代码\] 应该是短期的，并在收到后立即使用。验证 auth 代码是否仅驻留在瞬态内存上，并且未存储或记录。

客户端机密：

* 共享密钥不应用于证明客户端的身份，因为客户端可能被模拟（"client\_id"已用作证明）。如果它们确实使用客户端机密，请确保它们存储在安全的本地存储中。

最终用户凭据：

* 使用传输层方法（如 TLS）保护最终用户凭据的传输。

令 牌：

* 将访问令牌保存在瞬态内存中。
* 访问令牌必须通过加密连接传输。
* 当无法保证端到端机密性或令牌提供对敏感信息或事务的访问权限时，减少访问令牌的范围和持续时间。
* 请记住，如果应用使用访问令牌作为承载令牌，而没有其他方法来标识客户端，则窃取令牌的攻击者可以访问其作用域及其关联的所有资源。
* 将刷新令牌存储在安全的本地存储中;它们是长期证书。

#### 外部用户代理与嵌入式用户代理

OAuth2 身份验证可以通过外部用户代理（例如 Chrome 或 Safari）执行，也可以在应用本身（例如，通过嵌入到应用或身份验证库中的 WebView）执行。这两种模式本质上都不是"更好" - 相反，选择何种模式取决于上下文。

对于需要与社交媒体帐户（Facebook、Twitter 等）进行交互的应用，使用 \[外部用户代理\] 是首选方法。此方法的优点包括：

* 用户的凭据永远不会直接公开给应用。这可确保应用在登录过程中无法获取凭据（"凭据网络钓鱼"）。
* 几乎无需将身份验证逻辑添加到应用本身，从而防止编码错误。

在消极方面，无法控制浏览器的行为（例如激活证书固定）。

对于在封闭生态系统中运行的应用，\[嵌入式身份验证\] 是更好的选择。例如，假设使用 OAuth2 从银行的身份验证服务器检索访问令牌的银行应用，该令牌随后用于访问许多微服务。在这种情况下，凭据网络钓鱼不可行。最好将身份验证过程保留在（希望）经过仔细保护的银行应用中，而不是将信任放在外部组件上。

### 其他 OAuth2 最佳实践

有关其他最佳做法和详细信息，请参阅以下源文档：

* [RFC6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
* [DRAFT - OAuth 2.0 for Native Apps](https://tools.ietf.org/html/draft-ietf-oauth-native-apps-12)
* [RFC6819 - OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819)

## 测试登录活动和设备阻止 \(MSTG-AUTH-11\)

对于需要 L2 保护的应用程序，MASVS 规定，它们应告知用户应用程序内的所有登录活动，并具有阻止某些设备的可能性。这可以分解为各种方案：

1. 应用程序提供推送通知时，他们的帐户在另一台设备上使用通知用户不同的活动。然后，用户可以通过推送通知打开应用程序后阻止此设备。
2. 如果上一个会话具有不同的配置（例如位置、设备、应用版本），则应用程序提供登录后最后一个会话的概述，然后用户提供其当前配置。然后，用户可以选择报告可疑活动并阻止上一会话中使用的设备。
3. 应用程序提供登录后最后一个会话的概览。
4. 应用程序有一个自助服务门户，用户可以在其中查看审核日志并管理他可以使用的不同设备登录。

开发人员可以使用特定的元信息并将其关联到应用程序中的每个不同活动或事件。这将使用户更容易发现可疑行为并阻止相应的设备。元信息可能包括：

* 设备：用户可以清楚地识别正在使用应用的所有设备。
* 日期和时间：用户可以清楚地看到使用应用的最新日期和时间。
* 位置：用户可以清楚地识别应用使用的最新位置。

应用程序可以提供活动历史记录列表，将在应用程序中的每个敏感活动后更新。根据每个应用程序处理的数据以及团队愿意承担的安全风险级别，选择需要为每个应用程序执行哪些活动。以下是通常审核的常见敏感活动的列表：

* 登录尝试
* 密码更改
* 个人身份信息变更（姓名、电子邮件地址、电话号码等）
* 敏感活动（购买、访问重要资源等）
* 同意条款和条件条款

付费内容需要特殊照顾，并且可以使用其他元信息（例如运营成本、信用等）来确保用户了解整个操作的参数。

此外，应对敏感交易（例如付费内容访问、同意条款和条件条款等）应用不可否认机制，以证明特定交易实际上是执行（完整性）和由谁执行的（身份验证）。

在所有情况下，都应验证是否正确检测到不同的设备。因此，应测试应用程序与实际设备的绑定。 在 iOS 中，开发人员可以使用与捆绑 ID 相关的"标识符ForVendor"：当您更改捆绑 ID 时，该方法将返回不同的值。首次运行应用时，请确保将"标识符ForVendor"返回的值存储到 KeyChain，以便在早期阶段检测到对应用的更改。

在 Android 中，开发人员可以使用"设置.Secure.ANDROID\_ID"，直到 Android 8.0（API 级别 26）来识别应用程序实例。请注意，从 Android 8.0（API 级别 26）开始，"ANDROID\_ID"不再是设备的唯一 ID。相反，它通过应用签名密钥、用户和设备的组合而成为范围。因此，对于这些 Android 版本来说，验证设备阻塞的"ANDROID\_ID"可能比较棘手。因为如果应用更改其签名密钥，"ANDROID\_ID"将更改，并且无法识别旧用户设备。因此，最好使用"AndroidKeyStore"中随机生成的密钥将"ANDROID\_ID"加密和私下存储在私有的共享首选项文件中，最好AES\_GCM加密。当应用程序签名更改时，应用程序可以检查增量并注册新的"ANDROID\_ID"。在未使用新应用程序签名密钥的情况下更改此新 ID 时，应表明存在其他错误。 接下来，可以通过使用存储在 iOS 的"钥匙串"中的密钥对请求签名来扩展设备绑定，在 Android 中的"KeyStore"中可以保证强大的设备绑定。 您还应测试使用不同的 IP、不同位置和/或不同的时隙是否会在所有方案中触发正确的信息类型。

最后，应通过阻止应用的注册实例，并查看是否不再允许其进行身份验证来测试设备的阻止。 注意：如果应用程序需要 L2 保护，最好在新设备上进行第一次身份验证之前警告用户。相反：在注册应用的第二个实例时已警告用户。

## 参考资料

### OWASP Mobile Top 10 2016

* M4 - Insecure Authentication - [https://www.owasp.org/index.php/Mobile\_Top\_10\_2016-M4-Insecure\_Authentication](https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication)

### OWASP MASVS

* MSTG-ARCH-2: "Security controls are never enforced only on the client side, but on the respective remote endpoints."
* MSTG-AUTH-1: "If the app provides users access to a remote service, some form of authentication, such as username/password authentication, is performed at the remote endpoint."
* MSTG-AUTH-2: "If stateful session management is used, the remote endpoint uses randomly generated session identifiers to authenticate client requests without sending the user's credentials."
* MSTG-AUTH-3: "If stateless token-based authentication is used, the server provides a token that has been signed with a secure algorithm."
* MSTG-AUTH-4: "The remote endpoint terminates the existing stateful session or invalidates the stateless session token when the user logs out."
* MSTG-AUTH-5: "A password policy exists and is enforced at the remote endpoint."
* MSTG-AUTH-6: "The remote endpoint implements an exponential back-off or temporarily locks the user account when incorrect authentication credentials are submitted an excessive number of times."
* MSTG-AUTH-7: "Sessions are invalidated at the remote endpoint after a predefined period of inactivity and access tokens expire."
* MSTG-AUTH-9: "A second factor of authentication exists at the remote endpoint and the 2FA requirement is consistently enforced."
* MSTG-AUTH-10: "Sensitive transactions require step-up authentication."
* MSTG-AUTH-11: "The app informs the user of all login activities with their account. Users are able view a list of devices used to access the account, and to block specific devices."

### CWE

* CWE-287 - Improper Authentication
* CWE-307 - Improper Restriction of Excessive Authentication Attempts
* CWE-308 - Use of Single-factor Authentication
* CWE-521 - Weak Password Requirements
* CWE-613 - Insufficient Session Expiration

#### SMS-OTP 研究

* Dmitrienko, Alexandra, et al. "On the \(in\) security of mobile two-factor authentication." International Conference on Financial Cryptography and Data Security. Springer, Berlin, Heidelberg, 2014.
* Grassi, Paul A., et al. Digital identity guidelines: Authentication and lifecycle management \(DRAFT\). No. Special Publication \(NIST SP\)-800-63B. 2016.
* Grassi, Paul A., et al. Digital identity guidelines: Authentication and lifecycle management. No. Special Publication \(NIST SP\)-800-63B. 2017.
* Konoth, Radhesh Krishnan, Victor van der Veen, and Herbert Bos. "How anywhere computing just killed your phone-based two-factor authentication." International Conference on Financial Cryptography and Data Security. Springer, Berlin, Heidelberg, 2016.
* Mulliner, Collin, et al. "SMS-based one-time passwords: attacks and defense." International Conference on Detection of Intrusions and Malware, and Vulnerability Assessment. Springer, Berlin, Heidelberg, 2013.
* Siadati, Hossein, et al. "Mind your SMSes: Mitigating social engineering in second factor authentication." Computers & Security 65 \(2017\): 14-28.
* Siadati, Hossein, Toan Nguyen, and Nasir Memon. "Verification code forwarding attack \(short paper\)." International Conference on Passwords. Springer, Cham, 2015.

#### 工具

* Burp Suite - [https://portswigger.net/burp/](https://portswigger.net/burp/)
* Using Burp Intruder - [https://portswigger.net/burp/documentation/desktop/tools/intruder/using](https://portswigger.net/burp/documentation/desktop/tools/intruder/using)
* OWASP ZAP - [https://www.owasp.org/index.php/OWASP\_Zed\_Attack\_Proxy\_Project](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
* jwtbrute - [https://github.com/jmaxxz/jwtbrute](https://github.com/jmaxxz/jwtbrute)
* crackjwt - [https://github.com/Sjord/jwtcrack/blob/master/crackjwt.py](https://github.com/Sjord/jwtcrack/blob/master/crackjwt.py)
* John the ripper - [https://github.com/magnumripper/JohnTheRipper](https://github.com/magnumripper/JohnTheRipper)

