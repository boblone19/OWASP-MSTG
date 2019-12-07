# iOS 平台概述

iOS是为苹果移动设备（包括iPhone，iPad和iPod Touch）提供动力的移动操作系统。这也是Apple tvOS的基础，后者继承了iOS的许多功能。本节从架构角度介绍iOS平台。讨论了以下五个关键领域：

1. iOS安全架构
2. iOS应用程序结构

   3.进程间通信（IPC）

3. iOS应用程序发布
4. iOS应用程序攻击面

与Apple桌面操作系统macOS（以前称为OS X）类似，iOS基于Darwin，Darwin是Apple开发的开源Unix操作系统。 Darwin的内核是XNU（“ X不是Unix”），它是混合了Mach和FreeBSD内核组件的混合内核。

但是，iOS应用程序在比桌面应用程序更严格的环境中运行。 iOS应用在文件系统级别彼此隔离，并且在系统API访问方面受到很大限制。

为了保护用户免受恶意应用程序的侵害，Apple限制并控制了对允许在iOS设备上运行的应用程序的访问。苹果的App Store是唯一的官方应用程序分发平台。那里的开发人员可以提供他们的应用程序，而消费者可以购买，下载和安装应用程序。这种发布方式不同于Android，后者支持多个应用商店和侧载（无需使用官方App Store即可在iOS设备上安装应用）。在iOS中，侧载通常是指通过USB安装应用程序的方法，尽管在[Apple Developer Enterprise Program](https://developer.apple.com/programs/enterprise/).

过去，只有通过越狱或复杂的解决方法才能进行旁加载。使用iOS 9或更高版本，可以 [sideload via Xcode](https://www.igeeksblog.com/how-to-sideload-apps-on-iphone-ipad-in-ios-10/).

iOS应用程序通过Apple的iOS沙箱（历史上称为Seatbelt）彼此隔离，这是一种强制访问控制（MAC）机制，用于描述应用程序可以访问和不能访问的资源。与Android广泛的Binder IPC设施相比，iOS提供的IPC（进程间通信）选项很少，从而最大程度地减少了潜在的攻击面。

统一的硬件和紧密的硬件/软件集成创建了另一个安全优势。每个iOS设备都提供安全功能，例如安全启动，硬件支持的钥匙串和文件系统加密（在iOS中称为数据保护）。通常，iOS更新通常会迅速推广到很大一部分用户，从而减少了支持不受保护的旧iOS版本的需求。

尽管iOS具有众多优势，但iOS应用开发人员仍然需要担心安全性。数据保护，钥匙串，Touch ID / Face ID身份验证以及网络安全性仍然为错误留有很大余地。在以下各章中，我们将介绍iOS安全体系结构，说明基本的安全测试方法，并提供反向工程方法。

## iOS安全架构

Apple在iOS安全指南中正式记录的[iOS安全体系结构](https://www.apple.com/business/docs/iOS_Security_Guide.pdf),包含六个核心功能。 Apple针对每个主要的iOS版本更新了此安全指南：

* 硬件安全
* 安全启动
* 代码签名
* 沙盒
* 加密和数据保护
* 一般利用漏洞

![iOS Security Architecture](../.gitbook/assets/ios_security_architecture%20%281%29.png)

### 硬件安全

iOS安全体系结构充分利用了基于硬件的安全功能，可增强整体性能。每个iOS设备都带有两个内置的高级加密标准（AES）256位密钥。设备的唯一ID（UID）和设备组ID（GID）是在制造过程中融合到应用处理器（AP）和安全防护处理器（SEP）中的AES 256位密钥（UID）或已编译（GID）。没有直接的方法可以通过软件或调试接口（例如JTAG）读取这些密钥。加密和解密操作由对这些密钥具有独占访问权的硬件AES加密引擎执行。

GID是由一类设备中的所有处理器共享的值，用于防止篡改固件文件和与用户的私人数据不直接相关的其他加密任务。每个设备唯一的UID用于保护用于设备级文件系统加密的密钥层次结构。由于在制造过程中未记录UID，因此，甚至Apple也无法还原特定设备的文件加密密钥。

为了允许安全删除闪存中的敏感数据，iOS设备包括一项功能[Effaceable Storage](https://www.apple.com/business/docs/iOS_Security_Guide.pdf). 此功能提供对存储技术的直接低级别访问，从而可以安全地擦除选定的块。

### 安全启动

开启iOS设备电源后，它将从称为引导ROM的只读存储器中读取初始指令，引导系统。 Boot ROM包含不可变的代码和Apple Root CA，后者在制造过程中被蚀刻到硅芯片中，从而建立了信任的根源。接下来，Boot ROM确保LLB（低级Bootloader）签名正确，并且LLB也检查iBoot Bootloader签名是否正确。签名经过验证后，iBoot将检查下一个引导阶段（即iOS内核）的签名。如果这些步骤中的任何一个失败，引导过程将立即终止，设备将进入恢复模式并显示“连接到iTunes”屏幕。但是，如果Boot ROM无法加载，设备将进入一种特殊的低级恢复模式，称为设备固件升级（DFU）。这是将设备还原到原始状态的最后手段。在此模式下，设备不会显示任何活动迹象。即，其屏幕将不会显示任何内容。

这整个过程称为“安全启动链”。其目的集中在验证引导过程的完整性，确保系统及其组件由Apple编写和分发。安全启动链由内核，引导加载程序，内核扩展和基带固件组成。

### 代码签名

苹果已经实施了精心设计的DRM系统，以确保只有苹果批准的代码才能在其设备上运行，即由苹果签名的代码。换句话说，除非苹果明确允许，否则您将无法在没有越狱的iOS设备上运行任何代码。最终用户只能通过官方的Apple App Store安装应用程序。出于这个原因（和其他原因），iOS已被\[比作水晶监狱\]\([https://www.eff.org/deeplinks/2012/05/apples-crystal-prison-and-future-open-platforms](https://www.eff.org/deeplinks/2012/05/apples-crystal-prison-and-future-open-platforms) "Apple's Crystal Prison and the Future of Open Platforms"\).

部署和运行应用程序需要开发者资料和Apple签名的证书。 开发人员需要在Apple上注册，加入[Apple Developer Program](https://developer.apple.com/support/compare-memberships/) 并按年订阅以获取完整的内容。开发和部署的可能性。还有一个免费的开发人员帐户，您可以通过侧面加载来编译和部署应用程序（但不能在App Store中分发它们）。

### 加密和数据保护

_FairPlay代码加密_ 适用于从App Store下载的应用程序。 FairPlay被开发为DRM，用于通过iTunes购买的多媒体内容。最初，Fairplay加密被应用于MPEG和QuickTime流，但是相同的基本概念也可以应用于可执行文件。基本思路如下：一旦注册了新的Apple用户帐户或Apple ID，就会创建一个公钥/私钥对并将其分配给您的帐户。私钥安全地存储在您的设备上。这意味着FairPlay加密的代码只能在与您的帐户关联的设备上解密。反向FairPlay加密通常是通过在设备上运行应用程序，然后从内存中转储解密的代码来获得的（另请参阅“ iOS上的基本安全性测试”）。

自iPhone 3GS发布以来，Apple已在其iOS设备的硬件和固件中内置了加密功能。每个设备都有专用的基于硬件的加密引擎，该引擎提供AES 256位加密和SHA-1哈希算法的实现。此外，每个设备的硬件中都内置了一个唯一标识符（UID），并将AES 256位密钥融合到了应用处理器中。此UID是唯一的，未在其他位置记录。在编写本文时，软件和固件都无法直接读取UID。由于密钥已烧入硅芯片，因此无法对其进行篡改或绕过。只有加密引擎才能访问它。

将加密构建到物理体系结构中使其成为默认的安全功能，可以对存储在iOS设备上的所有数据进行加密。结果，数据保护在软件级别实现，并与硬件和固件加密一起使用，以提供更高的安全性。

启用数据保护后，只需在移动设备中建立密码即可，每个数据文件都与特定的保护类相关联。每个类都支持不同级别的可访问性，并根据需要何时访问数据来保护数据。与每个类关联的加密和解密操作基于利用设备的UID和密码，类密钥，文件系统密钥和每个文件密钥的多种密钥机制。每个文件的密钥用于加密文件的内容。类密钥包装在每个文件的密钥周围，并存储在文件的元数据中。文件系统密钥用于加密元数据。 UID和密码保护类密钥。用户看不到该操作。要启用数据保护，在访问设备时必须使用密码。密码解锁设备。密码与UID结合使用，还可以创建iOS加密密钥，从而更能抵抗黑客攻击和暴力攻击。启用数据保护是用户在其设备上使用密码的主要原因。

### Sandbox

[appsandbox](https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html) 是一种iOS访问控制技术。它在内核级别执行。它的目的是限制应用程序受到威胁时可能发生的系统和用户数据损坏。

自iOS的第一个发行版以来，沙盒已成为一项核心安全功能。所有第三方应用程序都在同一用户（“移动”）下运行，只有少数系统应用程序和服务以“ root”（或其他特定系统用户）运行。常规的iOS应用程序局限于“容器”，该容器限制了对应用程序自己文件和系统API数量的限制。对所有资源（例如文件，网络套接字，IPC和共享内存）的访问由沙箱控制。这些限制的工作方式如下\[\#levin\]：

* 应用程序进程通过类似于chroot的进程被限制在其自己的目录（在/ var / mobile / Containers / Bundle / Application /或/ var / containers / Bundle / Application /下，具体取决于iOS版本）。
* 修改了mmap和mmprotect系统调用，以防止应用程序使可写内存页面可执行，并阻止进程执行动态生成的代码。结合代码签名和FairPlay，这严格限制了在特定情况下可以运行的代码（例如，通过App Store分发的应用程序中的所有代码均已获得Apple批准）。
* 进程彼此隔离，即使它们在操作系统级别上由同一UID拥有。
* 无法直接访问硬件驱动程序。相反，必须通过Apple的公共框架访问它们。

### 一般利用缓解措施

iOS实现了地址空间布局随机化（ASLR）和eXecute Never（XN）位，以减轻代码执行攻击。

每次执行程序时，ASLR都会将程序的可执行文件，数据，堆和堆栈的内存位置随机化。因为共享库必须是静态的才能被多个进程访问，所以每次操作系统启动时（而不是每次调用程序时），共享库的地址都是随机的。这使得特定功能和库的内存地址难以预测，从而防止了诸如回返libc攻击之类的攻击，该攻击涉及基本libc函数的内存地址。

XN机制允许iOS将进程的选定内存段标记为不可执行。在iOS上，进程堆栈和用户模式进程堆被标记为不可执行。不可同时将可写页面标记为可执行页面。这样可以防止攻击者执行注入堆栈或堆中的机器代码。

## iOS上的软件开发

与其他平台一样，Apple提供了软件开发工具包（SDK），可帮助开发人员开发，安装，运行和测试本地iOS应用程序。 Xcode是用于Apple软件开发的集成开发环境（IDE）。 iOS应用程序是用Objective-C或Swift开发的。

Objective-C是一种面向对象的编程语言，它将Smalltalk样式的消息传递添加到C编程语言中。它在macOS上用于开发桌面应用程序，在iOS上用于开发移动应用程序。 Swift是Objective-C的后继产品，并允许与Objective-C互操作。

Swift于2014年随Xcode 6一起推出。

在非越狱设备上，有两种方法可以从App Store中安装应用程序：

1. 通过企业移动设备管理。这需要Apple签署的全公司证书。
2. 通过侧面加载，即通过使用开发者的证书对应用进行签名，然后通过Xcode（或Cydia Impactor）将其安装在设备上。可以使用相同的证书安装数量有限的设备。

## iOS上的应用

iOS应用程序分布在IPA（iOS应用程序商店软件包）档案中。 IPA文件是ZIP压缩的存档，其中包含执行该应用程序所需的所有代码和资源。

IPA文件具有内置的目录结构。下面的示例从高层次显示了此结构：

* `/Payload/`文件夹包含所有应用程序数据。我们将更详细地返回此文件夹的内容。
* `/Payload/Application.app`包含应用程序数据本身（ARM编译代码）和关联的静态资源。
* `/iTunesArtwork`是一个512x512像素的PNG图片，用作应用程序的图标。
* `/iTunesMetadata.plist`包含各种信息，包括开发者的名称和ID，捆绑包标识符，版权信息，类型，应用名称，发行日期，购买日期等。
* `/WatchKitSupport/WK`是扩展捆绑包的示例。该特定的捆绑软件包含扩展委托和控制器，用于管理界面和响应Apple Watch上的用户交互。

### IPA有效负载 - 仔细研究

L让我们仔细看看IPA容器中的不同文件。苹果使用相对扁平的结构，几乎没有多余的目录来节省磁盘空间并简化文件访问。顶级包目录包含应用程序的可执行文件和应用程序使用的所有资源（例如，应用程序图标，其他图像和本地化内容）。

* **MyApp**：可执行文件，其中包含已编译（不可读）的应用程序源代码。
* **Application**：应用图标。
* **Info.plist** ：配置信息，例如捆绑包ID，版本号和应用程序显示名称。
* **Launch images**：以特定方向显示初始应用程序界面的图像。系统使用提供的启动映像之一作为临时背景，直到应用程序完全加载为止。
* **MainWindow.nib** ：启动应用程序时加载的默认接口对象。然后，其他接口对象要么从其他nib文件加载，要么由应用程序以编程方式创建。
* **Settings.bundle** ：特定于应用程序的首选项将显示在“设置”应用程序中。
* **Custom resource file**：非本地化的资源放置在顶级目录中，本地化的资源放置在应用程序捆绑包的特定于语言的子目录中。资源包括笔尖文件，图像，声音文件，配置文件，字符串文件以及应用程序使用的任何其他自定义数据文件。

应用程序支持的每种语言都有一个language.lproj文件夹。它包含一个情节提要和字符串文件。

-故事板是iOS应用程序用户界面的直观表示。它显示屏幕以及这些屏幕之间的连接。 -字符串文件格式由一个或多个键值对和可选注释组成。

![iOS App Folder Structure](../.gitbook/assets/ios_project_folder%20%281%29.png)

在越狱设备上，您可以使用允许解密主应用程序二进制文件并重建IPA文件的其他工具来恢复已安装的iOS应用程序的IPA。 同样，在越狱设备上，可以使用[IPA Installer](https://github.com/autopear/ipainstaller). 安装IPA文件。 在进行移动安全评估时，开发人员通常会直接向您提供IPA。 他们可以向您发送实际文件或提供对他们使用的特定于开发的发行平台的访问，例如[HockeyApp](https://hockeyapp.net/) 或者 [TestFlight](https://developer.apple.com/testflight/).

### 应用权限

与Android应用程序（Android 6.0（API级别23之前））相比，iOS应用程序没有预先分配的权限。而是当应用程序首次尝试使用敏感API时，要求用户在运行时授予权限。 “设置”&gt;“隐私”菜单中列出了已被授予权限的应用程序，允许用户修改特定于应用程序的设置。 Apple将此权限概念称为[隐私控制](https://support.apple.com/en-sg/HT203033).

iOS开发人员无法直接设置请求的权限-他们使用敏感的API间接请求它们。例如，当访问用户的联系人时，在要求用户授予或拒绝访问权限时，对CNContactStore的任何调用都会阻止该应用程序。从iOS 10.0开始，应用程序必须包含使用情况描述键，以说明其请求的权限类型和需要访问的数据（例如NSContactsUsageDescription）。

以下API [需要用户权限](https://www.apple.com/business/docs/iOS_Security_Guide.pdf):

* 联系人
* 麦克风
* 日历
* 相机
* 提醒
* 家用套件
* 相片
* 健康
* 运动活动和健身
* 语音识别
* 位置服务
* 蓝牙共享
* 媒体库
* 社交媒体帐户

## iOS应用程序攻击面

iOS应用程序攻击面由应用程序的所有组件组成，包括发布应用程序和支持其功能所需的辅助材料。如果没有，iOS应用程序可能容易受到攻击：

* 通过IPC通信或URL方案验证所有输入，另请参阅：
  * [测试自定义URL方案](0x06h-testing-platform-interaction.md#testing-custom-url-schemes-mstg-platform-3)
* 验证用户在输入字段中的所有输入。
* 验证WebView内部加载的内容，另请参见：
  * [测试iOS Web视图](0x06h-testing-platform-interaction.md#testing-ios-webviews-mstg-platform-5)
  * [确定是否通过 WebView 公开本机方法](0x06h-testing-platform-interaction.md#determining-whether-native-methods-are-exposed-through-webviews-mstg-platform-7)
* 与后端服务器安全通信或容易受到服务器与移动应用程序之间的中间人（MITM）攻击，另请参阅：
  * [测试网络通讯](../tong-yong-yi-dong-ying-yong-ce-shi-zhi-nan/0x04f-testing-network-communication.md#testing-network-communication)
  * [iOS 网络 API](0x06g-testing-network-communication.md#ios-network-apis)
* 安全地存储所有本地数据，或从存储中加载不受信任的数据，另请参见：
  * [iOS 上的数据存储](0x06d-testing-data-storage.md#data-storage-on-ios)
* 保护自己不受损害的环境，重新包装或其他本地攻击，另请参阅：
  * [iOS 防逆向防御](0x06j-testing-resiliency-against-reverse-engineering.md#ios-anti-reversing-defenses)

