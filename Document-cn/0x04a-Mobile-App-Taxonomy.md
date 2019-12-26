# 常规安全测试指南

## 移动应用分类

术语"移动应用"是指用于在移动设备上执行的自包含计算机程序。如今，Android 和 iOS 操作系统累计占据了移动操作系统市场份额的 99% 以上。(https://www.idc.com/promo/smartphone-market-share/os "智能手机市场份额"). 此外，移动互联网的使用在历史上首次超过桌面使用，使得移动浏览和应用程序成为[最普遍的互联网应用程序](https://www.idc.com/promo/smartphone-market-share/os "Smartphone Market Share").

> 在本指南中，我们将使用术语"应用"作为通用术语，用于引用在流行的移动 OS 上运行的任何类型的应用程序。

从基本意义上讲，应用设计为直接在为其设计的平台上运行，在智能设备的移动浏览器之上运行，或者使用两者的组合。在以下一章中，我们将定义符合应用在移动应用分类中各自位置的特征，并讨论每个变体的差异。

### 原生应用程序

移动操作系统（包括 Android 和 iOS）附带软件开发工具包 （SDK），用于开发特定于操作系统的应用程序。此类应用程序称为 *原生*，用于开发这些应用程序的系统。讨论应用时，一般假设是，它是在相应操作系统的标准编程语言中实现的本机应用 - iOS 的目标 C 或 Swift，以及用于 Android 的 Java 或 Kotlin。

本机应用本质上能够提供具有最高可靠性的最快性能。它们通常遵循特定于平台的设计原则（例如 [安卓设计原则](https://developer.android.com/design/get-started/principles.html "Android Design Principles")), 与 *hybrid* 或 *web* 应用程序相比，这往往会导致更一致的用户界面（UI）。 由于它们与操作系统的紧密集成，因此本机应用程序可以直接访问设备的几乎每个组件（相机，传感器，硬件支持的密钥存储区等）。

在讨论Android的 *原生应用* 时，由于平台提供了两个开发工具包-Android SDK和Android NDK，因此存在一些歧义。 该SDK基于Java和Kotlin编程语言，是开发应用程序的默认工具。 NDK（或本机开发套件）是一种C / C ++开发套件，用于开发可直接访问较低级别的API（例如OpenGL）的二进制库。 这些库可以包含在使用SDK构建的常规应用程序中。 因此，我们说Android *原生应用*（即使用SDK构建的）可能具有NDK构建的 *原生* 代码。

*原生应用程序* 最明显的缺点是它们仅针对一个特定平台。 要为Android和iOS构建相同的应用程序，需要维护两个独立的代码库，或引入通常复杂的开发工具才能将单个代码库移植到两个平台 (e.g. [Xamarin](https://www.xamarin.com/ "Xamarin")).

### 网络应用

移动网络应用程序（或简称为 *网络应用* ）是旨在外观和感觉像 *原始应用程序* 的网站。这些应用程序运行在设备的浏览器之上，通常使用HTML5开发，就像现代的网页一样。可以创建启动器图标，以与访问*原始应用*相同的感觉。但是，这些图标本质上与浏览器书签相同，只需打开默认的Web浏览器以加载引用的网页即可。

Web应用程序在浏览器范围内运行（即，它们被“沙盒化”），因此与设备的常规组件的集成受限，并且与原始应用程序相比通常缺乏性能。由于Web应用程序通常针对多个平台，因此其UI不遵循特定平台的某些设计原则。最大的优点是减少了与单个代码库相关的开发和维护成本，并使开发人员无需使用特定于平台的应用程序商店即可分发更新。例如，对Web应用程序的HTML文件进行更改可以作为可行的跨平台更新，而对基于商店的应用程序进行更新则需要付出更多的努力。

### 混合应用

混合应用程序试图填补 *原生* 和 *网络应用* 之间的空白。 *混合应用* 的执行方式类似于 *原始应用程序*，但是大多数流程都依赖于网络技术，这意味着该应用程序的一部分在嵌入式网络浏览器（通常称为“网络视图”）中运行。 因此，混合应用程序继承了 * 原生* 和 *web应用* 的优缺点。

Web到本地的抽象层允许访问纯混合的Web应用程序无法访问的混合应用程序的设备功能。 根据开发所使用的框架，一个代码库可以导致针对不同平台的多个应用程序，其UI与开发该应用程序的原始平台的UI非常相似。

以下是用于开发 *混合移动应用程序* 比较流行框架详尽列表：

- [Apache Cordova](https://cordova.apache.org/ "Apache Cordova")
- [Framework 7](https://framework7.io/ "Framework 7")
- [Ionic](https://ionicframework.com/ "Ionic")
- [jQuery Mobile](https://jquerymobile.com/ "jQuery Mobile")
- [Google Flutter](https://flutter.dev/ "Google Flutter")
- [Native Script](https://www.nativescript.org/ "Native Script")
- [Onsen UI](https://onsen.io/ "Onsen UI")
- [React Native](https://www.reactnative.com/ "React Native")
- [Sencha Touch](https://www.sencha.com/products/touch/ "Sencha Touch")

### 渐进式Web应用

渐进式Web应用程序（PWA）的加载方式与常规网页一样，但是在某些方面与常规Web应用程序不同。 例如，可以脱机工作，并且可以访问移动设备硬件，而传统上仅对本地移动应用程序可用。

PWA结合了现代浏览器提供的不同的Web开放标准，以提供丰富的移动体验。 Web App Manifest是一个简单的JSON文件，可用于配置“安装”后应用程序的行为。

Android和iOS支持PWA，但并非所有硬件功能都可用。 例如，推送通知，iPhone X或增强现实的ARKit上的人脸ID在iOS上尚不可用。 可以在[Maximiliano Firtman的中文章]中找到PWA和每个平台上支持的功能的概述。(https://medium.com/@firt/progressive-web-apps-on-ios-are-here-d00430dee3a7 "iOS上的渐进式Web应用程序在这里").

### 移动安全测试指南的涵盖内容

在本指南中，我们将重点关注主导市场的两个平台的应用程序：Android和iOS。 移动设备是当前在这些平台上运行的最常见的设备类别–但是，越来越多的相同平台（尤其是Android）运行在其他设备上，例如智能手表，电视，汽车导航/音频系统和其他嵌入式系统。

鉴于有大量的移动应用程序框架可用，因此不可能详尽地涵盖所有这些框架。 因此，我们专注于每个操作系统上的 *原生*应用。 但是，在处理Web或混合应用程序时，同样的技术也很有用（最终，无论采用哪种框架，每个应用程序都基于本机组件）。