<a href="https://leanpub.com/mobile-security-testing-guide"><img width=180px align="right" style="float: right;" src="Document/Images/mstg-cover-release-small.jpg"></a>

# OWASP 移动安全测试指南 [![Twitter Follow](https://img.shields.io/twitter/follow/OWASP_MSTG.svg?style=social&label=Follow)](https://twitter.com/OWASP_MSTG)

[![Creative Commons License](https://licensebuttons.net/l/by-sa/4.0/88x31.png)](https://creativecommons.org/licenses/by-sa/4.0/ "CC BY-SA 4.0")

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-48A646.svg)](https://www.owasp.org/index.php/Category:OWASP_Project#tab=Project_Inventory)
[![Build Status](https://travis-ci.com/OWASP/owasp-mstg.svg?branch=master)](https://travis-ci.com/OWASP/owasp-mstg)

这是 OWASP 移动安全测试指南 （MSTG） 的官方 GitHub 存储库。MSTG 是移动应用安全测试和逆向工程的综合手册。它描述了验证 [OWASP 移动应用程序验证标准 （MASVS）中列出的控制的技术流程](https://github.com/OWASP/owasp-masvs "MASVS").
您还可以阅读 MSTG [Gitbook](https://mobile-security.gitbook.io/mobile-security-testing-guide/ "MSTG @ Gitbook") 或下载它作为 [e-book](https://leanpub.com/mobile-security-testing-guide-preview "MSTG as an e-book").

MSTG 和 MASVS 正被许多公司、标准和各种组织采用。想了解更多信息？查看我们的 [用户文档，列出一些采用者](Users.md).

## 目录

### 介绍

- [页眉](Document/0x00-Header.md)
- [前言](Document/Foreword.md)
- [正面](Document/0x02-Frontispiece.md)
- [移动安全测试指南简介](Document/0x03-Overview.md)
- [移动应用分类](Document/0x04a-Mobile-App-Taxonomy.md)
- [移动应用安全测试](Document/0x04b-Mobile-App-Security-Testing.md)

### 一般测试指南

- [Mobile App Authentication Architectures](Document/0x04e-Testing-Authentication-and-Session-Management.md)
- [Testing Network Communication](Document/0x04f-Testing-Network-Communication.md)
- [Cryptography in Mobile Apps](Document/0x04g-Testing-Cryptography.md)
- [Testing Code Quality](Document/0x04h-Testing-Code-Quality.md)
- [Tampering and Reverse Engineering](Document/0x04c-Tampering-and-Reverse-Engineering.md)
- [Testing User Education](Document/0x04i-Testing-user-interaction.md)

### 安卓测试指南

- [Platform Overview](Document/0x05a-Platform-Overview.md)
- [Android Basic Security Testing](Document/0x05b-Basic-Security_Testing.md)
- [Data Storage on Android](Document/0x05d-Testing-Data-Storage.md)
- [Android Cryptographic APIs](Document/0x05e-Testing-Cryptography.md)
- [Local Authentication on Android](Document/0x05f-Testing-Local-Authentication.md)
- [Android Network APIs](Document/0x05g-Testing-Network-Communication.md)
- [Android Platform APIs](Document/0x05h-Testing-Platform-Interaction.md)
- [Code Quality and Build Settings for Android Apps](Document/0x05i-Testing-Code-Quality-and-Build-Settings.md)
- [Tampering and Reverse Engineering on Android](Document/0x05c-Reverse-Engineering-and-Tampering.md)
- [Android Anti-Reversing Defenses](Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md)

### iOS 测试指南

- [Platform Overview](Document/0x06a-Platform-Overview.md)
- [iOS Basic Security Testing](Document/0x06b-Basic-Security-Testing.md)
- [Data Storage on iOS](Document/0x06d-Testing-Data-Storage.md)
- [iOS Cryptographic APIs](Document/0x06e-Testing-Cryptography.md)
- [Local Authentication on iOS](Document/0x06f-Testing-Local-Authentication.md)
- [iOS Network APIs](Document/0x06g-Testing-Network-Communication.md)
- [iOS Platform APIs](Document/0x06h-Testing-Platform-Interaction.md)
- [Code Quality and Build Settings for iOS Apps](Document/0x06i-Testing-Code-Quality-and-Build-Settings.md)
- [Tampering and Reverse Engineering on iOS](Document/0x06c-Reverse-Engineering-and-Tampering.md)
- [iOS Anti-Reversing Defenses](Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md)

### 附录

- [Testing Tools](Document/0x08-Testing-Tools.md)
- [Suggested Reading](Document/0x09-Suggested-Reading.md)

## 阅读移动安全测试指南

MSTG 的 1.0 版本于 2018 年 6 月发布。您可以获取多种格式的中间版本。

1. 阅读 [Gitbook](https://mobile-security.gitbook.io/mobile-security-testing-guide/ "Gitbook"). 本书会自动与主回购同步。

2. 检查 [版本](https://github.com/OWASP/owasp-mstg/releases "Our releases"). 在这里，您可以找到 PDF、包含源的存档以及任何给定标记版本的 DocX 文档。请注意，文档是按标记自动生成的。

3. 将书籍作为印刷版本。这本书的硬拷贝可以通过[lulu.com]订购。(http://www.lulu.com/shop/sven-schleier-and-jeroen-willemsen-and-bernhard-m%C3%BCller/owasp-mobile-security-testing-guide/paperback/product-24091501.html "MSTG 在 Lulu.com"). 这本书的这个版本并不完全符合书籍印刷标准，但我们正在改进每个版本。如果您发现任何问题或错误，即使是小问题或错误，请提出 [问题](https://github.com/OWASP/owasp-mstg/issues "我们的问题部分")，所以我们可以在下一个版本中修复它。.

4. 获取 [电子书](https://leanpub.com/mobile-security-testing-guide-preview "MSTG as an e-book"). 这本书是免费的，但如果你想支持我们的项目，你可以选择以你选择的价格购买它。通过销售电子书筹集的所有资金将直接纳入项目预算，并将用于资助未来发行的制作。

5. 克隆存储库并运行 [文档生成器](https://github.com/OWASP/owasp-mstg/blob/master/Tools/generate_document.sh "The document generator") (需要 [pandoc](http://pandoc.org "Pandoc")). 这将在"生成"子目录中生成 docx 和 HTML 文件。

    ```shell
    $ git clone https://github.com/OWASP/owasp-mstg/
    $ cd owasp-mstg/Tools/
    $ ./generate_document.sh
    ```

6. 克隆存储库并运行 [gitbook 生成器](https://github.com/OWASP/owasp-mstg/blob/master/Tools/gitbookepubandpdf.sh "Gitbook based"). 这将在"生成"子目录中生成 PDF、Epub 和 Mobi 文件。

    ```shell
    $ git clone https://github.com/OWASP/owasp-mstg/
    $ cd owasp-mstg/Tools/
    $ ./gitbookandpdf.sh
    ```

您还可以使用 [文档索引](https://rawgit.com/OWASP/owasp-mstg/master/Generated/OWASP-MSTG-Table-of-Contents.html "TOC") 以导航 MSTG 的主分支。

## 贡献、功能请求和反馈

**我们正在寻找更多的作者，评论者和编辑。** 入门的最佳方式是浏览 [现有内容](https://mobile-security.gitbook.io/mobile-security-testing-guide/ "existing content"). 此外，请检查 [问题](https://github.com/OWASP/owasp-mstg/issues "our issues section") 和 [项目页面](https://github.com/OWASP/owasp-mstg/projects/2 "The MSTG Project") 用于打开的任务的列表。

将"我们"线路放在 [Slack通道](https://app.slack.com/client/T04T40NHX/C1M6ZVC6S "Come to our Slack!") 在你开始研究一个主题之前。这有助于我们跟踪每个人正在做什么，并防止冲突。您可以在此处创建 Slack 帐户：

[https://owasp.slack.com/](https://join.slack.com/t/owasp/shared_invite/enQtNjExMTc3MTg0MzU4LWQ2Nzg3NGJiZGQ2MjRmNzkzN2Q4YzU1MWYyZTdjYjA2ZTA5M2RkNzE2ZjdkNzI5ZThhOWY5MjljYWZmYmY4ZjM)

在您开始供款之前，请查看我们的 [贡献指南](https://github.com/OWASP/owasp-mstg/blob/master/CONTRIBUTING.md "Contribution Guide") 应该让你开始。

请注意，MSTG 主要关注本机应用程序。这些是使用 Java 或 Kotlin 构建的应用程序，使用 Android 的 Android SDK 构建，或使用适用于 iOS 的 Apple SDK 使用 Swift 或 Objective-C 构建。原生脚本/反应原生/Xamarin/Cordova/...应用不在 MSTG 的重点范围内。但是，一些键控件（如固定）已经针对其中一些平台进行了解释。
如果您正在寻找有关此字段的更多安全建议，请查看基于合规性清单 1.1.2 的正在进行的 Google 工作表：

- [Flutter Compliancy Checklist (WIP)](https://drive.google.com/open?id=1wHK3VI1cU1xmYrCu9yb5OHKUEeLIPSkC "Flutter Compliancy Checklist");
- [React-Native Compliancy Checklist (WIP)](https://drive.google.com/open?id=1P5FZ_Bup5eSPOmkePZA8cIpKGOKvngkN "React-Native Compliancy Checklist").
- [Xamarin Compliancy Checklist (WIP)](https://drive.google.com/open?id=1UL1yLRREJwXfe0HlrcX-IuvPYQM7lTtG "Xamarin Compliancy Checklist").

如果指南中确实要查看某些内容，或者您想要建议改进，请创建一个问题 [问题](https://github.com/OWASP/owasp-mstg/issues "Issue") 或呼叫我们 [Slack](https://app.slack.com/client/T04T40NHX/C1M6ZVC6S "Come to our Slack!").
如果问题被接受，我们将将其安排到我们的[里程碑](https://github.com/OWASP/owasp-mstg/milestones "Milestones").

## Authoring Credit

Contributors are added to the acknowledgements table based on their contributions logged by GitHub. The list of names is sorted by the number of lines added. Authors are categorized as follows:

- Project Leader / Author: Manage development of the guide continuously and write a large amount of new content. Project Leadership cannot be achieved if any violations of the Code of Conduct occurred in the past.
- Co-Author: Consistently contribute quality content, [at least 2,000 additions logged](https://github.com/OWASP/owasp-mstg/graphs/contributors "Co-author").
- Top Contributor: Consistently contribute quality content, [at least 500 additions logged](https://github.com/OWASP/owasp-mstg/graphs/contributors "Top Contributor").
- Contributor: Any form of contribution, [at least 50 additions logged](https://github.com/OWASP/owasp-mstg/graphs/contributors "Contributor").
- Mini-contributor: Everything below 50 additions, e.g. committing a single word or sentence.
- Reviewer: People that haven't submitted their own pull requests, but have created issues or given useful feedback in other ways.

如果您在表或错误的列中缺少，请 ping 我们或创建拉取请求（请注意，我们经常更新表，但不是实时更新）。

如果您愿意编写大部分指南，并帮助持续推动项目向前发展，您可以以作者身份加入。请注意，您将在几个月内投入大量时间。请联系斯文·施莱尔（斯莱克：[斯文]）、耶罗恩·威廉森（斯莱克：[耶罗恩·威廉森]）或卡洛斯·霍尔格拉（斯莱克：[卡洛斯]）了解更多信息。

## Crackmes

在"Crackmes"文件夹中，您可以找到一组要破解的移动应用程序。你能找到秘密吗？有关详细信息：请查看 [README.md](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/README.md "Crackmes readme") at the [Crackmes folder](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes "Crackmes folder").
