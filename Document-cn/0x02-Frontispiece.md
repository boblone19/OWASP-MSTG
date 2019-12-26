# Frontispiece

## 关于 OWASP 移动安全测试指南

OWASP 移动安全测试指南 （MSTG） 是测试移动应用安全性的全面手册。它描述了如何验证 [移动应用程序安全验证标准 （MASVS） 中列出的要求]（https：//github.com/OWASP/owasp-masvs[MASVS]）中列出的要求的过程和技术观点，为完整和一致的安全测试提供了基础。

OWASP 感谢许多作者、评论者和编辑在编写本指南方面所做的工作。如果您对《移动安全测试指南》有任何意见或建议，请加入[OWASP 移动安全项目Slack通道](https://owasp.slack.com/messages/project-mobile_omtg/details/ "OWASP Mobile Security Project Slack Channel"). 您可以使用 [此邀请]自行注册Slack频道 (https://join.slack.com/t/owasp/shared_invite/enQtNDI5MzgxMDQ2MTAwLTEyNzIzYWQ2NDZiMGIwNmJhYzYxZDJiNTM0ZmZiZmJlY2EwZmMwYjAyNmJjNzQxNzMyMWY4OTk3ZTQ0MzFhMDY "Slack 通道注册"). (如果邀请已过期，请打开 PR.)

## 版权和许可

版权所有 © OWASP 基金会。本作品根据 #创意共享归因-共享 A 类似 4.0 国际许可证获得许可(https://creativecommons.org/licenses/by-sa/4.0/ "知识共享归因-共享类似 4.0 国际许可证"). 对于任何重用或分发，您必须向其他人说明此作品的许可条款。

<img src="Images/CC-license.png" alt="drawing" width="150">

## ISBN

我们的 ISBN 号码是 978-0-359-47489-9.

## 确认

**Note**: 此参与者表基于我们的 [GitHub 贡献统计信息]（https：//github.com/OWASP/owasp-mstg/图表/贡献者 [GitHub 贡献统计信息]）生成。有关这些统计信息的详细信息，请参阅 [GitHub 存储库 README]（https：//github.com/OWASP/owasp-mstg/blob/master/README.md [GitHub 存储库 README]）。我们手动更新表，因此，如果您没有立即列出，请耐心等待。

### 作者

#### Bernhard Mueller

Bernhard 是一位网络安全专家，拥有各种黑客系统的天赋。在业界的十多年中，他为 MS SQL Server、Adobe Flash Player、IBM 控制器、思科 VOIP 和 ModSecurity 等软件发布了许多零日漏洞。如果你能说出它的名字，他可能至少弄坏了一次。BlackHat USA 凭借 Pwnie 最佳研究奖表彰他在移动安全领域的开创性工作。

#### Sven Schleier

Sven 是一个经验丰富的网络和移动渗透测试仪，并评估了从历史闪存应用程序到渐进式移动应用程序的所有内容。他也是一名安全工程师，在 SDLC 期间端到端支持许多项目以"在 中构建安全性"。他正在当地和国际会议上发表演讲，并举办有关 Web 应用和移动应用安全性的动手研讨会。

#### Jeroen Willemsen

Jeroen 是 Xebia 的主要安全架构师，对移动安全和风险管理充满热情。他支持公司担任安全教练、安全工程师和全栈开发人员，这使得他成为所有行业的一个插孔。他喜欢解释技术主题：从安全问题到编程挑战。

#### Carlos Holguera

Carlos 是一名安全工程师，领导 ESCRYPT 的移动渗透测试团队。他在移动应用和嵌入式系统（如汽车控制单元和 IoT 设备）的安全测试领域积累了多年的实践经验。他热衷于移动应用的逆向工程和动态检测，并不断学习和分享自己的知识。

### Co-Authors

Co-authors 始终提供高质量的内容，并在 GitHub 存储库中至少记录了 2，000 个新增内容。

#### Romuald Szkudlarek

Romuald 是一位充满激情的网络安全和隐私专家，在网络、移动、物联网和云领域拥有超过 15 年的经验。在他的职业生涯中，他一直将业余时间用于各种项目，目标是推动软件和安全领域的发展。他经常在各个机构任教。他拥有 CISSP、CCSP、CSSLP 和 CEH 证书。

#### Jeroen Beckers

Jeroen 是 NVISO 的移动安全主管，负责移动安全项目的质量保证和所有移动项目的研发。他在高中和大学期间担任 Flash 开发人员，但毕业后转行从事网络安全工作，现在在移动安全领域拥有超过 5 年的经验。他喜欢与他人分享自己的知识，他的许多演讲——在大学、大学、客户和会议中接受培训——就证明了这一点。

### 最佳贡献者

顶级贡献者始终提供高质量的内容，并在 GitHub 存储库中记录了至少 500 个新增内容。

- Pawel Rzepa
- Vikas Gupta
- Francesco Stillavato
- Henry Hoggard
- Andreas Happe
- Kyle Benac
- Paulino Calderon
- Alexander Anthuk
- Abderrahmane Aftahi
- Wen Bin Kong
- Abdessamad Temmar
- Cláudio André
- Slawomir Kosowski
- Bolot Kerimbaev

<br/>
<br/>

### 贡献者

贡献者已贡献高质量的内容，并在 GitHub 存储库中记录了至少 50 个新增内容。

Koki Takeyama, Jin Kung Ong, Sjoerd Langkemper, Caleb Kinney, Gerhard Wagner, Michael Helwig, Pece Milosev, Ryan Teoh, Denis Pilipchuk, José Carlos Andreu, Dharshin De Silva, Anatoly Rosencrantz, Caitlin Andrews, Abhinav Sejpal, Anita Diamond, Raul Siles, Yogesh Sharma, Enrico Verzegnassi, Nick Epson, Anna Szkudlarek, Elie Saad, Prathan Phongthiproek, Tom Welch, Luander Ribeiro, Heaven L. Hodges, Shiv Sahni, Akanksha Bana, Dario Incalza, Jason Doyle, Oguzhan Topgul, Ender IBL, Imani Sherman, magicansk, Sijo Abraham, Dominique RIGHETTO, Pishu Mahtani, Jay Mbolda, Anuruddha E., Emil Tostrup.

### 核审专员

审阅者一直通过 GitHub 问题和拉取请求注释提供有用的反馈。

- Jeroen Beckers
- Sjoerd Langkemper
- Anant Shrivastava

### 编辑者

- Heaven Hodges
- Caitlin Andrews
- Nick Epson
- Anita Diamond
- Anna Szkudlarek

### 其他

许多其他贡献者都承诺了少量内容，例如单个单词或句子（少于 50 个新增内容）。参与者的完整列表可在 [GitHub] 上找到。(https://github.com/OWASP/owasp-mstg/graphs/contributors "contributors").

### 赞助商

虽然 MASVS 和 MSTG 都是由社区在自愿的基础上创建和维护的，但有时需要一点外部帮助。因此，我们感谢我们的赞助商提供资金，以便能够聘请技术编辑。请注意，他们的赞助不会以任何方式影响 MASVS 或 MSTG 的内容。赞助包在[OWASP项目维基]（https：//www.owasp.org/index.php/OWASP_Mobile_Security_Testing_Guide_tab_Sponsorship_Packages"OWASP移动安全测试指南赞助包]"上进行了描述。

#### 荣誉恩人

[![NowSecure](Images/Sponsors/NowSecure_logo.png)](https://www.nowsecure.com/ "NowSecure")

[OWASP 湾区分会](https://twitter.com/OWASPBayArea?ref_src=twsrc%5Egoogle%7Ctwcamp%5Eserp%7Ctwgr%5Eauthor "Twitter Bay Area")

#### 捐赠者

以下人员/或公司使用 Leanpub 或其他方式捐赠了超过 25 美元：

- [RandoriSec](https://www.randorisec.fr/ "RandoriSec")
- eShard

<br/>
<br/>

### 旧版本

移动安全测试指南由米兰·辛格·塔库尔于2015年发起。原始文档托管在 Google 云端硬盘上。指南开发于 2016 年 10 月移至 GitHub。

#### OWASP MSTG "Beta 2" (Google Doc)

| 作者 | 审核者 | 最佳贡献者 |
| --- | --- | --- |
| Milan Singh Thakur, Abhinav Sejpal, Blessen Thomas, Dennis Titze, Davide Cioccia, Pragati Singh, Mohammad Hamed Dadpour, David Fern, Ali Yazdani, Mirza Ali, Rahil Parikh, Anant Shrivastava, Stephen Corbiaux, Ryan Dewhurst, Anto Joseph, Bao Lee, Shiv Patel, Nutan Kumar Panda, Julian Schütte, Stephanie Vanroelen, Bernard Wagner, Gerhard Wagner, Javier Dominguez | Andrew Muller, Jonathan Carter, Stephanie Vanroelen, Milan Singh Thakur  | Jim Manico, Paco Hope, Pragati Singh, Yair Amit, Amin Lalji, OWASP Mobile Team|

#### OWASP MSTG "Beta 1" (Google Doc)

| 作者 | 审核者 | 最佳贡献者 |
| --- | --- | --- |
| Milan Singh Thakur, Abhinav Sejpal, Pragati Singh, Mohammad Hamed Dadpour, David Fern, Mirza Ali, Rahil Parikh | Andrew Muller, Jonathan Carter | Jim Manico, Paco Hope, Yair Amit, Amin Lalji, OWASP Mobile Team  |
