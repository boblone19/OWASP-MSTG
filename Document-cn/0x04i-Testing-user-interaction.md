## 测试用户互动

### 测试用户教育 (MSTG-STORAGE-12)

最近在职责方面变化很大，开发人员必须教育用户他们需要了解的知识。这种情况尤其发生了变化，伴随着条例在欧洲的引入 [通用数据保护条例（GDPR）](https://gdpr-info.eu/ "GDPR"). 从那时起，对用户进行有关其私人数据使用的情况及其原因成为了最好的教育。
此外，优良作法是告知用户有关他如何才能最好地使用该应用程序以确保对其信息进行安全处理的信息。
接下来，应告知用户该应用将访问哪种设备数据类型，无论是否为PII。
最后，您需要与用户共享OSS相关信息。
这四个项目都将在这里介绍。

>请注意，这是MSTG项目，而不是法律手册。 因此，在此我们将不涵盖GDPR和其他可能的相关法律。

#### 通知用户其私人信息

当您需要来自用户的个人信息来进行业务流程时，需要告知用户您对数据进行的操作以及为什么需要它。如果有第三方进行数据的实际处理，则您也应将其告知用户。最后，需要支持三个过程：

- **被遗忘的权利**：用户需要能够请求删除其数据，并说明如何删除。
- **更正数据的权利**：用户应能够随时更正其个人信息，并说明如何进行更正。
- **访问用户数据的权利**：用户应该能够请求该应用程序所拥有的所有信息，并且应该向用户说明如何请求该信息。

隐私策略可以涵盖其中大部分内容，但请确保用户可以理解。

当需要处理其他数据时，应再次征求用户的同意。在该同意请求期间，需要弄清楚用户如何才能从共享其他数据中恢复过来。同样，当需要链接用户的现有数据集时，您应该征得用户的同意。

#### 通知用户最佳安全做法

以下是可以告知用户的最佳做法的列表：

- **指纹使用**：当应用使用指纹进行身份验证并提供对高风险交易/信息的访问权限时，请告知用户有关在其他人同时向设备注册了多个指纹的情况下可能出现的问题。
- **生根/越狱**：当应用检测到生根或越狱设备时，通知用户以下事实：由于设备的越狱/生根状态，某些高风险操作会带来额外的风险。
- **特定凭据**：当用户从应用程序中获取恢复码，密码或密码（或设置一个密码）时，请指示用户不要与他人共享此密码，只有该应用程序会请求它。
- **应用分发**：如果是高风险的应用，建议传达官方分发应用的方式。否则，用户可能会使用其他渠道来下载应用程序的受威胁版本。

#### 访问设备数据

尽管Google Play商店和Apple App Store涵盖了部分内容，但您仍然需要向用户说明您的应用使用哪些服务以及原因。 例如：

- 您的应用是否需要访问联系人列表？
- 您的应用是否需要访问设备的位置服务？
- 您的应用是否使用设备标识符来标识设备？

向用户说明为什么您的应用程序需要执行此类操作。 有关此主题的更多信息，请参见[Apple人机界面指南](https://developer.apple.com/design/human-interface-guidelines/ios/app-architecture/requesting-permission/ "Apple Human Interface Guidelines") 和[Android App 权限最佳做法](https://developer.android.com/training/permissions/requesting.html#explain "Android App permissions best practices").

#### 您必须共享的其他信息（OSS信息）

根据版权法，您必须确保将应用程序中使用的任何第三方库告知用户。 对于每个第三方库，您应咨询许可，以查看是否应向用户提供某些信息（例如版权，修改，原始作者等）。 为此，最好征求专家的法律意见。 可以在此文中找到示例[Big Nerd Ranch的博客文章](https://www.bignerdranch.com/blog/open-source-licenses-and-android/ "Example on license overview"). 此外，该网站 [TL;DR - Legal](https://tldrlegal.com/ "TL;DR - Legal") 可以帮助您确定每个许可证的必要条件。

### 参考文献

#### OWASP MASVS

- MSTG-STORAGE-12: "该应用程序可向用户介绍所处理的个人身份信息的类型，以及用户在使用该应用程序时应遵循的安全最佳实践."

#### Example for open source license mentioning

- <https://www.bignerdranch.com/blog/open-source-licenses-and-android/>

#### Website to Help with Understanding Licenses

- <https://tldrlegal.com/>

#### 许可请求指南

- Apple Human Interface Guidelines - <https://developer.apple.com/design/human-interface-guidelines/ios/app-architecture/requesting-permission/>
- Android App permissions best practices - <https://developer.android.com/training/permissions/requesting.html#explain>
