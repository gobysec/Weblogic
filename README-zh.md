[English](https://github.com/gobysec/Weblogic/edit/main/README.md)｜ [中文](https://github.com/gobysec/Weblogic/edit/main/README-zh.md)

# WebLogic漏洞研究专题

## [*Weblogic CVE-2023-21931 漏洞挖掘技巧：后反序列化利用* ](https://github.com/gobysec/Weblogic/edit/main/WebLogic_CVE-2023-21931_zh_CN.md.md)

摘要：近些年，Weblogic反序列化漏洞一直围绕着反序列化的触发点进行漏洞挖掘，事实上还有很多存在反序列化但无法实时利用的点，在大家平时的漏洞挖掘中容易忽略。在行业内也有一些关于”后反序列化“的进一步讨论，这些看似无法利用的漏洞，其实可以通过一些后续的技巧完成稳定的利用效果。例如，进行`bind()`或`rebind()`操作后，并没有触发漏洞，此时可以尝试其他方法如`lookup()`、`lookupLink()`等触发漏洞。
通过这种思路我们发现了两个Weblogic的后反序列化漏洞（CVE-2023-21931、CVE-2023-21839），获得了Oracle的官方确认。本文以这两个Weblogic漏洞为例，分享"后反序列化漏洞"的利用思路。我们相信还有很多这类的漏洞在未来会逐渐被挖掘出来，希望本篇文章能够给大家一些启发。

[CVE-2023-21931 demo](https://github.com/gobysec/GobyVuls/blob/master/CVE-2023-21931.md)


## [*越语言的艺术：Weblogic序列化漏洞与IIOP协议* ](https://github.com/gobysec/Weblogic/blob/main/Weblogic_Serialization_Vulnerability_and_IIOP_Protocol_zh_CN.md)

摘要：Weblogic 的序列化漏洞主要依赖于 T3 和 IIOP 协议，这两种协议在通信交互的过程中存在如跨语言、网络传输等方面的诸多问题，会给漏洞的检测和利用带来许多不便。在白帽汇安全研究院的理念中，漏洞检测和利用是一项需要创造性的工作，应该以最简洁，高效的方式实现，这样才能确保漏洞的跨平台和实用性。因此，我们通过跨语言方式实现 IIOP 协议通信，以解决出现的序列化漏洞问题。
在 Goby 中的 CVE-2023-21839 漏洞中，我们成功的实现了IIOP 协议跨语言通信的方案，实现了完美漏洞的检测与利用效果。

## [*WebLogic Coherence 组件漏洞总结分析* ](https://github.com/gobysec/Weblogic/blob/main/WebLogic_Coherence_Component_zh_CN.md)

摘要：本文涉及的漏洞有：CVE-2021-2135 ，CVE-2021-2394，CVE-2020-2555，CVE-2020-2883，CVE-2020-14645，CVE-2020-14825 ， CVE-2020-14841，CVE-2020-14756
近些年，weblogic Coherence 组件反序列化漏洞被频繁爆出，苦于网上没有公开对 weblogic Coherence 组件历史反序列化漏洞的总结，导致很多想入门或者了解 weblogic Coherence 组件反序列化漏洞的朋友不知道该怎么下手，于是本文便对 weblogic Coherence 组件历史反序列化漏洞做出了一个总结和分析。

## [*Weblogic CVE-2021-2394反序列化漏洞分析* ](https://github.com/gobysec/Weblogic/blob/main/Analysis_of_CVE-2021-2394_zh_CN.md)

摘要：在2021年7月21日，Oracle官方发布了一系列安全更新。涉及旗下产品（Weblogic Server、Database Server、Java SE、MySQL等）的 342 个漏洞。其中，Oracle WebLogic Server 产品中有高危漏洞，漏洞编号为 CVE-2021-2394，CVSS 评分9.8分，影响多个 WebLogic 版本，且漏洞利用难度低，可基于 T3 和 IIOP 协议执行远程代码。

## [*Weblogic 远程命令执行漏洞（CVE-2020-14645）分析* ](https://github.com/gobysec/Weblogic/blob/main/Analysis_of_CVE-2020-14645_zh_CN.md)

摘要：近期公布的关于 Weblogic 的反序列化RCE漏洞 CVE-2020-14645，是对 CVE-2020-2883的补丁进行绕过。之前的 CVE-2020-2883 本质上是通过 ReflectionExtractor 调用任意方法，从而实现调用 Runtime 对象的 exec 方法执行任意命令，补丁将 ReflectionExtractor 列入黑名单，那么可以使用 UniversalExtractor 重新构造一条利用链。UniversalExtractor 任意调用 get、is方法导致可利用 JDNI 远程动态类加载。UniversalExtractor 是 Weblogic 12.2.1.4.0 版本中独有的，本文也是基于该版本进行分析。

## [*Weblogic 远程命令执行漏洞（CVE-2020-14644）分析* ](https://github.com/gobysec/Weblogic/blob/main/Analysis_of_CVE-2020-14644_zh_CN.md)

2020 年 7 月 15 日，Oracle 发布大量安全修复补丁，其中 CVE-2020-14644 漏洞被评分为 9.8 分，影响版本为 12.2.1.3.0、12.2.1.4.0, 14.1.1.0.0 。本文基于互联网公开的 POC 进行复现、分析，最终实现无任何限制的 defineClass + 实例化，进行实现 RCE。

<br/>

<br/>

**[Goby 官网: https://gobysec.net/](https://gobysec.net/)** 

如果您有任何反馈建议，您可通过提交 issue 或是以下方式联系我们：

1. GitHub issue: [https://github.com/gobysec/Goby/issues](https://github.com/gobysec/Goby/issues)
2. 微信群：关注公众号“GobySec“，回复暗号”加群“ （社群优势：可第一时间了解Goby功能发布、活动等咨询）
3. Telegram Group: [http://t.me/gobies](http://t.me/gobies) 
4. 推特：[https://twitter.com/GobySec](https://twitter.com/GobySec)
