[English](https://github.com/gobysec/Weblogic/edit/main/README.md)｜ [中文](https://github.com/gobysec/Weblogic/edit/main/README-zh.md)

# Research topic on WebLogic vulnerabilities

## [*Weblogic CVE-2023-21931 vulnerability exploration technique: post-deserialization exploitation* ](https://github.com/gobysec/Weblogic/blob/main/WebLogic_CVE-2023-21931_en_US.md)

Abstract：In recent years, Weblogic deserialization vulnerabilities have been discovered and focused on the triggering point of deserialization. However, there are many points that involve deserialization but cannot be exploited in real-time, which are easily overlooked during regular vulnerability research. There have been further discussions in the industry about "post-deserialization" vulnerabilities, where seemingly unexploitable vulnerabilities can actually be exploited through subsequent techniques. For example, if the vulnerability is not triggered after performing a `bind()` or `rebind()` operation, you can try other methods such as `lookup()` or` lookupLink()` to trigger the vulnerability.
Using this approach, we have discovered two Weblogic post-deserialization vulnerabilities (CVE-2023-21931, CVE-2023-21839), which have been officially confirmed by Oracle. In this article, we will use these two Weblogic vulnerabilities as examples to share the thought process behind exploiting post-deserialization vulnerabilities. We believe that there are many similar vulnerabilities that will be gradually discovered in the future, and we hope this article can provide some inspiration for researchers.

[CVE-2023-21931](https://github.com/gobysec/GobyVuls/blob/master/CVE-2023-21931.md)


## [*The Art of Cross-Languages: Weblogic Serialization Vulnerability and IIOP Protocol* ](https://github.com/gobysec/Weblogic/blob/main/Weblogic_Serialization_Vulnerability_and_IIOP_Protocol_en_US.md)

Abstract：The Weblogic serialization vulnerability mainly depends on the T3 and IIOP protocols, which have many issues in communication interaction, such as cross-language and network transmission, which can bring many inconveniences to vulnerability detection and exploitation. In the philosophy of WhiteHat Labs, vulnerability detection and exploitation is a creative work that should be implemented in the most concise and efficient way to ensure cross-platform and practicality of the vulnerability. Therefore, we have implemented a cross-language IIOP protocol communication solution to solve the serialization vulnerability problem.

## [*Analysis and Summary of WebLogic Coherence Component Vulnerabilities* ](https://github.com/gobysec/Weblogic/blob/main/WebLogic_Coherence_Component_en_US.md)

Abstract：This article covers the following vulnerabilities: CVE-2021-2135, CVE-2021-2394, CVE-2020-2555, CVE-2020-2883, CVE-2020-14645, CVE-2020-14825, CVE-2020-14841, CVE-2020-14756.
In recent years, deserialization vulnerabilities in the WebLogic Coherence component have been frequently reported. However, there is no public summary of historical deserialization vulnerabilities in the WebLogic Coherence component, which makes it difficult for those who want to learn or understand deserialization vulnerabilities in the WebLogic Coherence component. Therefore, this article provides a summary and analysis of historical deserialization vulnerabilities in the WebLogic Coherence component.

## [*Analysis of Weblogic CVE-2021-2394 Deserialization Vulnerability* ](https://github.com/gobysec/Weblogic/blob/main/Analysis_of_CVE-2021-2394_en_US.md)

Abstract：On July 21, 2021, Oracle released a series of security updates, involving 342 vulnerabilities in its products, including Weblogic Server, Database Server, Java SE, MySQL, etc. Among them, there is a high-risk vulnerability in the Oracle WebLogic Server product, with the vulnerability number CVE-2021-2394 and a CVSS score of 9.8. It affects multiple versions of WebLogic and can be exploited remotely with low difficulty using the T3 and IIOP protocols.


## [*Analysis of Weblogic Remote Command Execution Vulnerability (CVE-2020-14645)* ](https://github.com/gobysec/Weblogic/blob/main/Analysis_of_CVE-2020-14645_en_US.md)

Abstract：The recently disclosed deserialization RCE vulnerability CVE-2020-14645 in Weblogic is a bypass of CVE-2020-2883 patch. CVE-2020-2883 essentially called arbitrary methods through ReflectionExtractor, which then executed arbitrary commands using the exec method of the Runtime object. The patch blacklisted ReflectionExtractor, so a new exploit chain could be constructed using UniversalExtractor. UniversalExtractor can call the get and is methods arbitrarily, which leads to the exploitation of JDNI remote dynamic class loading. UniversalExtractor is unique to Weblogic version 12.2.1.4.0, and this article analyzes it based on that version.

## [Analysis of Weblogic Remote Command Execution Vulnerability (CVE-2020-14644)](https://github.com/gobysec/Weblogic/blob/main/Analysis_of_CVE-2020-14644_en_US.md)

Abstract：On July 15, 2020, Oracle released a large number of security patches, among which the CVE-2020-14644 vulnerability was rated 9.8 in severity, affecting versions 12.2.1.3.0, 12.2.1.4.0, and 14.1.1.0.0. This article is based on publicly available proof-of-concept (POC) code from the internet for reproduction and analysis. Eventually, we achieved unrestricted defineClass + instantiation, which resulted in remote code execution (RCE).

<br/>

<br/>
[Goby Official URL](https://gobies.org/)

If you have a functional type of issue, you can raise an issue on GitHub or in the discussion group below:

1. GitHub issue: https://github.com/gobysec/Goby/issues
2. Telegram Group: http://t.me/gobies (Community advantage: Stay updated with the latest information about Goby features, events, and other announcements in real-time.) 
3. Telegram Channel: https://t.me/joinchat/ENkApMqOonRhZjFl 
4. Twitter：[https://twitter.com/GobySec](https://twitter.com/GobySec)
