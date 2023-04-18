Artical: *[The Art of Cross-Languages: Weblogic Serialization Vulnerability and IIOP Protocol]([https://github.com/gobysec/Weblogic](https://github.com/gobysec/Weblogic/edit/main/Weblogic%20Serialization%20Vulnerability%20and%20IIOP%20Protocol.md))*

Abstract：The Weblogic serialization vulnerability mainly depends on the T3 and IIOP protocols, which have many issues in communication interaction, such as cross-language and network transmission, which can bring many inconveniences to vulnerability detection and exploitation. In the philosophy of WhiteHat Labs, vulnerability detection and exploitation is a creative work that should be implemented in the most concise and efficient way to ensure cross-platform and practicality of the vulnerability. Therefore, we have implemented a cross-language IIOP protocol communication solution to solve the serialization vulnerability problem.



Artical: *[Research on WebLogic After-Deserialization](https://github.com/gobysec/Weblogic/blob/main/Research%20on%20WebLogic%20After-Deserialization.md)*

Abstract：In recent years, Weblogic deserialization vulnerabilities have been discovered and focused on the triggering point of deserialization. However, there are many points that involve deserialization but cannot be exploited in real-time, which are easily overlooked during regular vulnerability research. There have been further discussions in the industry about "post-deserialization" vulnerabilities, where seemingly unexploitable vulnerabilities can actually be exploited through subsequent techniques. For example, if the vulnerability is not triggered after performing a `bind()` or `rebind()` operation, you can try other methods such as `lookup()` or` lookupLink()` to trigger the vulnerability.
Using this approach, we have discovered two Weblogic post-deserialization vulnerabilities (CVE-2023-21931, CVE-2023-21839), which have been officially confirmed by Oracle. In this article, we will use these two Weblogic vulnerabilities as examples to share the thought process behind exploiting post-deserialization vulnerabilities. We believe that there are many similar vulnerabilities that will be gradually discovered in the future, and we hope this article can provide some inspiration for researchers.
