# Analysis and Summary of WebLogic Coherence Component Vulnerabilities

Author: WhiteHatHui Security Research Institute @kejaly

Proofreading: WhiteHatHui Security Research Institute @r4v3zn

# Introduction

Coherence component is a core component in WebLogic and is built into WebLogic. For official introduction of Coherence component, please refer to: [https://www.oracle.com/java/coherence/]

![image.png](https://nosec.org/avatar/uploads/attach/image/eb5f9ecd34a6f8f5f46295f0001a1960/image.png)

This article covers the following vulnerabilities: CVE-2021-2135, CVE-2021-2394, CVE-2020-2555, CVE-2020-2883, CVE-2020-14645, CVE-2020-14825, CVE-2020-14841, CVE-2020-14756.

In recent years, deserialization vulnerabilities in the WebLogic Coherence component have been frequently reported. However, there is no public summary of historical deserialization vulnerabilities in the WebLogic Coherence component, which makes it difficult for those who want to learn or understand deserialization vulnerabilities in the WebLogic Coherence component. Therefore, this article provides a summary and analysis of historical deserialization vulnerabilities in the WebLogic Coherence component.

Regarding the architecture of the deserialization vulnerability exploitation chain in the Coherence component, it can be divided into two parts: one is based on the `ValueExtractor.extract` exploitation chain architecture, and the other is based on the `ExternalizableHelper` exploitation chain architecture.

# Prerequisite knowledge

To understand the history of deserialization vulnerabilities in WebLogic's Coherence component, it is necessary to first understand some interfaces and classes that are frequently involved in Coherence component deserialization vulnerabilities. They often appear in Coherence component deserialization vulnerability exploitation.

## ValueExtractor

`com.tangosol.util.ValueExtrator` is an interface:

![image.png](https://nosec.org/avatar/uploads/attach/image/67fdb310f09d10156916affc6edcb6e4/image.png)

In Coherence, many classes with names ending in `Extrator` implement this interface:

![image.png](https://nosec.org/avatar/uploads/attach/image/bd0d88c1294541ca9f717e9b1c6a2662/image.png)

This interface declares an `extract` method, and `ValueExtractor.extract` is the key to Coherence component historical vulnerabilities (part of the `ValueExtractor.extract` chain).

## ExternalizableLite

There is a `com.tangosol.io.ExternalizableLite` in the Coherence component, which extends `java.io.Serializable` and declares two methods `readExternal` and `writeExternal`.

![image.png](https://nosec.org/avatar/uploads/attach/image/f401ed76c9e3caacb2576b16bb65a355/image.png)

The `com.tangosol.io.ExternalizableLite` interface is similar to the native `java.io.Externalizable` in the JDK, but be careful not to confuse them.

## ExternalizableHelper

The serialization and deserialization of the implementation classes of the `com.tangosol.io.ExternalizableLite` interface are accomplished through the `ExternalizableHelper` class.

Let's take a closer look at how the `ExternalizableHelper` class serializes and deserializes classes that implement the `com.tangosol.io.ExternalizableLite` interface. Here, we will take the `readObject` method as an example, and readers can refer to the `writeObject` method on their own:

![image.png](https://nosec.org/avatar/uploads/attach/image/eb59a068c4685cdea676fdd5dbf2dc43/image.png)

If the passed `DataInput` is not a `PofInputStream` (the `DataInput` passed in the `ExternalizableHelper.readObject` of the Coherence component historical vulnerabilities is not a `PofInputStream`), the `ExternalizableHelper#readObject` method will call the `ExternalizableHelper#readObjectInternal` method:

In `readObjectInternal`, different branches will be entered based on the value of `nType`:

![image.png](https://nosec.org/avatar/uploads/attach/image/f363fc461b220e112fb8ab07a79d3727/image.png)

For objects that implement the `com.tangosol.io.ExternalizableLite` interface, it will enter the `readExternalizableLite` method:

![image.png](https://nosec.org/avatar/uploads/attach/image/25a45f6e2539fe77734f35559d12449f/image.png)

As we can see from `readExternalizableLite`, at line 1125, the class is loaded according to the class name, the object of this class is instantiated, and then its `readExternal()` method is called.

# Vulnerability Chain

## ValueExtractor.extract

When analyzing the deserialization exploitation chain, we can divide it into four parts: the chain header, the dangerous middle node (vulnerability point), the calling location of the dangerous middle node (trigger point), and finally the exploitation chain tail that uses this node to cause harm.

In the Coherence component's deserialization exploitation chain architecture based on `ValueExtractor.extract`, the dangerous middle node is the `ValueExtractor.extract` method.

### Vulnerability Point

#### ReflectionExtractor

The `extract` method in `ReflectionExtractor` contains reflective invocation of any object method:

![image.png](https://nosec.org/avatar/uploads/attach/image/a72ab95ed087df943b4299ab14dd1e05/image.png)

With `ChainedExtractor` and `ConstantExtractor`, it can achieve a `transform` chain call similar to cc1.

##### Related CVEs

CVE-2020-2555, CVE-2020-2883

#### MvelExtractor

The `extract` method in `MvelExtractor` executes any MVEL expression (RCE):

![image.png](https://nosec.org/avatar/uploads/attach/image/6614c3044be0832fb6bb23271166ba8a/image.png)

During serialization and deserialization, `m_sExpr` participates in the process:

![image.png](https://nosec.org/avatar/uploads/attach/image/6a2d613dfa38fab5c1b73adf85aeb931/image.png)

Therefore, `m_xExpr` is controllable, which can lead to arbitrary command execution using `MvelExtractor.extractor`.

##### Related CVEs

CVE-2020-2883

#### UniversalExtractor

The `extract` method in `UniversalExtractor` (unique to Weblogic 12.2.1.4.0) can call the `get` and `is` prefix parameterless methods in any class, which can be combined with `jdbsRowset` to remotely load malicious classes to achieve RCE through JDNI.

For more details, please refer to: https://nosec.org/home/detail/4524.html

##### Related CVEs

CVE-2020-14645, CVE-2020-14825, CVE-2020-14841

#### LockVersionExtractor

The `extract()` method in `oracle.eclipselink.coherence.integrated.internal.cache.LockVersionExtractor` can call the `getAttributeValueFromob ject()` method of any `AttributeAccessor`, assigning `Accessor` to `MethodAttributeAccessor` to achieve arbitrary invocation of any class's parameterless method.

![image.png](https://nosec.org/avatar/uploads/attach/image/de666a912641adac7893baa82526e9d1/image.png)

![image.png](https://nosec.org/avatar/uploads/attach/image/74fae0670dabf0308ae1556fd71768ae/image.png)

For specific details, please refer to: https://cloud.tencent.com/developer/article/1740557

**`MethodAttributeAccessor.getAttributeValueFromob ject`** is essentially using the existence of arbitrary parameterless method calls in `MethodAttributeAccessor.getAttributeValueFromob ject`, which was also used in CVE-2021-2394.

![image.png](https://nosec.org/avatar/uploads/attach/image/3117a80177a8cc3fc0bd8d1857a5cdc3/image.png)

##### Related CVE

CVE-2020-14825, CVE-2020-14841

#### FilterExtractor.extract

There is an arbitrary call to `AttributeAccessor.getAttributeValueFromob ject(obj)` in `filterExtractor.extract`, and assigning `this.attributeAccessor` to `MethodAttributeAccessor` can result in arbitrary parameterless method invocation.

![image.png](https://nosec.org/avatar/uploads/attach/image/a6c47ef8a944a12f92b9e34d6323a22d/image.png)

![image.png](https://nosec.org/avatar/uploads/attach/image/cb61ef0f3cf84335295dbfe402a6ddcc/image.png)

For details about `readAttributeAccessor`, please refer to CVE-2021-2394: https://blog.riskivy.com/weblogic-cve-2021-2394-rce漏洞分析/ and https://www.cnblogs.com/potatsoSec/p/15062094.html.

##### Related CVE

CVE-2021-2394

### Trigger Points

Many dangerous `ValueExtractor.extract` methods have been mentioned above. Now let's see where `ValueExtractor.extract` methods are called.

#### LimitFilter

In `LimitFilter.toString()`, there is an arbitrary `ValueExtractor.extract` method call:

![image.png](https://nosec.org/avatar/uploads/attach/image/304355d89919aeecdceb18ee0ab79f84/image.png)

As `this.m_comparator` is involved in serialization and deserialization, it can be controlled:

![image.png](https://nosec.org/avatar/uploads/attach/image/376d780654b671903b1ac056cf9de24d/image.png)

We just need to assign `this.m_comparator` to a malicious `ValueExtractor` to achieve arbitrary `ValueExtractor.extract` method calls. The `toString` method can be triggered using `BadAttributeValueExpException`, which is used in CC5.

#### Involving CVE

CVE-2020-2555

The `ExtractorComparator.compare` method is actually a bypass for the patch of CVE-2020-2555. The fix for CVE-2020-2555 modified the `Limitfiler.toString` method, which means modifying the place where `ValueExtractor.extract` method is called. CVE-2020-2883 found another place where `ValueExtractor.extract` is called, which is `ExtractorComparator.compare`.

In `ExtratorComparator.compare`, there is an arbitrary (because `this.m_extractor` participates in serialization and deserialization) call to the `ValueExtractor` `extract` method.

![image.png](https://nosec.org/avatar/uploads/attach/image/5f71210aa6b547fee62ca696084b7592/image.png)

![image.png](https://nosec.org/avatar/uploads/attach/image/31defeb660539a383310904740c41282/image.png)

The `Comparator.compare` method can be triggered through `PriorityQueue.readobject` used in CC2.

In addition, in weblogic, the `BadAttributeValueExpException.readobject` can also implement calling any `comparator.compare` method:

![image.png](https://nosec.org/avatar/uploads/attach/image/1af87a4380b61613b98404026a9d78b8/image.png)

#### Involving CVE

CVE-2020-2883, the fix is to blacklist `ReflectionExtractor` and `MvelExtractor`.

CVE-2020-14645 uses `com.tangosol.util.extractor.UniversalExtractor` to bypass, and the fix is to blacklist `UniversalExtractor`.

CVE-2020-14825 and CVE-2020-14841 use `oracle.eclipselink.coherence.integrated.internal.cache.LockVersionExtractor.LockVersionExtractor` for bypass.

## ExternalizableHelper

When analyzing the exploit chain architecture of `ExternalizableHelper`, we can still divide the chain into four parts: a chain head, a dangerous middle node (vulnerability point), another place that calls the dangerous middle node (trigger point), and finally a chain tail that exploits this node to cause harm.

In the exploit chain architecture of `ExternalizableHelper`, the dangerous middle node is the `ExternalizableLite.readExternal` method.

WebLogic filters for deserialized classes are performed when loading classes, so the classes loaded in `ExternalizableHelper.readExternalizableLite` are not restricted by the blacklist.

![image.png](https://nosec.org/avatar/uploads/attach/image/185c9e2e9abd575bb715e36f864eb552/image.png)

The specific reason is: WebLogic's blacklist is based on JEP 290. JEP 290 checks whether the class to be deserialized is a class in the blacklist based on the class name obtained during `readObject`. Here, `loadClass` is directly used to load the class, so it is not restricted by WebLogic's blacklist. (It can also be understood in this way: JEP 290 is targeted at blacklisting classes when deserializing by checking the class to be loaded. Here, the class is loaded directly through `loadClass`, which is not deserialized. Of course, in the subsequent `readExternal`, it is still restricted by WebLogic's blacklist because it goes through the deserialization process.)

The WebLogic blacklist mechanism can refer to: https://cert.360.cn/report/detail?id=c8eed4b36fe8b19c585a1817b5f10b9e, https://cert.360.cn/report/detail?id=0de94a3cd4c71debe397e2c1a036436f, https://www.freebuf.com/vuls/270372.html.

### Vulnerability Point

#### PartialResult

![8cc12e15d607796c1f1c34b0fb81521.png](https://nosec.org/avatar/uploads/attach/image/a996f34843ae3668c5858ba2b44ebad3/8cc12e15d607796c1f1c34b0fb81521.png)

The `readExternal` method of `com.tangosol.util.aggregator.TopNAggregator.PartialResult` will trigger any `comparator.compare` method.

Roughly, the principle is:

```
javaCopy code
On line 149, the comparator is passed as a parameter to the constructor of TreeMap.
Then on line 153, this.add is called, which calls this.m_map.put, which means calling the put method of TreeMap, which leads to the call of comparator.compare().
```

For a detailed analysis, please refer to: https://mp.weixin.qq.com/s/E-4wjbKD-iSi0CEMegVmZQ

Then calling `comparator.compare` can lead to `ExtractorComparator.compare` and achieve RCE.

##### Involving CVE

CVE-2020-14756 (January)

The first exploitation of `ExternalizableHelper` appeared in CVE-2020-14756. It exploits the fact that `ExternalizableHelper` deserialization loads classes through `loadClass`, so it is not restricted by the blacklist previously set by WebLogic. For specific exploits, please refer to: https://mp.weixin.qq.com/s/E-4wjbKD-iSi0CEMegVmZQ.

The fix for CVE-2020-14756 is to check the `Datainput` passed to the `readExternalizable` method, and if it is an `ObjectInputStream`, call `checkObjectInputFilter()` to check it. `checkObjectInputFilter` specifically checks using JEP 290.


![image.png](https://nosec.org/avatar/uploads/attach/image/6d859959322d32416006a22491b5b225/image.png)

CVE-2021-2135 (April)

The fix solution for the above patch only checks the case where the `DataInput` is an `ObjectInputStream`, but does not filter other types of `DataInput`.

Therefore, we only need to find other places where the `readExternalizableit` function is called and the parameter passed in is not an `ObjectInputStream`.【`ObjectInputStream` is generally the most common and usually comes in the form of a chain where the upstream is the common `readObject`, so the patch may only pay attention to the case of `ObjectInputStream`.】

Therefore, the method used to bypass CVE-2021-2135 is to set the parameter type passed to the `readExternalizableit` function to `BufferInput`.

There are two places in `ExternalizableHelper` that call `readObjectInternal`, one is `readObjectInternal`, and the other is `deserializeInternal`. `deserializeInternal` first converts `DataInput` to `BufferInput`:

![image.png](https://nosec.org/avatar/uploads/attach/image/650df25f4ea02f49eb3df591023d47c3/image.png)

So just find the place where `ExternalizableHelper.deserializeInternal` is called.

And `ExternalizableHelper.fromBinary` (on the same level as `ExternalizableHelper.readObject`) calls `deserializeInternal`, so just find a place where `ExternalizableHelper.fromBinary` is used for deserialization to connect to the later (CVE-2020-14756) exploitation chain.

Then find the places where the `getKey` and `getValue` methods of `SimpleBinaryEntry` are called, which contain calls to `ExternalizableHelper.fromBinary`.

![image.png](https://nosec.org/avatar/uploads/attach/image/14a4e538452ba78f1c543d817720c9a9/image.png)

Then in the `equals` method overridden in `com.sun.org.apache.xpath.internal.objects.XString`, `tostring` is called, which in turn calls `getKey` method.

In `ExternalizableHelper#readMap`, `map.put` is called which in turn calls `equals` method.

In `com.tangosol.util.processor.ConditionalPutAll`, `ExternalizableHelper#readMap` is called in `readExternal` method.

Then, the `AttributeHolder` chain is used to exploit the vulnerability.

For more details, please refer to: https://mp.weixin.qq.com/s/eyZfAPivCkMbNCfukngpzg

![image.png](https://nosec.org/avatar/uploads/attach/image/8b6224ac6dc4dddecc9688fbfa0f65dc/image.png)

The April vulnerability fix is: Add `simpleBianry` to the blacklist.

![image.png](https://nosec.org/avatar/uploads/attach/image/1774b0f015cb06488f787474252ed323/image.png)

```java
private static final Class[] ABBREV_CLASSES = new Class[]{String.class, ServiceContext.class, ClassTableEntry.class, JVMID.class, AuthenticatedUser.class, RuntimeMethodDesc riptor.class, Immutable.class};
```

#### filterExtractor

In the `filterExtractor.reaExternal` method, the `readAttributeAccessor()` method directly creates a new `MethodAttributeAccessor` object.

![image.png](https://nosec.org/avatar/uploads/attach/image/1764bc82fcfeda9dbab77c9019a7370d/image.png)

![image.png](https://nosec.org/avatar/uploads/attach/image/df811794f81ac9861843e101cf43c3c2/image.png)

Subsequently, in the `filterExtractor.extract` function, a call to `this.attributeAccessor.getAttributeValueFromObject` will lead to the invocation of any parameterless method.

![image.png](https://nosec.org/avatar/uploads/attach/image/61a0683e5609a800aa46ac11ce647739/image.png)

##### Involving  CVE

CVE-2021-2394 (April)

![image.png](https://nosec.org/avatar/uploads/attach/image/8266211c785125787e1eaee54f848bb7/image.png)

In the April patch, filtering was applied to the `DataInput` stream of OIS, so instantiating a malicious class directly through `newInstance` has been prevented (CVE-2021-2135 bypassed the filter using `bufferinputStream`). Therefore, it is necessary to find another `readExternal` method that is not on the blacklist.

CVE-2021-2394 exploits the `filterExtractor.readExternal` method to achieve the attack.

For more information, please refer to: https://blog.riskivy.com/weblogic-cve-2021-2394-rce漏洞分析/ and https://www.cnblogs.com/potatsoSec/p/15062094.html

The triggering points of `ExternalizableHelper.readExternal` are `ExternalizableHelper.readObject` and `ExternalizableHelper.fromBinary`. In CVE-2021-2135, the fix for CVE-2020-14756 only focused on `ExternalizableHelper.readObject` and added restrictions only in that method, but did not consider `ExternalizableHelper.fromBinary`, leading to a bypass.

`ExternalizableHelper.readObject` can be triggered using `com.tangosol.coherence.servlet.AttributeHolder`, which implements the `java.io.Externalizable` interface and calls `ExternalizableHelper.readObject(in)` in its `readExternal` method.

![image.png](https://nosec.org/avatar/uploads/attach/image/6ae0e00de820888168a95428b7757f41/image.png)

The triggering of `ExternalizableHelper.fromBinary` is more complex and can be referred to at: https://mp.weixin.qq.com/s/eyZfAPivCkMbNCfukngpzg

# Postscript

Many of the weblogic Coherence deserialization vulnerabilities are related, and for a specific vulnerability, it is likely to use some of the previous vulnerabilities in the chain. In fact, not only weblogic, but other deserialization chains in Java are also like this, and many situations involve one chain using a part of another chain. Therefore, in the learning process, it is important to summarize and analyze the vulnerabilities of a component or library together. Finally, I hope this article can help other friends who are learning deserialization.

# References

https://nosec.org/home/detail/4524.html

https://cloud.tencent.com/developer/article/1740557

[https://blog.riskivy.com/weblogic-cve-2021-2394-rce%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/](https://blog.riskivy.com/weblogic-cve-2021-2394-rce漏洞分析/)

https://www.cnblogs.com/potatsoSec/p/15062094.html

https://cert.360.cn/report/detail?id=c8eed4b36fe8b19c585a1817b5f10b9e

https://cert.360.cn/report/detail?id=0de94a3cd4c71debe397e2c1a036436f

https://www.freebuf.com/vuls/270372.html

https://mp.weixin.qq.com/s/E-4wjbKD-iSi0CEMegVmZQ

https://mp.weixin.qq.com/s/eyZfAPivCkMbNCfukngpzg



<br/>

<br/>
[Goby Official URL](https://gobies.org/)

If you have a functional type of issue, you can raise an issue on GitHub or in the discussion group below:

1. GitHub issue: https://github.com/gobysec/Goby/issues
2. Telegram Group: http://t.me/gobies (Community advantage: Stay updated with the latest information about Goby features, events, and other announcements in real-time.) 
3. Telegram Channel: https://t.me/joinchat/ENkApMqOonRhZjFl 
4. Twitter：[https://twitter.com/GobySec](https://twitter.com/GobySec)
