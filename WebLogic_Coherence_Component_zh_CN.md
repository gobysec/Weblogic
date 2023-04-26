作者：白帽汇安全研究院@kejaly

校对：白帽汇安全研究院@r4v3zn

# 前言

Coherence 组件是 WebLogic 中的一个核心组件，内置在 WebLogic 中。关于 Coherence 组件的官方介绍：https://www.oracle.com/cn/java/coherence/

![image.png](https://nosec.org/avatar/uploads/attach/image/eb5f9ecd34a6f8f5f46295f0001a1960/image.png)

本文涉及的漏洞有：CVE-2021-2135 ，CVE-2021-2394，CVE-2020-2555，CVE-2020-2883，CVE-2020-14645，CVE-2020-14825 ， CVE-2020-14841，CVE-2020-14756

近些年，weblogic Coherence 组件反序列化漏洞被频繁爆出，苦于网上没有公开对 weblogic Coherence 组件历史反序列化漏洞的总结，导致很多想入门或者了解 weblogic Coherence 组件反序列化漏洞的朋友不知道该怎么下手，于是本文便对 weblogic Coherence 组件历史反序列化漏洞做出了一个总结和分析。

关于 Coherence 组件反序列化漏洞利用链的架构，我把他分为两个，一个是基于 `ValueExtractor.extract` 的利用链架构，另一个则是基于 `ExternalizableHelper` 的利用链架构。

# 前置知识

想理清 WebLogic 的 Coherence 组件历史反序列化漏洞需要首先了解一些 Coherence 组件反序列化漏洞中经常会涉及的一些接口和类。他们在 Coherence 组件反序列化漏洞利用中经常出现。

## ValueExtractor

`com.tangosol.util.ValueExtrator` 是一个接口：

![image.png](https://nosec.org/avatar/uploads/attach/image/67fdb310f09d10156916affc6edcb6e4/image.png)

在 Coherence 中 很多名字以 `Extrator` 结尾的类都实现了这个接口：

![image.png](https://nosec.org/avatar/uploads/attach/image/bd0d88c1294541ca9f717e9b1c6a2662/image.png)

这个接口中声明了一个 `extract` 方法，而 `ValueExtractor.extract` 正是 Coherence 组件历史漏洞（ `ValueExtractor.extract` 链部分 ）的关键。

## ExternalizableLite

Coherence 组件中存在一个 `com.tangosol.io.ExternalizableLite`，它继承了 `java.io.Serializable`，另外声明了 `readExternal` 和 `writeExternal` 这两个方法。

![image.png](https://nosec.org/avatar/uploads/attach/image/f401ed76c9e3caacb2576b16bb65a355/image.png)

`com.tangosol.io.ExternalizableLite` 接口 和 jdk 原生的 `java.io.Externalizable` 很像，注意不要搞混了。

## ExternalizableHelper

上面提到的 `com.tangosol.io.ExternalizableLite` 接口的实现类的序列化和反序列化操作，都是通过 `ExternalizableHelper` 这个类来完成的。

我们可以具体看 `ExternalizableHelper` 这个类是怎么对实现 `com.tangosol.io.ExternalizableLite` 接口的类进行序列化和反序列化的，这里以 `readob ject` 方法为例，`writeob ject` 读者可自行去查看：

![image.png](https://nosec.org/avatar/uploads/attach/image/eb59a068c4685cdea676fdd5dbf2dc43/image.png)

如果传入的`DataInput` 不是 `PofInputStream` 的话（Coherence 组件历史漏洞 涉及到的 `ExternalizableHelper.readob ject` 传入的 `DataInput` 都不是 `PofInputStream`），`ExternalizableHelper#readob ject` 中会调用 `ExternalizableHelper#readob jectInternal` 方法：

`readob jectInternal` 中会根据传入的中 `nType` 进行判断，进入不同的分支：

![image.png](https://nosec.org/avatar/uploads/attach/image/f363fc461b220e112fb8ab07a79d3727/image.png)

对于实现 `com.tangosol.io.ExternalizableLite` 接口的对象，会进入到 `readExternalizableLite` 方法：

![image.png](https://nosec.org/avatar/uploads/attach/image/25a45f6e2539fe77734f35559d12449f/image.png)

可以看到在 `readExternalizableLite` 中 1125 行会根据类名加载类，然后并且实例化出这个类的对象，然后调用它的 `readExternal()` 方法。

# 漏洞链

## ValueExtractor.extract

我们在分析反序列化利用链的时候，可以把链分为四部分，一个是链头，一个是危险的中间的节点（漏洞点），另一个是调用危险中间节点的地方（触发点），最后一个则是利用这个节点去造成危害的链尾。

在 Coherence 组件 `ValueExtractor.extract` 利用链架构中，这个危险的中间节点就是 `ValueExtractor.extract` 方法。

### 漏洞点

#### ReflectionExtractor

`ReflectionExtractor` 中的 `extract` 方法含有对任意对象方法的反射调用：

![image.png](https://nosec.org/avatar/uploads/attach/image/a72ab95ed087df943b4299ab14dd1e05/image.png)

配合 `ChainedExtractor` 和 `ConstantExtractor` 可以实现类似 cc1 中的 `transform` 链的调用。

##### 涉及 CVE

CVE-2020-2555，CVE-2020-2883

#### MvelExtractor

`MvelExtrator` 中的 `extract` 方法，会执行任意一个 MVEL 表达式（RCE）：

![image.png](https://nosec.org/avatar/uploads/attach/image/6614c3044be0832fb6bb23271166ba8a/image.png)

而在序列化和反序列化的时候 `m_sExpr` 会参与序列化和反序列化：

![image.png](https://nosec.org/avatar/uploads/attach/image/6a2d613dfa38fab5c1b73adf85aeb931/image.png)

所以 `m_xExpr` 可控，所以就导致可以利用 `MvelExtrator.extrator` 来达到执行任意命令的作用。

##### 涉及 CVE

CVE-2020-2883

#### UniversalExtractor

`UniversalExtractor`（Weblogic 12.2.1.4.0 独有） 中的 `extract` 方法，可以调用任意类中的的 `get` 和 `is` 开头的无参方法，可以配合 `jdbsRowset`，利用 JDNI 来远程加载恶意类实现 RCE。

具体细节可以参考：https://nosec.org/home/detail/4524.html

##### 涉及 CVE

CVE-2020-14645，CVE-2020-14825 ， CVE-2020-14841

#### LockVersionExtractor

`oracle.eclipselink.coherence.integrated.internal.cache.LockVersionExtractor` 中的 `extract()` 方法，可以调用任意 `AttributeAccessor` 的 `getAttributeValueFromob ject` 方法，赋值 `Accessor` 为 `MethodAttributeAccessor` 进而可以实现调用任意类的无参方法。

![image.png](https://nosec.org/avatar/uploads/attach/image/de666a912641adac7893baa82526e9d1/image.png)

![image.png](https://nosec.org/avatar/uploads/attach/image/74fae0670dabf0308ae1556fd71768ae/image.png)

具体细节可参考：https://cloud.tencent.com/developer/article/1740557

**`MethodAttributeAccessor.getAttributeValueFromob ject`**，本质是利用`MethodAttributeAccessor.getAttributeValueFromob ject`中存在任意无参方法调用，在 CVE-2021-2394 中也利用到了。

![image.png](https://nosec.org/avatar/uploads/attach/image/3117a80177a8cc3fc0bd8d1857a5cdc3/image.png)

##### 涉及 CVE

CVE-2020-14825 ， CVE-2020-14841

#### FilterExtractor.extract

`filterExtractor.extract` 中存在任意 `AttributeAccessor.getAttributeValueFromob ject(obj)` 的调用，赋值 this.attributeAccessor 为上面说的`MethodAttributeAccessor` 就可以导致任意无参方法的调用。

![image.png](https://nosec.org/avatar/uploads/attach/image/a6c47ef8a944a12f92b9e34d6323a22d/image.png)

![image.png](https://nosec.org/avatar/uploads/attach/image/cb61ef0f3cf84335295dbfe402a6ddcc/image.png)

关于 `readAttributeAccessor` 的细节可以看 CVE-2021-2394：[https://blog.riskivy.com/weblogic-cve-2021-2394-rce%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/](https://blog.riskivy.com/weblogic-cve-2021-2394-rce漏洞分析/) 和 https://www.cnblogs.com/potatsoSec/p/15062094.html 。

##### 涉及 CVE

CVE-2021-2394

### 触发点

上面例举出了很多危险的 `ValueExtractor.extract` 方法，接下来再看看哪里存在调用 `ValueExtractor.extract` 方法的地方。

#### Limitfiler

Limitfiler 中 `Limitfiler.toString` 中存在任意 `ValueExtractor.extract` 方法调用：

![image.png](https://nosec.org/avatar/uploads/attach/image/304355d89919aeecdceb18ee0ab79f84/image.png)

由于 `this.m_comparator` 参与序列化和反序列化，所以可控：

![image.png](https://nosec.org/avatar/uploads/attach/image/376d780654b671903b1ac056cf9de24d/image.png)

我们只需要赋值 `this.m_comparator` 为 恶意的 `ValueExtractor` 就可以实现任意 `ValueExtractor .extract` 方法的调用。`toString` 方法，则可以利用 CC5 中用到的 `BadAttributeValueExpException` 来触发。

##### 涉及 CVE

CVE-2020-2555

#### ExtractorComparator

`ExtractorComparator.compare` ，其实是针对 CVE-2020-2555 补丁的绕过，CVE-2020-2555 的修复方法中修改了 `Limitfiler.toString` 方法，也就是说修改了一个调用 `ValueExtractor.extract` 方法的地方。 而 CVE-2020-2883 则找到另一个调用 `ValueExtractor.extract` 的地方，也就是 `ExtractorComparator.compare` 。

在`ExtratorComparator.compare` 中存在任意（因为 `this.m_extractor` 参与序列化和反序列化） `ValueExtractor` 的 `extract` 方法调用。

![image.png](https://nosec.org/avatar/uploads/attach/image/5f71210aa6b547fee62ca696084b7592/image.png)

![image.png](https://nosec.org/avatar/uploads/attach/image/31defeb660539a383310904740c41282/image.png)

`Comparator.compare 方法，则可以通过 CC2 中用到的`PriorityQueue.readob ject` 来触发。

另外在 weblogic 中， `BadAttributeValueExpException.readob ject` 中也可以实现调用任意 `compartor.compare`方法：

![image.png](https://nosec.org/avatar/uploads/attach/image/1af87a4380b61613b98404026a9d78b8/image.png)

##### 涉及 CVE

CVE-2020-2883，修复方法是将 `ReflectionExtractor` 和 `MvelExtractor` 加入了黑名单 。

CVE-2020-14645 使用 `com.tangosol.util.extractor.UniversalExtractor` 绕过，修复方法将 `UniversalExtractor` 加入黑名单。

CVE-2020-14825，CVE-2020-14841 使用 `oracle.eclipselink.coherence.integrated.internal.cache.LockVersionExtractor.LockVersionExtractor` 进行绕过。

## ExternalizableHelper

在分析`ExternalizableHelper` 利用链架构的时候，我们依然可以把链分为四部分，一个是链头，一个是危险的中间的节点（漏洞点），另一个是调用危险中间节点的地方（触发点），最后一个则是利用这个节点去造成危害的链尾。

在 `ExternalizableHelper` 利用链架构中，这个危险的中间节点就是 `ExternalizableLite.readExternal` 方法。

weblogic 对于反序列化类的过滤都是在加载类时进行的，因此在 `ExternalizableHelper.readExternalizableLite` 中加载的 class 是不受黑名单限制的。

![image.png](https://nosec.org/avatar/uploads/attach/image/185c9e2e9abd575bb715e36f864eb552/image.png)

具体原因是：weblogic 黑名单是基于 jep 290 ，jep 290 是在 `readob ject` 的时候，在得到类名后去检查要反序列化的类是否是黑名单中的类。而这里直接使用的 `loadClass` 去加载类，所以这里不受 weblogic 黑名单限制。（也可以这么理解： jep 290 是针对在反序列化的时候，通过对要加载类进行黑名单检查。而这里直接通过 `loadClass` 加载，并没有通过反序列化，和反序列化是两码事，当然在后续 `readExternal` 的时候还是受 weblogic 黑名单限制，因为走的是反序列化那一套）

weblogic 黑名单机制可以参考：https://cert.360.cn/report/detail?id=c8eed4b36fe8b19c585a1817b5f10b9e，https://cert.360.cn/report/detail?id=0de94a3cd4c71debe397e2c1a036436f，https://www.freebuf.com/vuls/270372.html

### 漏洞点

#### PartialResult

![8cc12e15d607796c1f1c34b0fb81521.png](https://nosec.org/avatar/uploads/attach/image/a996f34843ae3668c5858ba2b44ebad3/8cc12e15d607796c1f1c34b0fb81521.png)

`com.tangosol.util.aggregator.TopNAggregator.PartialResult` 的 `readExternal` 会触发任意 `compartor.compare` 方法。

大致原理：

```java
在 149 行会把comparator 作为参数传入 TreeMap 的构造函数中。

然后 153 行，会调用 this.add ,this.add 会调用 this.m_map.put 方法，也就是说调用了 TreeMap 的 put 方法，这就导致了 comparator.compare()的调用。
```

具体分析见：https://mp.weixin.qq.com/s/E-4wjbKD-iSi0CEMegVmZQ

然后调用 `comparator.compare` 就可以接到 `ExtractorComparator.compare` 那里去了，从而实现 rce 。

##### 涉及 CVE

CVE-2020-14756 （1月）

`ExternalizableHelper` 的利用第一次出现是在 CVE-2020-14756 中。利用的正是 `ExternalizableHelper` 的反序列化通过 `loadClass` 加载类，所以不受 weblogic 之前设置的黑名单的限制。具体利用可以参考：https://mp.weixin.qq.com/s/E-4wjbKD-iSi0CEMegVmZQ

CVE-2020-14756 的修复方法则是对 `readExternalizable` 方法传入的 `Datainput` 检查，如果是 `ob jectInputStream` 就调用 checkob jectInputFilter() 进行检查，`checkob jectInputFilter` 具体是通过 jep290 来检查的。

![image.png](https://nosec.org/avatar/uploads/attach/image/6d859959322d32416006a22491b5b225/image.png)

CVE-2021-2135 （4月）

上面补丁的修复方案 只是检查了 `DataInput` 为 `ob jectInputStream` 的情况, 却没有过滤其他 `DataInput` 类型 。

那我们只需要找其他调用 `readExternalizableit` 函数的地方,并且传入的参数不是 `ob jectInputStream` 就可以了。【`ob jectInputStream` 一般是最常见的,通常来说是 `readob ject` =>`readob jectInternal` =>`readExternalizableite` 这种链,也就是上游是常见的 `readob ject`, 所以补丁就可能只注意到ob jectInputStream 的情况。】

所以CVE-2021-2135 绕过的方法就是设置传入 `readExternalizableite` 函数的参数类型为 `BufferInput` 来进行绕过。

`ExternalizableHelper` 中调用 `readob jectInternal` 的地方有两处,一处是 `readob jectInternal` , 另一处则是 `deserializeInternal` 。而 deserializeInternal 会先把 `DataInput` 转化为 `BufferInut` ：

![image.png](https://nosec.org/avatar/uploads/attach/image/650df25f4ea02f49eb3df591023d47c3/image.png)

所以只要找调用 `ExternalizableHelper .deserializeInternal` 的地方。

而 `ExternalizableHelper.fromBinary` （和 `ExternalizableHelper.readob ject` 平级的关系 ）里就调用了 `deserializeInternal` , 所以只需要找到一个地方用 来 `ExternalizableHelper.fromBinary` 来反序列化就可以接上后面的（CVE-2020-14756）利用链了。

然后就是找 调用了 `ExternalizableHelper.fromBinary` 的方法的地方。`SimpleBinaryEntry` 中的 `getKey` 和 `getValue`方法中存在 `ExternalizableHelper.fromBinary` 的调用，所以就只要找到调用 `getKey` 和 `getValue` 的地方就可以了。

![image.png](https://nosec.org/avatar/uploads/attach/image/14a4e538452ba78f1c543d817720c9a9/image.png)

然后在 `com.sun.org.apache.xpath.internal.ob jects.XString`重写的`equals`方法里调用了 `tostring` ，在 `tostring` 中调用了 `getKey` 方法。

`ExternalizableHelper#readMap` 中会调用 `map.put` ，`map.put` 会调用 `equals` 方法。

`com.tangosol.util.processor.ConditionalPutAll` 的 `readExteranl` 中调用了 `ExternalizableHelper#readMap` 方法。

然后再套上 `AttributeHolder` 链头就可以了。

具体可以参考：https://mp.weixin.qq.com/s/eyZfAPivCkMbNCfukngpzg

![image.png](https://nosec.org/avatar/uploads/attach/image/8b6224ac6dc4dddecc9688fbfa0f65dc/image.png)

4月漏洞修复则是：添加`simpleBianry` 到黑名单。

![image.png](https://nosec.org/avatar/uploads/attach/image/1774b0f015cb06488f787474252ed323/image.png)

```java
private static final Class[] ABBREV_CLASSES = new Class[]{String.class, ServiceContext.class, ClassTableEntry.class, JVMID.class, AuthenticatedUser.class, RuntimeMethodDesc riptor.class, Immutable.class};
```

#### filterExtractor

`filterExtractor.reaExternal` 方法中的 `readAttributeAccessor()` 方法会直接 `new` 一个 `MethodAttributeAccessor` 对象。

![image.png](https://nosec.org/avatar/uploads/attach/image/1764bc82fcfeda9dbab77c9019a7370d/image.png)

![image.png](https://nosec.org/avatar/uploads/attach/image/df811794f81ac9861843e101cf43c3c2/image.png)

随后在 `filterExtractor.extract` 函数中会因为调用 `this.attributeAccessor.getAttributeValueFromob ject` 进而导致任意无参方法的调用。

![image.png](https://nosec.org/avatar/uploads/attach/image/61a0683e5609a800aa46ac11ce647739/image.png)

##### 涉及 CVE

CVE-2021-2394 （4月）

![image.png](https://nosec.org/avatar/uploads/attach/image/8266211c785125787e1eaee54f848bb7/image.png)

在4月的补丁中，对 ois 的 `DataInput` 流进行了过滤，所以直接通过 `newInstance` 实例化恶意类的方式已经被阻止（CVE-2021-2135 通过 `bufferinputStream` 进行了绕过），所以需要重新寻找其他不在黑名单中的 `readExternal` 方法。

CVE-2021-2394 中就是利用 `filterExtractor.readExternal` 来进行突破。

具体可以参考：[https://blog.riskivy.com/weblogic-cve-2021-2394-rce%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/](https://blog.riskivy.com/weblogic-cve-2021-2394-rce漏洞分析/) 和 https://www.cnblogs.com/potatsoSec/p/15062094.html

### 触发点

`ExternalizableHelper.readExternal` 的触发点有 `ExternalizableHelper.readob ject` 和 `ExternalizableHelper.fromBinary` 这两个。其中 CVE-2021-2135 则就是因为在 CVE-2020-14756 的修复方法中，只注意到了 `ExternalizableHelper.readob ject` ，只在`ExternalizableHelper.readob ject` 里面做了限制，但是没有考虑到 `ExternalizableHelper.fromBinary` 从而导致了绕过。

`ExternalizableHelper.readob ject`可以利用 `com.tangosol.coherence.servlet.AttributeHolder`来触发，`com.tangosol.coherence.servlet.AttributeHolder` 实现了 `java.io.Externalizabe` 接口，并且他的`readExternal` 方法 调用了 `ExternalizableHelper.readob ject(in)` 。

![image.png](https://nosec.org/avatar/uploads/attach/image/6ae0e00de820888168a95428b7757f41/image.png)

`ExternalizableHelper.fromBinary` 的触发则较为复杂一些，具体可以参考：https://mp.weixin.qq.com/s/eyZfAPivCkMbNCfukngpzg

# 后记

weblogic Coherence 反序列化漏洞很多都是相关联的，对于某个漏洞，很可能就是用到了之前一些漏洞的链子。其实不仅仅 weblogic ，java 其他反序列化链也是如此，很多情况都是一个链会用到其他链的一部分。所以在学习中，把一个组件或者一个库的漏洞总结起来一起分析还是比较重要的，最后希望这篇文章能帮助到其他一起学反序列化的朋友们。

# 参考

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
**[Goby 官网: https://gobysec.net/](https://gobysec.net/)** 

如果您有任何反馈建议，您可通过提交 issue 或是以下方式联系我们：

1. GitHub issue: [https://github.com/gobysec/Goby/issues](https://github.com/gobysec/Goby/issues)
2. 微信群：关注公众号“GobySec“，回复暗号”加群“ （社群优势：可第一时间了解Goby功能发布、活动等咨询）
3. Telegram Group: [http://t.me/gobies](http://t.me/gobies) 
4. 推特：[https://twitter.com/GobySec](https://twitter.com/GobySec)
