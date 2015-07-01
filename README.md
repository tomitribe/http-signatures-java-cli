# Tomitribe HTTP Signatures CLI Verifier

Allows you to test HTTP signatures of a HTTP message to a server. After building the project you can use the following command:

```java -jar signature-verifier-standalone.jar [secret] [alias] [address] [path] [method] {input}```

* [secret] - the secret added in the server keystore configured in the conf/server.xml under 
```com.tomitribe.tribestream.security.signatures.SignatureJAASRealm`` Realm.
* [alias] - the alias associated with the secret.
* [address] - the server hostname to connect.
* [path] - the path of the address to invoke on the server that should be signed.
* [method] - method used to invoke the address (GET, POST).
* {input} - optional payload needed to invoke the method. If there is no payload, the applicatiom will use an empty string.

## Example of invocation 

```java -jar signature-verifier-standalone.jar changeit user http://localhost /service/123 GET```

* Note: You can find the signature-verifier-standalone.jar in the project ```target``` directory.