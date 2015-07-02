# Tomitribe HTTP Signatures CLI Verifier

Allows you to test HTTP signatures of a HTTP message to a server. After building the project you can use the following command:

```java -jar signature-verifier-standalone.jar help verify```

    Usage: verify [options]
    
    Options: 
      --alias=<String>                   the alias used to sign the request
      --secret=<String>                  the secret used to sign the request
      --signature-algorithm=<String>     the signature algorithm
                                         (default: hmac-sha256)
      --digest-algorithm=<String>        the digest algorithm if digest is used
                                         (default: sha-256)
      --headers=<String>                 the signature headers
                                         (default: (request-target) date digest)
      --http-method=<String>             the request HTTP method
                                         (default: GET)
      --endpoint=<String>                the endpoint URL
      --request-headers=<String[]>       additional request header, value is key pair separated by equal (--request-headers=myheader=myvalue). Can be used multiple times.
      --accept=<String>                  request Accept
      --type=<String>                    request Content-Type
      --payload=<String>                 request payload if needed


## Example of invocation 

```java -jar target/signature-verifier-standalone.jar verify --alias=xxx --secret=yyyyy --endpoint=http://zzzz:8080/app/api/users --http-method=POST --type=application/json --accept=application/json --payload='{'name': 'Test'}'```

* Note: You can find the signature-verifier-standalone.jar in the project ```target``` directory.