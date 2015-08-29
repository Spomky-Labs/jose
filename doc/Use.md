How to use
==========

# Before to use

## JWS or JWE

This library is able to create and load signed JWT (JWS) and encrypted JWT (JWE).

JWS are digitally signed using one (or more) private key(s). The receiver of
this JOT will be able to verify this signature is valid using your public key.
If the signature is valid, the receiver can consider that the data received have
not been modified and that your are the sender.

JWE are encrypted using public keys of one (or more) recipient(s).
A recipient will be able decrypt the data using its private key.

You can create signed and encrypted data. You have to create a JWS and then create a JWE.

## JWK

The keys used to sign and encrypt are JWK objects.

A public key is used to verify a digital signature and to encrypt data using.
A private key can sign and decrypt data.

There are five types of keys:

* `RSA` keys,
* `EC` (Elliptic Curves) keys,
* `oct` keys,
* `dir` (direct) keys.
* `none` keys (only for `none` signature algorithm).

A key can be used with different algorithms. But an algorithm only supports one type.
For example, `ES256`, `ES384` and `ES512` algorithms only accept `EC` keys.
Read [the algorithms page](Keys.md) to know which type of key you need for your algorithm.

## JWKSet

You can group your keys in a JWKSet object. This object accepts any kind of JWK objects.
It is recommended to group your public and private keys in different JWKSet.

All JWK and JWKSet are managed using a JWKManager object.

**Note: in a near future, the JWKManager will be split into two managers: JWKManager and JWKSetManager**

## Data

A JWS or JWE object includes a signed data or an encrypted data. This library supports any type of data that are serializable (all types supported by `json_encode`).

So you can sign or encrypt

* a number: 3.14159265359
* a string: "Live long and prosper"
* an array:  `["iss"=>"my.example.com","sub"=>"me@example.com","is_admin"=>true]`
* a key (JWK object)
* a set of private keys (JWKSet object)
* a JWT object.
* other objects supported by `json_encode` and `json_decode` methods or that implement `JsonSerializable`

If you use specific object and want to add custom header parameters to your JWS/JWE, you can add your own payload converter.
Read [the converter page](Converter.md) to know how to create your own converter.

# Creation of my first JOSE

In this example, we suppose that you already have (extended the required components)[Extend the library](Extend.md).

You are Alice and you want to send a very important message to Bob: ```"Meet me in the front of train station at 8:00AM"```.

The public key of Bob is a RSA Certificate. Using JWK representation, it will be:

```php
array(
    "kty" => "RSA",
    "n"   =>"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
    "e"   =>"AQAB",
);
```

**Note: to create such array from a X509 certificate, you can use the following method:**

```php
<?php
use SpomkyLabs\Jose\Util\RSAConverter;

// This method also accepts a string of the certificate in PEM format.
// "passphrase" is the passphrase used to secure the private key. This argument is optional.
$certificate = RSAConverter::loadKeyFromFile("/path/to/your/certificate", "passphrase");
```

Alice will encrypt the message (=create a JWE object) using the key encryption algorithm `RSA-OAEP-256` and the content encryption algorithm ```A256CBC-HS512```.

As there is only one receiver, we can use the compact serialization.

```php
<?php
//We create and configure instances of JWKManager and JWTManager
$aliceJWK = ...; //The key of Alice (JWK object). See above.
$bobJWK   = ...; //The key of Bob (JWK object). See below.
$message  = "Meet me in the front of train station at 8:00AM";

//We create an encryption instruction
$instruction = new EncryptionInstruction();
$instruction->setRecipientPublicKey($bobJWK)
$instruction->setSenderPrivateKey($aliceJWK); //This is not mandatory except when using specific algorithms (e.g. ECDH-ES)

//The first argument is the data you want to encrypt
//The second argument is an array of instructions. We have only one.
//The third argument is the shared protected headers. We set the algorithms and we want to compress the data before encryption using the DEFLATE method.
//The fourth argument is the unprotected shared headers. We set nothing because the compact serialization method does not support it
//The fifth argument define the expected serialization method.
$jwe = $encrypter->encrypt(
    $message,
    array($instruction),
    array("enc" => "A256CBC-HS512", "alg" => "RSA-OAEP-256", "zip" => "DEF"),
    array(),
    JSONSerializationModes::JSON_COMPACT_SERIALIZATION
);
```

The variable `$jwe` now contains your encrypted message. You can send it to Bob.
The encrypted message will look like:

```php
eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMi...8drPvQGxL6L_r
```

## Load a JOSE ##

Bob received the message from Alice and wants to decrypt the message. Bob has the
private key used to encrypt this message in its JWKSet (managed by its JWKManager object).

The private key of Bob is:

```php
array(
    "kty" => "RSA",
    "n"   =>"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
    "e"   =>"AQAB",
    "d"   =>"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
);
```

To decrypt the message, Bob will load the data he received:

```php
<?php

//In this case, the result is a JWE object.
//The payload is still encrypted, but all other information such as protected header or unprotected header are available
$jwe = $loader->load("eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMi...8drPvQGxL6L_r");

//The result is a boolean. If true, the payload of the JWE is populated with the decrypted value
$result = $loader->decrypt($jwe);
echo $result->getPayload(); // "Meet me in the front of train station at 8:00AM"
```

If you want to use a specific key set, you can pass it as second argument.

```php
<?php

$my_keyset = ...; //A JWKSet object that contains keys.

$jwe = $loader->load("eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMi...8drPvQGxL6L_r", $my_keyset);

$result = $loader->decrypt($jwe);
```
