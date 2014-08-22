# How to use #

## Before to use ##

### JWS or JWE

This library is able to handle signed JOSE (JWS) and enrypted JOSE (JWE).

The first one will add a digital signature using your private key. The receiver of this JOSE will be able to verify this signature is valid using your public key. If the signature is valid, the receiver can consider that the data received have not been modified and that your are the sender.

The second one will encrypt your data using the public key of the receiver. Only the receiver will be able decrypt this data.

### JWK and JWKSet

The keys used to sign and encrypt are JWK objects.

A public key is able to verify a digital signature and to encrypt data using an algorithm. A private key can sign and decrypt data using the same algorithm.

You can group your keys in a JWKSet object. This object accepts any kind of JWK objects. It is recommended to group your public and private keys in different JWKSet.

All JWK and JWKSet are managed using a JWKManager object (read [Extend the library](Extend.md)).

### Data

A JWS or JWE object include a signed data or an encrypted data. This library support four types of data.

If you use JWS, you can sign

* a string: "Long live and prosper"
* an array: {"iss":"my.example.com","sub":"me@example.com","is_admin":true}

If you use JWE, you can sign

* a string
* an array
* a private key (JWK object)
* a set of private keys (JWKSet object)

## Creation of my first JOSE ##

First of all, you must have a JWTManager object and a JWKManager object to manage your keys and to create or load your JOSE.

You are Alice and you want to send a very important message to Bob: ```"Meet me in the front of train station at 8:00AM"```.

The public key of Bob is a RSA Certificate. Using JWK representation, it will be:

	array(
	    "kty" => "RSA",
	    "n"   =>"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
	    "e"   =>"AQAB",
	)

*Todo: explain how to convert a RSA Certificate into a JWK representation*

In the example, we will encrypt the message (=create a JWE object) using the key encryption algorithm ```RSA-OAEP-256``` and the content encryption algorithm ```A256CBC-HS512```.

As there is only one receiver, we can use the compact serialization.

	<?php

	use SpomkyLabs\JOSE\Encryption\RSA;

	$jwk_manager = new JWKManager();
	$jwt_manager = new JWTManager();
	
	$jwt_manager->setKeyManager($jwk_manager);
	
	$jwk = new RSA();
	$jwk->setValues(array(
	    "n"   =>"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
	    "e"   =>"AQAB"
	));

    $jwe = $jwt_manager->convertToCompactSerializedJson(
        "Meet me in the front of train station at 8:00AM",
        $jwk,
        array(
            "alg"=>"RSA-OAEP-256",
            "enc"=>"A256CBC-HS512",
            'iss'=>'Alice',
    ));

The variable ```$jwe``` now contains your ecnrypted message. You can send it to Bob. The encrypted message will look like:

	eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMi...8drPvQGxL6L_r


## Load a JOSE ##

Bob received the message from Alice and want to decrypt the message. Bob has the private key used to encrypt this message in its JWKSet (managed by its JWKManager object).

The private key of Bob is:

	array(
	    "kty" => "RSA",
	    "n"   =>"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
	    "e"   =>"AQAB",
	    "d"   =>"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
	)

To decrypt the message, Bob will load the data he received:

	<?php

	use SpomkyLabs\JOSE\Encryption\RSA;

	$jwk_manager = new JWKManager();
	$jwt_manager = new JWTManager();
	
	$jwt_manager->setKeyManager($jwk_manager);
	
	$jwk = new RSA();
	$jwk->setValues(array(
	    "n"   =>"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
	    "e"   =>"AQAB",
	    "d"   =>"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"
	));

    $message = $jwt_manager->load("eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMi...8drPvQGxL6L_r");


The variable ```$message``` now contains the message of Alice: ```"Meet me in the front of train station at 8:00AM"```.

