Output modes
============

This library is able to support all output modes defined in the specifications:
* Complete Serialization,
* Flattened Serialization,
* Compact Serialization.

You can choose the output mode when you sign or encrypt an input.

Hereafter some examples:

```
Complete Serialization of a signature:
{
  "payload":"<payload contents>",
  "signatures":[
  {"protected":"<integrity-protected header 1 contents>",
  "header":<non-integrity-protected header 1 contents>,
  "signature":"<signature 1 contents>"},
  ...
  {"protected":"<integrity-protected header N contents>",
  "header":<non-integrity-protected header N contents>,
  "signature":"<signature N contents>"}]
}


Flattened Serialization of a signature:
{
    "payload":"<payload contents>",
    "protected":"<integrity-protected header contents>",
    "header":<non-integrity-protected header contents>,
    "signature":"<signature contents>"
}


Compact Serialization of a signature:
eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

To avoid hardcoding into your projects, we created class constants you can use with all our methods:

```php
use Jose\JSONSerializationModes;

JSONSerializationModes::JSON_SERIALIZATION; // Complete Serialization
JSONSerializationModes::JSON_FLATTENED_SERIALIZATION; // Flattened Serialization
JSONSerializationModes::JSON_COMPACT_SERIALIZATION; // Compact Serialization
```

This library also provides a converter to help you to convert any output (signature or encryption) from a mode to another.

```php
use Jose\Util\Converter;

$compact = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
$flattened = Converter::convert($compact, JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);

// $flattened now contains the flattened representation of the signature
```

`Converter` is also able to merge representations. You can only merge representations under certain conditions:
* Signatures:
    * The input MUST be the same
* Encryptions:
    * The cyphertext MUST be identical
    * The protected and unprotected headers MUST be identical
    * The `iv`, `aad` and `tag` must be identical

You cannot merge a signature with an encryption.

```php
$merged = Converter::merge(
    $signature1,
    $signature2,
    $signature3,
    $signature4
);

// If succeded, $merged will contain all signatures
```
