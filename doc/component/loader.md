The Loader
==========

The Loader will try to load data and return you a `JWS`, `JWE` or a list of these objects. 

We recommend you to use our factory to create such object:

```php
use Jose\Factory\LoaderFactory;
use Jose\Payload\JWKConverter;
use Jose\Payload\JWKSetConverter;

$payload_converters = [
    new JWKConverter(),
    new JWKSetConverter(),
];

$loader = LoaderFactory::createLoader($payload_converters);

$jwt = $loader->load('eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw');
```

Please note that at this moment variable `$jwt` is a `JWS` object **but the signature and claims have not been verified**.
You must use the verifier to perform these verifications.
