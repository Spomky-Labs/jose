The JWKSet Manager
==================

The JWK manager is used to find or create [JWKSet](../object/jwkset.md) objects (keys).

By default, it can find the following keys:
* When the keys url is in the header (`jku` parameter),
* When the certificate chain url is in the header (`x5u` parameter),

If you do not have any particular need, you can use the provided class directly:

```php
<?php

use Jose\JWKSetManager;

$jwkset_manager = new JWKSetManager();
```

The JWKSet manager can also be used to store key sets.
You can override some methods to allow your key sets to be automatically found during operations:

```php
<?php

use Jose\JWKSetManager;

class MyKeyManager extends JWKSetManager
{
    /**
     * @var \Jose\JWKSetInterface
     */
    private $keys = [];
    
    protected function getSupportedMethods()
    {
        return array_merge(
            [
                'findByKeyAlgorithm',
            ],
            parent::getSupportedMethods()
        );
    }
    
    protected function findByKeyAlgorithm()
    {
        if (!isset($header['alg'])) {
            return;
        }
        $keyset = $this->createJWKSet();
        foreach($this->keys as $key) {
            if ($header['alg'] === $key->getKeyAlgorithm()) {
                $keyset->addKey($key);
            }
        }
        return $keyset;
    }
    
    //Do not forget to add/remove key sets methods
}
```
