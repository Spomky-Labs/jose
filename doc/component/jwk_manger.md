The JWK Manager
===============

The JWK manager is used to find or create [JWK](../object/jwk.md) objects (keys).

By default, it can find the following keys:
* When the algorithm is `none`,
* When the key is in the header (`jwk` parameter),
* When the key is a certificate chain in the header (`x5c` parameter),

If you do not have any particular need, you can use the provided class directly:

```php
<?php

use SpomkyLabs\Jose\JWKManager;

$jwk_manager = new JWKManager();
```

The JWK manager can also be used to store keys.
You can override some methods to allow your key to be automatically found during operations:

```php
<?php

use SpomkyLabs\Jose\JWKManager;

class MyKeyManager extends JWKManager
{
    /**
     * @var \Jose\JWKInterface
     */
    private $keys = [];
    
    protected function getSupportedMethods()
    {
        return array_merge(
            [
                'findByKeyID',
            ],
            parent::getSupportedMethods()
        );
    }
    
    protected function findByKeyID()
    {
        if (!isset($header['kid'])) {
            return;
        }
        foreach($this->keys as $key) {
            if ($header['kid'] === $key->getKeyID()) {
                return $key;
            }
        }
    }
    
    //Do not forget to add/remove keys methods
}
```
