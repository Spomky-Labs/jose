The JWT Manager
===============

The JWT manager does nothing really complicated: it creates [JWT](../object/jwt.md), [JWS](../object/jws.md) or [JWE](../object/jwe.md) objects.

```php
<?php

use SpomkyLabs\Jose\JWTManager;

$jwt_manager = new JWTManager();
```

You should not use this manager directly and other components interact with it.
However, in some cases, it could be useful to generate a JWT object and use it as input:

```php
<?php

$jwt = $jwt_manager->createJWT();

$jwt->setPayload([
    'exp' => time()+3600,
    'iat' => time(),
    'nbf' => time(),
    'sub' => 'you',
    'iss' => 'My authorization server',
    'aud' => 'My resource server',
    ...
]);
```

By default, it creates these objects using the classes provided by this library.
If you need to, you can override some methods and create your own objects.

```php
<?php

use SpomkyLabs\Jose\JWTManager;

class MyCustomJWTManager extends JWTManager
{
    /**
     * {@inheritdoc}
     */
    public function createJWT()
    {
        return new MyCustomJWTClass();
    }
}
```

Then, use `MyCustomJWTManager` directly or inject it on the different components.
