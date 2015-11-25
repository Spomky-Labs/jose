The Checker Manager
===================

When you load data, you will have to check the header parameters and the claims in the payload.
The checker manager contains multiple rules to verify these parameters and claims.

You can define all checkers you want.

# Available checkers

This library provides the following checkers:

* 'Audience' Checker: verifies the audience (`aud` parameter)
* 'Critical' Checker: verifies the critical parameters (`crit` parameter)
* 'Expiration' Checker: verifies the JWT is not expired (`exp` parameter)
* 'Issued At' Checker: verifies when the JWT has been issued (`iat` parameter)
* 'Issuer' Checker: verifies the issuer (`iss` parameter)
* 'Not Before' Checker: verifies if the JWT can be used (`nbf` parameter)
* 'Subject' Checker: verifies the subject (`sub` parameter)

# The manager

You just have to create an instance of `Jose\Checker\CheckerManager` and add each checker you want to use.

```php
<?php

use Jose\Checker\CheckerManager;
use Jose\CheckerManager\AudienceChecker;
use Jose\CheckerManager\ExpirationChecker;

$checker_manager = new CheckerManager();

$checker_manager->addChecker(new AudienceChecker('My server'))
    ->addChecker(new ExpirationChecker());
```

This manager is called when you call the method `verify` of the `loader`.
You can also call the method `checkJWT` manually at any time.

```php
<?php

$checker_manager->checkJWT($jwt);
```

# Create my own checker

If you need to verify a custom claim, you can create your own checker and add it to the manager.
Your checker must implements `Jose\Checker\CheckerInterface`.

Hereafter an example. Our animal checker will verify if the protected header contains the key `animal`.
If this key exists, it verifies the animal is in the provided list.

```php
<?php

use Jose\Checker\CheckerInterface;

class AnimalChecker implements CheckerInterface
{
    public function checkJWT(JWTInterface $jwt)
    {
        $animal = $jwt->getProtectedHeader('animal');
        if (is_null($animal)) {
            return;
        }
        if (!in_array($animal, ['owl', 'cat', 'dog', 'rat', 'mouse']) {
            throw new \Exception('Unauthorized animal.');
        }
    }
}
```
