Check claims
============

A loaded [JWS object](../object/jws.md) may contain claims. Before to use these claims, you may need to verify some of them.

Some claims defined in the [RFC7519](https://tools.ietf.org/html/rfc7519) must be verified before doing anything.
Same goes for the `crit` header: if one claim in this header is not understood, then reject the whole JWS.

To help you to check claims, this library provides a (very) simple claims/headers Checker Manager.
If you use custom claims or headers, you are also able to create and use your own Checkers with this Checker Manager.

# The Checkers

Claim and Header Checkers are simple classes that implement the interface `Jose\Checker\ClaimCheckerInterface` or `Jose\Checker\HeaderCheckerInterface` respectively.
This library provides some claims and header checkers:

* Claim Checker:
    * `Jose\Checker\AudienceChecker`: checks the audience (recommended).
    * `Jose\Checker\ExpirationTimeChecker`: checks the `exp` claims (highly recommended).
    * `Jose\Checker\IssuedAtChecker`: checks the `iat` claims (recommended).
    * `Jose\Checker\NotBeforeChecker`: checks the `nbf` claims (recommended).
    * `Jose\Checker\IssuerChecker`: checks the `iss` claims. This class is an abstract class and must be extended to be used.
    * `Jose\Checker\SubjectChecker`: checks the `sub` claims. This class is an abstract class and must be extended to be used.
    * `Jose\Checker\JtiChecker`: checks the `jti` claims. This class is an abstract class and must be extended to be used.
* Header Checker:
    * `Jose\Checker\CriticalHeaderChecker`: checks the header `crit` (highly recommended).

## Custom Checkers

You can create your own claim or header checkers by implementing the associated interface.
In the following lazy example, we check is the claim `animal` is set. If it is set, in must contain `dog`, `cat` or `owl`.

```php
<?php

namespace Acme\Checker;

use Assert\Assertion;
use Jose\Checker\ClaimCheckerInterface;
use Jose\Object\JWTInterface;

class AnimalChecker implements ClaimCheckerInterface
{
    /**
     * This method must return an array of the checker claims.
     * It must return an empty array if nothing has been checker
     * Else an exception must be thrown.
     */
    public function checkClaim(JWTInterface $jwt)
    {
        // If the claim 'animal' is not available, returns an empty array
        if (!$jwt->hasClaim('animal')) {
            return [];
        }

        // We verify the claim contains the required value.
        $animal = $jwt->getClaim('animal');
        Assertion::inArray($animal, ['bog', 'cat', 'owl'], 'Bad animal.');

        // We return an array with the checked claims (here only 'animal').
        return ['animal'];
    }
}
```

# The Checker Manager

The Checker Manager will handle all checkers and verify a JWS.
After the manager is created, you have to add the checkers. Then, you will be able to check the JWS.

```php
use Jose\Checker\CheckerManager;
use Jose\Checker\AudienceChecker;
use Jose\Checker\CriticalHeaderChecker;
use Jose\Checker\ExpirationTimeChecker;
use Jose\Checker\IssuedAtChecker;
use Jose\Checker\NotBeforeChecker;

// We create an instance of CheckerManager.
$checker_manager = new CheckerManager();

// We add the claims checkers (exp, iat and nbf).
$checker_manager->addClaimChecker(new ExpirationTimeChecker());
$checker_manager->addClaimChecker(new IssuedAtChecker());
$checker_manager->addClaimChecker(new NotBeforeChecker());
$checker_manager->addClaimChecker(new AudienceChecker('My Server'));

// We add the header checker (crit).
$checker_manager->addHeaderChecker(new CriticalHeaderChecker());

// We verify the signature at index $signature_index of the JWS $jws.
// If the verification failed, an exception will be thrown.
$checker_manager->checkJWS($jws, $signature_index);
```

We highly recommend you to use the index returned by the [Verifier](../Verify.md#signature-index-and-security) to be sure to
check claims of the verified signature.

# The Checker Manager Factory

To ease the creation of the Checker Manager, we created a Checker Manager Factory `Jose\Factory\CheckerManagerFactory`:

```php
use Jose\Factory\CheckerManagerFactory;

$claim_checker_list = [
    'exp',
    'iat',
    'nbf'
];
$header_checker_list = [
    'crit'
];

$checker_manager = CheckerManagerFactory::createClaimCheckerManager($claim_checker_list, $header_checker_list);
```

The Checker Manager created with the factory is able to check `exp`, `iat`, `nbf` claims and the `crit` header.
As these list are the one by default, you can just call ` CheckerManagerFactory::createClaimCheckerManager();`.

This factory is also able to receive Checkers in the list of arguments:

```php
use Acme\Checker\AnimalChecker;
use Jose\Checker\AudienceChecker;
use Jose\Factory\CheckerManagerFactory;

$claim_checker_list = [
    'exp',
    'iat',
    'nbf',
    new AudienceChecker('My Server'),
    new AnimalChecker(),
];

$checker_manager = CheckerManagerFactory::createClaimCheckerManager($claim_checker_list);
```
