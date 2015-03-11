<?php

namespace SpomkyLabs\Jose;

use Jose\JWKInterface;

/**
 * Trait used to check key purpose.
 */
trait KeyChecker
{
    protected function checkKeyUsage(JWKInterface $key, $usage)
    {
        $use = $key->getPublicKeyUse();
        $ops = $key->getKeyOperations();
        if (null === $use && null === $ops) {
            return;
        }
        if (null !== $use) {
            switch ($use) {
                case 'sig':
                    if ("verification" !== $usage) {
                        throw new \Exception("The key can not be used for signature verifications.");
                    }
                    break;
                case 'enc':
                    if ("encryption" !== $usage) {
                        throw new \Exception("The key can not be used for encryption.");
                    }
                    break;
                default:
                    # code...
                    break;
            }
        }
        if (is_array($ops)) {
            switch ($use) {
                case 'sign':
                    if ("signature" !== $usage) {
                        throw new \Exception("The key can not be used for signature verifications.");
                    }
                    break;
                case 'enc':
                    if ("encryption" !== $usage) {
                        throw new \Exception("The key can not be used for encryption.");
                    }
                    break;
                default:
                    # code...
                    break;
            }
        }
    }
}
