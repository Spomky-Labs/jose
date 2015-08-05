<?php

namespace SpomkyLabs\Jose;

use Jose\JWKInterface;

/**
 * Trait used to check key purpose.
 */
trait KeyChecker
{
    /**
     * @param string $usage
     */
    protected function checkKeyUsage(JWKInterface $key, $usage)
    {
        $use = $key->getPublicKeyUse();
        $ops = $key->getKeyOperations();
        if (is_null($use) && is_null($ops)) {
            return true;
        }

        if (!is_null($use)) {
            switch ($usage) {
                case 'verification':
                case 'signature':
                    if ('sig' === $use) {
                        return true;
                    }

                    return false;
                case 'encryption':
                case 'decryption':
                    if ('enc' === $use) {
                        return true;
                    }

                    return false;
                default:
                    throw new \Exception('Unsupported key usage.');
                    break;
            }
        } elseif (is_array($ops)) {
            switch ($usage) {
                case 'verification':
                    if (in_array('verify', $ops)) {
                        return true;
                    }

                    return false;
                case 'signature':
                    if (in_array('sign', $ops)) {
                        return true;
                    }

                    return false;
                case 'encryption':
                    if (in_array('encrypt', $ops) || in_array('wrapKey', $ops)) {
                        return true;
                    }

                    return false;
                case 'decryption':
                    if (in_array('decrypt', $ops) || in_array('unwrapKey', $ops)) {
                        return true;
                    }

                    return false;
                default:
                    throw new \Exception('Unsupported key usage.');
                    break;
            }
        }

        return true;
    }
}
