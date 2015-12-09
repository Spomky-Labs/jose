<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Jose\Object\JWKInterface;

trait HasKeyChecker
{
    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $usage
     *
     * @throws \InvalidArgumentException
     *
     * @return bool
     */
    private function checkKeyUsage(JWKInterface $key, $usage)
    {
        if (!$key->has('use') && !$key->has('key_ops')) {
            return true;
        }
        if ($key->has('use')) {
            $use = $key->get('use');
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
                    throw new \InvalidArgumentException('Unsupported key usage.');
            }
        } elseif ($key->has('key_ops') && is_array($ops = $key->get('key_ops'))) {
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
                    throw new \InvalidArgumentException('Unsupported key usage.');
            }
        }

        return true;
    }

    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $algorithm
     *
     * @return bool
     */
    private function checkKeyAlgorithm(JWKInterface $key, $algorithm)
    {
        if (!$key->has('alg')) {
            return true;
        }

        return $key->get('alg') === $algorithm;
    }
}
