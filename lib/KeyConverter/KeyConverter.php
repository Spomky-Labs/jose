<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\KeyConverter;

use Base64Url\Base64Url;
use phpseclib\Crypt\RSA;

/**
 * This class will help you to load an EC key or a RSA key (private or public) and get values to create a JWK object.
 */
class KeyConverter
{
    /**
     * @param string      $file
     * @param null|string $password
     *
     * @throws \Exception
     *
     * @return array
     */
    public static function loadKeyFromFile($file, $password = null)
    {
        $content = file_get_contents($file);

        return self::loadKeyFromPEM($content, $password);
    }

    /**
     * @param string      $pem
     * @param null|string $passphrase
     *
     * @throws \Exception
     *
     * @return array
     */
    public static function loadKeyFromPEM($pem, $passphrase = null)
    {
        $res = openssl_pkey_get_private($pem, $passphrase);
        if ($res === false) {
            $res = openssl_pkey_get_public($pem);
        }
        if ($res === false) {
            throw new \Exception('Unable to load the key');
        }

        return self::loadKeyFromResource($res);
    }

    /**
     * @param resource $res
     *
     * @throws \Exception
     *
     * @return array
     */
    public static function loadKeyFromResource($res)
    {
        $details = openssl_pkey_get_details($res);
        if (!is_array($details)) {
            throw new \Exception('Unable to get details of the key');
        }

        if (array_key_exists('ec', $details)) {
            $pem = $details['key'];
            try {
                openssl_pkey_export($res, $pem);
            } catch (\Exception $e) {
                // Public keys cannot be exported with openssl_pkey_export
            }
            $ec_key = new ECKey($pem);

            return $ec_key->toArray();
        } elseif (array_key_exists('rsa', $details)) {
            return self::loadRSAKey($details['rsa']);
        }
        throw new \Exception('Unsupported key type');
    }

    /**
     * @param array $values
     *
     * @return array
     */
    private static function loadRSAKey(array $values)
    {
        $result = ['kty' => 'RSA'];
        foreach ($values as $key => $value) {
            $value = Base64Url::encode($value);
            if ($key === 'dmp1') {
                $result['dp'] = $value;
            } elseif ($key === 'dmq1') {
                $result['dq'] = $value;
            } elseif ($key === 'iqmp') {
                $result['qi'] = $value;
            } else {
                $result[$key] = $value;
            }
        }

        return $result;
    }

    /**
     *
     */
    private static function checkRequirements()
    {
        if (!class_exists('\phpseclib\Crypt\RSA')) {
            throw new \RuntimeException("The library 'phpseclib/phpseclib' is required to use RSA based algorithms");
        }
    }

    /**
     * @param array $data
     *²
     *
     * @throws \Exception
     *
     * @return \phpseclib\Crypt\RSA
     */
    public static function fromArrayToRSACrypt(array $data)
    {
        self::checkRequirements();
        $xml = self::fromArrayToXML($data);
        $rsa = new RSA();
        $rsa->loadKey($xml);

        return $rsa;
    }

    /**
     * @param array $data
     *
     * @throws \Exception
     *
     * @return string
     */
    public static function fromArrayToXML(array $data)
    {
        $result = "<RSAKeyPair>\n";
        foreach ($data as $key => $value) {
            $element = self::getElement($key);
            $value = strtr($value, '-_', '+/');

            switch (strlen($value) % 4) {
                case 0:
                    break; // No pad chars in this case
                case 2:
                    $value .= '==';
                    break; // Two pad chars
                case 3:
                    $value .= '=';
                    break; // One pad char
                default:
                    throw new \Exception('Invalid data');
            }

            $result .= "\t<$element>$value</$element>\n";
        }
        $result .= '</RSAKeyPair>';

        return $result;
    }

    /**
     * @param $key
     *
     * @return mixed
     */
    private static function getElement($key)
    {
        $values = [
            'n'  => 'Modulus',
            'e'  => 'Exponent',
            'p'  => 'P',
            'd'  => 'D',
            'q'  => 'Q',
            'dp' => 'DP',
            'dq' => 'DQ',
            'qi' => 'InverseQ',
        ];
        if (array_key_exists($key, $values)) {
            return $values[$key];
        } else {
            throw new \InvalidArgumentException('Unsupported key data');
        }
    }
}
