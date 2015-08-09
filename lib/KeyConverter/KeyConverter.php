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
use FG\ASN1\ExplicitlyTaggedObject;
use FG\ASN1\Object;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use phpseclib\Crypt\RSA;
use phpseclib\File\ASN1;

/**
 * This class will help you to load an EC key or a RSA key (private or public) and get values to create a JWK object
 */
class KeyConverter
{
    /**
     * @param string $file
     * @param null|string $password
     *
     * @throws \Exception
     *
     * @return array|bool|void
     */
    public static function loadKeyFromFile($file, $password = null)
    {
        $content = file_get_contents($file);
        return self::loadKeyFromPEM($content, $password);
    }

    /**
     * @param string $certificate
     * @param null|string $passphrase
     *
     * @throws \Exception
     *
     * @return mixed
     */
    public static function loadKeyFromPEM($certificate, $passphrase = null)
    {
        $res = openssl_pkey_get_private($certificate, $passphrase);
        if ($res === false) {
            $res = openssl_pkey_get_public($certificate);
        }
        if ($res === false) {
            throw new \Exception('Unable to load the key');
        }
        return self::loadKeyFromResource($res);
    }

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
            return self::loadECKey($pem);
        } else if (array_key_exists('rsa', $details)) {
            return self::loadRSAKey($details['rsa']);
        }
        throw new \Exception('Unsupported key type');
    }

    /**
     * @param $pem
     *
     * @return array
     * @throws \Exception
     * @throws \FG\ASN1\Exception\ParserException
     */
    private static function loadECKey($pem)
    {
        $data = base64_decode(preg_replace('#-.*-|\r|\n#', '', $pem));
        $asnObject = Object::fromBinary($data);

        if (!$asnObject instanceof Sequence) {
            throw new \Exception('Unable to load the key');
        }
        $children = $asnObject->getChildren();
        if (4 === count($children)) {
            return self::loadPrivateECKey($children);
        } elseif (2 === count($children)) {
            return self::loadPublicECKey($children);
        }
        throw new \Exception('Unable to load the key');
    }

    /**
     * @param array $children
     *
     * @return array
     * @throws \Exception
     */
    private static function loadPublicECKey(array $children)
    {
        if (!$children[0] instanceof Sequence) {
            throw new \Exception('Unable to load the key');
        }
        $sub = $children[0]->getChildren();
        if (!$sub[0] instanceof ObjectIdentifier || '1.2.840.10045.2.1' !== $sub[0]->getContent()) {
            throw new \Exception('Unsupported key type');
        }
        if (!$sub[1] instanceof ObjectIdentifier || !self::isECAlgorithmSupported($sub[1]->getContent())) {
            throw new \Exception('Unsupported key type');
        }

        if (!$children[1] instanceof BitString) {
            throw new \Exception('Unable to load the key');
        }

        $bits = $children[1]->getContent();

        return [
            'kty' => 'EC',
            'x' => $x = Base64Url::encode(hex2bin(substr($bits, 2, (strlen($bits) - 2) / 2))),
            'y' => $y = Base64Url::encode(hex2bin(substr($bits, (strlen($bits) - 2) / 2 + 2, (strlen($bits) - 2) / 2))),
        ];
    }

    /**
     * @param array $children
     *
     * @return array
     * @throws \Exception
     */
    private static function loadPrivateECKey(array $children)
    {
        if (!$children[0] instanceof Integer || '1' !== $children[0]->getContent()) {
            throw new \Exception('Unable to load the key');
        }
        if (!$children[1] instanceof OctetString) {
            throw new \Exception('Unable to load the key');
        }

        if (!$children[2] instanceof ExplicitlyTaggedObject) {
            throw new \Exception('Unable to load the key');
        }
        if (!$children[2]->getContent() instanceof ObjectIdentifier) {
            throw new \Exception('Unable to load the key');
        }
        if (!self::isECAlgorithmSupported($children[2]->getContent()->getContent())) {
            throw new \Exception('Unsupported key type');
        }

        if (!$children[3] instanceof ExplicitlyTaggedObject) {
            throw new \Exception('Unable to load the key');
        }
        if (!$children[3]->getContent() instanceof BitString) {
            throw new \Exception('Unable to load the key');
        }

        $bits = $children[3]->getContent()->getContent();

        return [
            'kty' => 'EC',
            'x' => $x = Base64Url::encode(hex2bin(substr($bits, 2, (strlen($bits) - 2) / 2))),
            'y' => $y = Base64Url::encode(hex2bin(substr($bits, (strlen($bits) - 2) / 2 + 2, (strlen($bits) - 2) / 2))),
            'd' => $d = Base64Url::encode(hex2bin($children[1]->getContent())),
        ];
    }

    /**
     * @param string $algorithm
     *
     * @return bool
     */
    private static function isECAlgorithmSupported($algorithm)
    {
        return in_array($algorithm, ['1.2.840.10045.3.1.7', '1.3.132.0.34', '1.3.132.0.35']);
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
        }
    }
}
