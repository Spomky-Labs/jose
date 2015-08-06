<?php

namespace SpomkyLabs\Jose\Util;

use Base64Url\Base64Url;
use phpseclib\Crypt\RSA;

/**
 * Class RSAConverter.
 *
 * This utility class will help to get details of a RSA key or certificate to generate a JWK
 */
class RSAConverter
{
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
     * @return \phpseclib\Crypt\RSA
     *
     * @throws \Exception
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
     * @param string $certificate
     * @param null|string $passphrase
     *
     *
     * @return array
     * @throws \Exception
     */
    private static function getCertificateValues($certificate, $passphrase = null)
    {
        $res = openssl_pkey_get_private($certificate, $passphrase);
        if ($res === false) {
            $res = openssl_pkey_get_public($certificate);
        }
        if ($res === false) {
            throw new \Exception('Unable to load the certificate');
        }
        return self::getOpenSSLResourceValues($res);
    }

    /**
     * @param $resource
     *
     * @return array
     * @throws \Exception
     */
    private static function getOpenSSLResourceValues($resource)
    {
        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new \Exception('Unable to get details of the key');
        }
        if (!is_array($details) || !isset($details['rsa'])) {
            throw new \Exception('Key is not a valid RSA key');
        }

        return $details['rsa'];
    }

    /**
     * @param string $file
     * @param null|string $passphrase
     *
     *
     * @return mixed
     * @throws \Exception
     */
    public static function loadKeyFromFile($file, $passphrase = null)
    {
        $content = file_get_contents($file);
        return self::loadKeyFromPEM($content, $passphrase);
    }

    /**
     * @param string $certificate
     * @param null|string $passphrase
     *
     *
     * @return mixed
     * @throws \Exception
     */
    public static function loadKeyFromPEM($certificate, $passphrase = null)
    {
        $values = self::getCertificateValues($certificate, $passphrase);
        return self::convertToKeyArray($values);
    }

    /**
     * @param $resource
     *
     * @return array
     * @throws \Exception
     */
    public static function loadKeyFromOpenSSLResource($resource)
    {
        $values = self::getOpenSSLResourceValues($resource);
        return self::convertToKeyArray($values);
    }

    /**
     * @param array $values
     *
     * @return array
     */
    private static function convertToKeyArray(array $values)
    {
        $result = array('kty' => 'RSA');
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
     * @param array $data
     *
     * @return string
     *
     * @throws \Exception
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
        $values = array(
            'n' => 'Modulus',
            'e' => 'Exponent',
            'p' => 'P',
            'd' => 'D',
            'q' => 'Q',
            'dp' => 'DP',
            'dq' => 'DQ',
            'qi' => 'InverseQ',
        );
        if (array_key_exists($key, $values)) {
            return $values[$key];
        }
    }
}
