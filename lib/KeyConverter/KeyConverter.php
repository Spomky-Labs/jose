<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
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
     * @param null|string $password
     *
     * @throws \Exception
     *
     * @return array
     */
    public static function loadKeyFromPEM($pem, $password = null)
    {
        if (preg_match('#DEK-Info: (.+),(.+)#', $pem, $matches)) {
            $iv = pack('H*', trim($matches[2]));
            $symkey = pack('H*', md5($password.substr($iv, 0, 8)));
            $symkey .= pack('H*', md5($symkey.$password.substr($iv, 0, 8)));
            $key = preg_replace('#^(?:Proc-Type|DEK-Info): .*#m', '', $pem);
            $ciphertext = base64_decode(preg_replace('#-.*-|\r|\n#', '', $key));

            $decoded = openssl_decrypt($ciphertext, strtolower($matches[1]), $symkey, true, $iv);

            $number = preg_match_all('#-{5}.*-{5}#', $pem, $result);
            if (2 !== $number) {
                throw new \InvalidArgumentException('Unable to load the key');
            }
            $pem = $result[0][0].PHP_EOL;
            $pem .= chunk_split(base64_encode($decoded), 64);
            $pem .= $result[0][1].PHP_EOL;
        }

        $res = openssl_pkey_get_private($pem);
        if ($res === false) {
            $res = openssl_pkey_get_public($pem);
        }
        if ($res === false) {
            throw new \InvalidArgumentException('Unable to load the key');
        }

        $details = openssl_pkey_get_details($res);
        if (!is_array($details) || !array_key_exists('type', $details)) {
            throw new \Exception('Unable to get details of the key');
        }

        switch ($details['type']) {
            case OPENSSL_KEYTYPE_EC:
                $ec_key = new ECKey($pem);

                return $ec_key->toArray();
            case OPENSSL_KEYTYPE_RSA:
                $temp = [
                    'kty' => 'RSA',
                ];

                foreach ([
                    'n' => 'n',
                    'e' => 'e',
                    'd' => 'd',
                    'p' => 'p',
                    'q' => 'q',
                    'dp' => 'dmp1',
                    'dq' => 'dmq1',
                    'qi' => 'iqmp',
                        ] as $A => $B) {
                    if (array_key_exists($B, $details['rsa'])) {
                        $temp[$A] = Base64Url::encode($details['rsa'][$B]);
                    }
                }

                return $temp;
                /*
                 * The following lines will be used when FGrosse/PHPASN1 v1.4.0 will be available
                 * (not available because of current version of mdanter/phpecc.
                 * $rsa_key = new RSAKey($pem);
                 *
                 * return $rsa_key->toArray();
                 */
            default:
                throw new \InvalidArgumentException('Unsupported key type');
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
