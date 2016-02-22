<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\KeyConverter;

use Base64Url\Base64Url;
use phpseclib\Crypt\RSA;

/**
 * This class will help you to load an EC key or a RSA key/certificate (private or public) and get values to create a JWK object.
 */
final class KeyConverter
{
    /**
     * @param string $file
     *
     * @throws \InvalidArgumentException
     *
     * @return array
     */
    public static function loadKeyFromCertificateFile($file)
    {
        if (!file_exists($file)) {
            throw new \InvalidArgumentException(sprintf('File "%s" does not exist.', $file));
        }
        $content = file_get_contents($file);

        return self::loadKeyFromCertificate($content);
    }

    /**
     * @param string $certificate
     *
     * @throws \InvalidArgumentException
     *
     * @return array
     */
    public static function loadKeyFromCertificate($certificate)
    {
        try {
            $res = openssl_x509_read($certificate);
        } catch (\Exception $e) {
            $certificate = self::convertDerToPem($certificate);
            $res = openssl_x509_read($certificate);
        }
        if (false === $res) {
            throw new \InvalidArgumentException('Unable to load the certificate');
        }
        $values = self::loadKeyFromX509Resource($res);
        openssl_x509_free($res);

        return $values;
    }

    /**
     * @param resource $res
     *
     * @throws \Exception
     *
     * @return array
     */
    public static function loadKeyFromX509Resource($res)
    {
        $key = openssl_get_publickey($res);

        $details = openssl_pkey_get_details($key);
        if (isset($details['key'])) {
            $values = self::loadKeyFromPEM($details['key']);
            openssl_x509_export($res, $out);
            $values['x5c'] = [trim(preg_replace('#-.*-#', '', $out))];

            if (function_exists('openssl_x509_fingerprint')) {
                $values['x5t'] = Base64Url::encode(openssl_x509_fingerprint($res, 'sha1', true));
                $values['x5t#256'] = Base64Url::encode(openssl_x509_fingerprint($res, 'sha256', true));
            } else {
                openssl_x509_export($res, $pem);
                $values['x5t'] = Base64Url::encode(self::calculateX509Fingerprint($pem, 'sha1', true));
                $values['x5t#256'] = Base64Url::encode(self::calculateX509Fingerprint($pem, 'sha256', true));
            }

            return $values;
        }
        throw new \InvalidArgumentException('Unable to load the certificate');
    }

    /**
     * @param string      $file
     * @param null|string $password
     *
     * @throws \Exception
     *
     * @return array
     */
    public static function loadFromKeyFile($file, $password = null)
    {
        $content = file_get_contents($file);

        return self::loadFromKey($content, $password);
    }

    /**
     * @param string      $key
     * @param null|string $password
     *
     * @throws \Exception
     *
     * @return array
     */
    public static function loadFromKey($key, $password = null)
    {
        try {
            return self::loadKeyFromDER($key, $password);
        } catch (\Exception $e) {
            return self::loadKeyFromPEM($key, $password);
        }
    }

    /**
     * @param string      $der
     * @param null|string $password
     *
     * @throws \Exception
     *
     * @return array
     */
    private static function loadKeyFromDER($der, $password = null)
    {
        $pem = self::convertDerToPem($der);

        return self::loadKeyFromPEM($pem, $password);
    }

    /**
     * @param string      $pem
     * @param null|string $password
     *
     * @throws \Exception
     *
     * @return array
     */
    private static function loadKeyFromPEM($pem, $password = null)
    {
        if (preg_match('#DEK-Info: (.+),(.+)#', $pem, $matches)) {
            $pem = self::decodePEM($pem, $matches, $password);
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
     * @param array $x5c
     *
     * @return array
     */
    public static function loadFromX5C(array $x5c)
    {
        $certificate = null;
        $last_issuer = null;
        $last_subject = null;
        foreach ($x5c as $cert) {
            $current_cert = "-----BEGIN CERTIFICATE-----\n$cert\n-----END CERTIFICATE-----";
            $x509 = openssl_x509_read($current_cert);
            if (false === $x509) {
                $last_issuer = null;
                $last_subject = null;
                break;
            }
            $parsed = openssl_x509_parse($x509);

            openssl_x509_free($x509);
            if (false === $parsed) {
                $last_issuer = null;
                $last_subject = null;
                break;
            }
            if (null === $last_subject) {
                $last_subject = $parsed['subject'];
                $last_issuer = $parsed['issuer'];
                $certificate = $current_cert;
            } else {
                if (json_encode($last_issuer) === json_encode($parsed['subject'])) {
                    $last_subject = $parsed['subject'];
                    $last_issuer = $parsed['issuer'];
                } else {
                    $last_issuer = null;
                    $last_subject = null;
                    break;
                }
            }
        }
        if (null === $last_issuer || json_encode($last_issuer) !== json_encode($last_subject)) {
            throw new \InvalidArgumentException('Invalid certificate chain.');
        }

        return self::loadKeyFromCertificate($certificate);
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
     * @return string
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

    /**
     * @param string      $pem
     * @param string[]    $matches
     * @param null|string $password
     *
     * @return string
     */
    private static function decodePem($pem, array $matches, $password = null)
    {
        if (null === $password) {
            throw new \InvalidArgumentException('Password required for encrypted keys.');
        }
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

        return $pem;
    }

    /**
     * @param string $der_data
     *
     * @return string
     */
    private static function convertDerToPem($der_data)
    {
        $pem = chunk_split(base64_encode($der_data), 64, PHP_EOL);
        $pem = '-----BEGIN CERTIFICATE-----'.PHP_EOL.$pem.'-----END CERTIFICATE-----'.PHP_EOL;

        return $pem;
    }

    /**
     * @param string $pem
     * @param string $algorithm
     * @param bool   $binary
     *
     * @return string
     */
    private static function calculateX509Fingerprint($pem, $algorithm, $binary = false)
    {
        $pem = preg_replace('#-.*-|\r|\n#', '', $pem);
        $bin = base64_decode($pem);

        return hash($algorithm, $bin, $binary);
    }
}
