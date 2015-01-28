<?php

namespace SpomkyLabs\Jose\Util;

use Base64Url\Base64Url;

/**
 * Encode and decode data into Base64 Url Safe
 */
class RSAConverter
{
    protected static function checkRequirements()
    {
        if (!class_exists("\Crypt_RSA")) {
            throw new \RuntimeException("The library 'phpseclib/phpseclib' is required to use RSA based algorithms");
        }
    }

    public static function fromArrayToRSACrypt(array $data)
    {
        self::checkRequirements();
        $xml = self::fromArrayToXML($data);
        $rsa = new \Crypt_RSA();
        $rsa->loadKey($xml);

        return $rsa;
    }

    /**
     * @param string $certificate
     * @param string $passphrase
     */
    public static function laodCertificateValues($certificate, $passphrase = null)
    {
        $res = openssl_pkey_get_private($certificate, $passphrase);
        if ($res === false) {
            $res = openssl_pkey_get_public($certificate);
        }
        if ($res === false) {
            throw new \Exception("Unable to load the certificate");
        }
        $details = openssl_pkey_get_details($res);
        if ($details === false) {
            throw new \Exception("Unable to get details of the certificate");
        }
        if (!is_array($details) || !isset($details['rsa'])) {
            throw new \Exception("Certificate is not a valid RSA certificate");
        }

        return $details['rsa'];
    }

    /**
     * @param string $certificate
     * @param string $passphrase
     */
    public static function fromCertificateToArray($certificate, $passphrase = null)
    {
        $values = self::laodCertificateValues($certificate, $passphrase);
        $result = array('kty' => 'RSA');
        foreach ($values as $key => $value) {
            $value = Base64Url::encode($value);
            if ($key === "dmp1") {
                $result["dp"] = $value;
            } elseif ($key === "dmq1") {
                $result["dq"] = $value;
            } elseif ($key === "iqmp") {
                $result["qi"] = $value;
            } else {
                $result[$key] = $value;
            }
        }

        return $result;
    }

    public static function fromArrayToXML(array $data)
    {
        $result = "<RSAKeyPair>\n";
        foreach ($data as $key => $value) {
            $element = self::getElement($key);
            $value = strtr($value, '-_', '+/');

            switch (strlen($value)%4) {
                case 0:
                    break; // No pad chars in this case
                case 2:
                    $value .= "==";
                    break; // Two pad chars
                case 3:
                    $value .= "=";
                    break; // One pad char
                default:
                    throw new \Exception("Invalid data");
            }

            $result .= "\t<$element>$value</$element>\n";
        }
        $result .= "</RSAKeyPair>";

        return $result;
    }

    protected static function getElement($key)
    {
        $values = array(
            'n' => "Modulus",
            'e' => "Exponent",
            'p' => "P",
            'd' => "D",
            'q' => "Q",
            'dp' => "DP",
            'dq' => "DQ",
            'qi' => "InverseQ",
        );
        if (array_key_exists($key, $values)) {
            return $values[$key];
        }
    }
}
