<?php

namespace SpomkyLabs\JOSE\Util;

/**
 * Encode and decode data into Base64 Url Safe
 */
class RSAConverter
{
    public static function fromArrayToRSA_Crypt(array $data)
    {
        $xml = self::fromArrayToXML($data);
        $rsa = new \Crypt_RSA();
        $rsa->loadKey($xml);

        return $rsa;
    }

    /**
     * @param string $certificate
     * @param string $passphrase
     */
    public static function fromCertificateToArray($certificate, $passphrase = null)
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
        $values = $details['rsa'];
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
        switch ($key) {
            case 'n':
                return "Modulus";
            case 'e':
                return "Exponent";
            case 'p':
                return "P";
            case 'd':
                return "D";
            case 'q':
                return "Q";
            case 'dp':
                return "DP";
            case 'dq':
                return "DQ";
            case 'qi':
                return "InverseQ";
            default:
                break;
        }
    }
}
