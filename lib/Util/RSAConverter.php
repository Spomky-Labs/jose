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
                throw new \Exception("Key '$key' is not supported");
        }
    }
}
