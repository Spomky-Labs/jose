<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

use phpseclib\Crypt\AES;

/**
 */
class AESPHPSecLib implements AESInterface
{
    public static function encrypt($data, $k, $iv)
    {
        $aes = new AES(MCRYPT_MODE_CBC);
        $aes->setKey($k);
        $aes->setIV($iv);

        return $aes->encrypt($data);
    }

    public static function decrypt($data, $k, $iv)
    {
        $aes = new AES(MCRYPT_MODE_CBC);
        $aes->setKey($k);
        $aes->setIV($iv);

        return $aes->decrypt($data);
    }
}
