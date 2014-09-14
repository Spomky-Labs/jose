<?php

namespace SpomkyLabs\JOSE\Algorithm;

use SpomkyLabs\JOSE\JWKInterface;

interface KeyEncryptionInterface
{
    /**
     * [encryptKey description]
     * @param  string       $cek        The Content Encryption Key
     * @param  array        $header     The header
     * @param  JWKInterface $sender_key The sender's key
     * @return string
     */
    public function encryptKey($cek, array &$header = array(), JWKInterface $sender_key = null);
}
