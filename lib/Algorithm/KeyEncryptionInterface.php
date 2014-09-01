<?php

namespace SpomkyLabs\JOSE\Algorithm;

use SpomkyLabs\JOSE\JWKInterface;

interface KeyEncryptionInterface
{
    public function encryptKey($cek, array &$header = array(), JWKInterface $sender_key = null);

    public function getKeySize(array $header);
}
