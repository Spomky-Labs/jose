<?php

namespace SpomkyLabs\JOSE\Algorithm;

interface KeyDecryptionInterface
{
    public function decryptKey($encrypted_cek, array $header = array());
}
