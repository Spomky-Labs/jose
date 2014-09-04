<?php

namespace SpomkyLabs\JOSE\Algorithm;

interface KeyDecryptionInterface
{
    /**
     * @param string $encrypted_cek
     *
     * @return string|false
     */
    public function decryptKey($encrypted_cek, array $header = array());
}
