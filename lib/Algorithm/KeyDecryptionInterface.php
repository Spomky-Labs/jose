<?php

namespace SpomkyLabs\JOSE\Algorithm;

interface KeyDecryptionInterface
{
    /**
     * [decryptKey description]
     * @param  string $encrypted_cek The encrypted CEK
     * @param  array  $header        The header
     *
     * @return string|false
     */
    public function decryptKey($encrypted_cek, array $header = array());
}
