<?php

namespace SpomkyLabs\JOSE\Algorithm;

interface ContentEncryptionInterface
{
    /**
     * Encrypt data
     *
     * @return string
     */
    public function encryptContent($data, $cek, $iv, array &$header = array());

    /**
     * @return string
     */
    public function calculateAuthenticationTag($cek, $iv, $encrypted_data, array $header);
}
