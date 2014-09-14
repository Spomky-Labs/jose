<?php

namespace SpomkyLabs\JOSE\Algorithm;

interface ContentDecryptionInterface
{
    /**
     * @return string
     */
    public function decryptContent($data, $cek, $iv, array $header);

    /**
     * @return boolean
     */
    public function checkAuthenticationTag($authentication_tag, $cek, $iv, $encrypted_data, array $header);
}
