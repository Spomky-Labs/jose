<?php

namespace SpomkyLabs\JOSE\Algorithm;

interface ContentEncryptionInterface
{
    /**
     * Encrypt data
     *
     * @param string $data
     * @return string
     */
    public function encryptContent($data, $cek, $iv, array &$header = array());

    /**
     * @param string $encrypted_data
     * @return string
     */
    public function calculateAuthenticationTag($cek, $iv, $encrypted_data, array $header);

    /**
     * @return integer
     */
    public function getIVSize(array $header);

    /**
     * @return integer
     */
    public function getCEKSize(array $header);
}
