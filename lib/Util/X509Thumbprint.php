<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Util;

class X509Thumbprint
{
    public static function calculateThumbprint($certificate, $hash)
    {
        if (function_exists('openssl_x509_fingerprint')) {
            $cert = openssl_x509_read($certificate);
            return openssl_x509_fingerprint($cert, $hash);
        }
        $cert = preg_replace('#-.*-|\r|\n#', '', $certificate);
        $bin = base64_decode($cert);
        return hash($hash, $bin);
    }
}
