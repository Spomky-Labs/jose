<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Finder;

/**
 */
final class JKUFinder implements JWKFinderInterface
{
    /**
     * {@inheritdoc}
     */
    public function findJWK(array $header)
    {
        if (!isset($header['jku'])) {
            return;
        }

        $content = $this->downloadContent($header['jku']);
        if (null === $content) {
            return;
        }
        $content = json_decode($content, true);
        if (!is_array($content) || !array_key_exists('keys', $content)) {
            return;
        }

        return $content;
    }

    /**
     * @param string $url
     *
     * @return string|void
     */
    protected function downloadContent($url)
    {
        // The URL must be a valid URL and scheme must be https
        if (false === filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_SCHEME_REQUIRED | FILTER_FLAG_HOST_REQUIRED) || 'https://' !== substr($url, 0, 8)) {
            return;
        }

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_URL            => $url,
        ]);
        $content = curl_exec($ch);
        curl_close($ch);

        return $content;
    }
}
