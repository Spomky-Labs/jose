<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Jose\KeyConverter\KeyConverter;
use Jose\Object\JWK;
use Jose\Object\JWKSet;

final class JWKFactory
{
    /**
     * @param array $values
     *
     * @return \Jose\Object\JWKInterface|\Jose\Object\JWKSetInterface
     */
    public static function createFromValues(array $values)
    {
        if (array_key_exists('keys', $values) && is_array($values['keys'])) {
            return new JWKSet($values);
        }

        return new JWK($values);
    }

    /**
     * @param string $file
     * @param array  $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromCertificateFile($file, array $additional_values = [])
    {
        $values = KeyConverter::loadKeyFromCertificateFile($file);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * @param string $certificate
     * @param array  $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromCertificate($certificate, array $additional_values = [])
    {
        $values = KeyConverter::loadKeyFromCertificate($certificate);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * @param resource $res
     * @param array    $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromX509Resource($res, array $additional_values = [])
    {
        $values = KeyConverter::loadKeyFromX509Resource($res);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * @param string      $file
     * @param null|string $password
     * @param array       $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromKeyFile($file, $password = null, array $additional_values = [])
    {
        $values = KeyConverter::loadFromKeyFile($file, $password);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * @param string      $key
     * @param null|string $password
     * @param array       $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromKey($key, $password = null, array $additional_values = [])
    {
        $values = KeyConverter::loadFromKey($key, $password);
        $values = array_merge($values, $additional_values);

        return new JWK($values);
    }

    /**
     * @param string $jku
     * @param bool   $allow_unsecured_connection
     *
     * @return \Jose\Object\JWKSet
     */
    public static function createFromJKU($jku, $allow_unsecured_connection = false)
    {
        $content = self::downloadContent($jku, $allow_unsecured_connection);
        $content = json_decode($content, true);
        if (!is_array($content) || !array_key_exists('keys', $content)) {
            throw new \InvalidArgumentException('Invalid content.');
        }

        return new JWKSet($content);
    }

    /**
     * @param string $x5u
     * @param bool   $allow_unsecured_connection
     *
     * @return \Jose\Object\JWKSetInterface
     */
    public static function createFromX5U($x5u, $allow_unsecured_connection = false)
    {
        $content = self::downloadContent($x5u, $allow_unsecured_connection);
        $content = json_decode($content, true);
        if (!is_array($content)) {
            throw new \InvalidArgumentException('Invalid content.');
        }

        $jwkset = new JWKSet();
        foreach ($content as $kid => $cert) {
            $jwk = KeyConverter::loadKeyFromCertificate($cert);
            if (empty($jwk)) {
                throw new \InvalidArgumentException('Invalid content.');
            }
            if (is_string($kid)) {
                $jwk['kid'] = $kid;
            }
            $jwkset = $jwkset->addKey(new JWK($jwk));
        }

        return $jwkset;
    }

    /**
     * @param array $x5c
     * @param array $additional_values
     *
     * @return \Jose\Object\JWKInterface
     */
    public static function createFromX5C(array $x5c, array $additional_values = [])
    {
        $certificate = null;
        $last_issuer = null;
        $last_subject = null;
        foreach ($x5c as $cert) {
            $current_cert = "-----BEGIN CERTIFICATE-----\n$cert\n-----END CERTIFICATE-----";
            $x509 = openssl_x509_read($current_cert);
            if (false === $x509) {
                $last_issuer = null;
                $last_subject = null;
                break;
            }
            $parsed = openssl_x509_parse($x509);
            openssl_x509_free($x509);
            if (false === $parsed) {
                $last_issuer = null;
                $last_subject = null;
                break;
            }
            if (null === $last_subject) {
                $last_subject = $parsed['subject'];
                $last_issuer = $parsed['issuer'];
                $certificate = $current_cert;
            } else {
                if (json_encode($last_issuer) === json_encode($parsed['subject'])) {
                    $last_subject = $parsed['subject'];
                    $last_issuer = $parsed['issuer'];
                } else {
                    $last_issuer = null;
                    $last_subject = null;
                    break;
                }
            }
        }
        if (null === $last_issuer || json_encode($last_issuer) !== json_encode($last_subject)) {
            throw new \InvalidArgumentException('Invalid certificate chain.');
        }

        return self::createFromCertificate($certificate, $additional_values);
    }

    /**
     * @param string $url
     * @param bool   $allow_unsecured_connection
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function downloadContent($url, $allow_unsecured_connection)
    {
        // The URL must be a valid URL and scheme must be https
        if (false === filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_SCHEME_REQUIRED | FILTER_FLAG_HOST_REQUIRED)) {
            throw new \InvalidArgumentException('Invalid URL.');
        }
        if (false === $allow_unsecured_connection && 'https://' !==  substr($url, 0, 8)) {
            throw new \InvalidArgumentException('Unsecured connection.');
        }

        $params = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_URL            => $url,
        ];
        if (false === $allow_unsecured_connection) {
            $params[CURLOPT_SSL_VERIFYPEER] = true;
            $params[CURLOPT_SSL_VERIFYHOST] = 2;
        }

        $ch = curl_init();
        curl_setopt_array($ch, $params);
        $content = curl_exec($ch);
        curl_close($ch);

        if (empty($content)) {
            throw new \InvalidArgumentException('Unable to get content.');
        }

        return $content;
    }
}
