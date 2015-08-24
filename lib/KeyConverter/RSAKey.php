<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\KeyConverter;

use Base64Url\Base64Url;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\NullObject;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use Jose\JWKInterface;

class RSAKey extends Sequence
{
    private $private;
    private $n;
    private $e;
    private $d;
    private $p;
    private $q;
    private $dp;
    private $dq;
    private $qi;

    /**
     * @param \Jose\JWKInterface|string|array $data
     */
    public function __construct($data)
    {
        parent::__construct();

        if ($data instanceof JWKInterface) {
            $this->loadJWK($data->getValues());
        } elseif (is_array($data)) {
            $this->loadJWK($data);
        } elseif (is_string($data)) {
            $this->loadPEM($data);
        } else {
            throw new \InvalidArgumentException('Unsupported input');
        }
    }

    /**
     * @param $data
     *
     * @throws \Exception
     * @throws \FG\ASN1\Exception\ParserException
     *
     * @return array
     */
    private function loadPEM($data)
    {
        $res = openssl_pkey_get_private($data);
        if (false === $res) {
            $res = openssl_pkey_get_public($data);
        }
        if (false === $res) {
            throw new \Exception('Unable to load the key');
        }
        $details = openssl_pkey_get_details($res);
        if (!array_key_exists('rsa', $details)) {
            throw new \Exception('Unable to load the key');
        }

        foreach ($details['rsa'] as $key => $value) {
            $value = Base64Url::encode($value);
            if ($key === 'dmp1') {
                $this->dp = $value;
            } elseif ($key === 'dmq1') {
                $this->dq = $value;
            } elseif ($key === 'iqmp') {
                $this->qi = $value;
            } else {
                $this->$key = $value;
            }
        }
    }

    /**
     * @param array $jwk
     */
    private function loadJWK(array $jwk)
    {
        if (!array_key_exists('kty', $jwk) || 'RSA' !== $jwk['kty']) {
            throw new \InvalidArgumentException('JWK is not a RSA key');
        }

        $this->n = $jwk['n'];
        $this->e = $jwk['e'];
        if (array_key_exists('p', $jwk)) {
            $this->private = true;
            $this->p = $jwk['p'];
            $this->d = $jwk['d'];
            $this->q = $jwk['q'];
            $this->dp = $jwk['dp'];
            $this->dq = $jwk['dq'];
            $this->qi = $jwk['qi'];
            $this->initPrivateKey();
        } else {
            $this->private = false;
            $this->d = null;
            $this->initPublicKey();
        }
    }

    /**
     * @throws \Exception
     */
    private function initPublicKey()
    {
        $oid_sequence = new Sequence();
        $oid_sequence->addChild(new ObjectIdentifier('1.2.840.113549.1.1.1'));
        $oid_sequence->addChild(new NullObject());
        $this->addChild($oid_sequence);

        $n = new Integer($this->fromBase64ToInteger($this->n));
        $e = new Integer($this->fromBase64ToInteger($this->e));

        $key_sequence = new Sequence();
        $key_sequence->addChild($n);
        $key_sequence->addChild($e);
        $key_bit_string = new BitString(bin2hex($key_sequence->getBinary()));
        $this->addChild($key_bit_string);
    }

    /**
     *
     */
    private function initPrivateKey()
    {
        $this->addChild(new Integer(0));

        $oid_sequence = new Sequence();
        $oid_sequence->addChild(new ObjectIdentifier('1.2.840.113549.1.1.1'));
        $oid_sequence->addChild(new NullObject());
        $this->addChild($oid_sequence);

        $v = new Integer(0);
        $n = new Integer($this->fromBase64ToInteger($this->n));
        $e = new Integer($this->fromBase64ToInteger($this->e));
        $d = new Integer($this->fromBase64ToInteger($this->d));
        $p = new Integer($this->fromBase64ToInteger($this->p));
        $q = new Integer($this->fromBase64ToInteger($this->q));
        $dp = new Integer($this->fromBase64ToInteger($this->dp));
        $dq = new Integer($this->fromBase64ToInteger($this->dq));
        $qi = new Integer($this->fromBase64ToInteger($this->qi));

        $key_sequence = new Sequence();
        $key_sequence->addChild($v);
        $key_sequence->addChild($n);
        $key_sequence->addChild($e);
        $key_sequence->addChild($d);
        $key_sequence->addChild($p);
        $key_sequence->addChild($q);
        $key_sequence->addChild($dp);
        $key_sequence->addChild($dq);
        $key_sequence->addChild($qi);
        $key_octet_string = new OctetString(bin2hex($key_sequence->getBinary()));
        $this->addChild($key_octet_string);
    }

    /**
     * @param string $value
     *
     * @return string
     */
    private function fromBase64ToInteger($value)
    {
        return gmp_strval(gmp_init(current(unpack('H*', Base64Url::decode($value))), 16), 10);
    }

    /**
     * @return bool
     */
    public function isPrivate()
    {
        return $this->private;
    }

    /**
     * @param \SpomkyLabs\Jose\KeyConverter\RSAKey $private
     *
     * @return \SpomkyLabs\Jose\KeyConverter\RSAKey
     */
    public static function toPublic(RSAKey $private)
    {
        $data = $private->toArray();
        $keys = ['p','d','q','dp','dq','qi'];
        foreach ($keys as $key) {
            if (array_key_exists($key, $data)) {
                unset($data[$key]);
            }
        }

        return new self($data);
    }

    public function __toString()
    {
        return $this->toPEM();
    }

    /**
     * @return array
     */
    public function toArray()
    {
        $values = [
            'kty' => 'RSA',
            'n' => $this->n,
            'e' => $this->e,
        ];
        if (true === $this->private) {
            $values['p'] = $this->p;
            $values['d'] = $this->d;
            $values['q'] = $this->q;
            $values['dp'] = $this->dp;
            $values['dq'] = $this->dq;
            $values['qi'] = $this->qi;
        }

        return $values;
    }

    /**
     * @return string
     */
    public function toPEM()
    {
        $tmp = base64_encode($this->getBinary());
        $length = strlen($tmp);

        for ($i = 0; $i < $length; ++$i) {
            if (($i + 2) % 65 === 0) {
                $tmp = substr($tmp, 0, $i + 1).PHP_EOL.substr($tmp, $i + 1);
            }
        }

        $result = '-----BEGIN '.($this->private ? 'PRIVATE' : 'PUBLIC').' KEY-----'.PHP_EOL;
        $result .= $tmp.PHP_EOL;
        $result .= '-----END '.($this->private ? 'PRIVATE' : 'PUBLIC').' KEY-----'.PHP_EOL;

        return $result;
    }
}
