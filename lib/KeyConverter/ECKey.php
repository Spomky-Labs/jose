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
use FG\ASN1\ExplicitlyTaggedObject;
use FG\ASN1\Object;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use Jose\JWKInterface;

class ECKey extends Sequence
{
    private $private;
    private $curve;
    private $d;
    private $x;
    private $y;

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
        $data = base64_decode(preg_replace('#-.*-|\r|\n#', '', $data));
        $asnObject = Object::fromBinary($data);

        if (!$asnObject instanceof Sequence) {
            throw new \Exception('Unable to load the key');
        }
        $children = $asnObject->getChildren();
        if (4 === count($children)) {
            return $this->loadPrivatePEM($children);
        } elseif (2 === count($children)) {
            return $this->loadPublicPEM($children);
        }
        throw new \Exception('Unable to load the key');
    }

    /**
     * @param array $jwk
     */
    private function loadJWK(array $jwk)
    {
        if (!array_key_exists('kty', $jwk) || 'EC' !== $jwk['kty']) {
            throw new \InvalidArgumentException('JWK is not an Elliptic Curve key');
        }
        if (!array_key_exists('crv', $jwk)) {
            throw new \InvalidArgumentException('Curve parameter is missing');
        }
        if (!array_key_exists('x', $jwk) || !array_key_exists('y', $jwk)) {
            throw new \InvalidArgumentException('Point parameters are missing');
        }
        $this->curve = $jwk['crv'];
        $this->x = $jwk['x'];
        $this->y = $jwk['y'];
        if (array_key_exists('d', $jwk)) {
            $this->private = true;
            $this->d = $jwk['d'];
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
        $oid_sequence->addChild(new ObjectIdentifier('1.2.840.10045.2.1'));
        $oid_sequence->addChild(new ObjectIdentifier($this->getOID($this->curve)));
        $this->addChild($oid_sequence);

        $bits = '04';
        $bits .= bin2hex(Base64Url::decode($this->x));
        $bits .= bin2hex(Base64Url::decode($this->y));
        $this->addChild(new BitString($bits));
    }

    /**
     *
     */
    private function initPrivateKey()
    {
        $this->addChild(new Integer(1));
        $this->addChild(new OctetString(bin2hex(Base64Url::decode($this->d))));

        $oid = new ObjectIdentifier($this->getOID($this->curve));
        $this->addChild(new ExplicitlyTaggedObject(0, $oid));

        $bits = '04';
        $bits .= bin2hex(Base64Url::decode($this->x));
        $bits .= bin2hex(Base64Url::decode($this->y));
        $bit = new BitString($bits);
        $this->addChild(new ExplicitlyTaggedObject(1, $bit));
    }

    /**
     * @param array $children
     *
     * @throws \Exception
     *
     * @return array
     */
    private function loadPublicPEM(array $children)
    {
        if (!$children[0] instanceof Sequence) {
            throw new \Exception('Unable to load the key');
        }
        $sub = $children[0]->getChildren();
        if (!$sub[0] instanceof ObjectIdentifier || '1.2.840.10045.2.1' !== $sub[0]->getContent()) {
            throw new \Exception('Unsupported key type');
        }
        if (!$sub[1] instanceof ObjectIdentifier) {
            throw new \Exception('Unsupported key type');
        }

        if (!$children[1] instanceof BitString) {
            throw new \Exception('Unable to load the key');
        }

        $bits = $children[1]->getContent();

        if (substr($bits, 0, 2) !== '04') {
            throw new \Exception('Unsupported key type');
        }

        $this->private = false;
        $this->curve = $this->getCurve($sub[1]->getContent());
        $this->x = Base64Url::encode(hex2bin(substr($bits, 2, (strlen($bits) - 2) / 2)));
        $this->y = Base64Url::encode(hex2bin(substr($bits, (strlen($bits) - 2) / 2 + 2, (strlen($bits) - 2) / 2)));
    }

    /**
     * @param array $children
     *
     * @throws \Exception
     *
     * @return array
     */
    private function loadPrivatePEM(array $children)
    {
        if (!$children[0] instanceof Integer || 1 !== (int) $children[0]->getContent()) {
            throw new \Exception('Unable to load the key');
        }
        if (!$children[1] instanceof OctetString) {
            throw new \Exception('Unable to load the key');
        }

        if (!$children[2] instanceof ExplicitlyTaggedObject) {
            throw new \Exception('Unable to load the key');
        }
        if (!$children[2]->getContent() instanceof ObjectIdentifier) {
            throw new \Exception('Unable to load the key');
        }

        if (!$children[3] instanceof ExplicitlyTaggedObject) {
            throw new \Exception('Unable to load the key');
        }
        if (!$children[3]->getContent() instanceof BitString) {
            throw new \Exception('Unable to load the key');
        }

        $bits = $children[3]->getContent()->getContent();

        if (substr($bits, 0, 2) !== '04') {
            throw new \Exception('Unsupported key type');
        }

        $this->private = true;
        $this->curve = $this->getCurve($children[2]->getContent()->getContent());
        $this->d = Base64Url::encode(hex2bin($children[1]->getContent()));
        $this->x = Base64Url::encode(hex2bin(substr($bits, 2, (strlen($bits) - 2) / 2)));
        $this->y = Base64Url::encode(hex2bin(substr($bits, (strlen($bits) - 2) / 2 + 2, (strlen($bits) - 2) / 2)));
    }

    /**
     * @return bool
     */
    public function isPrivate()
    {
        return $this->private;
    }

    /**
     * @param \SpomkyLabs\Jose\KeyConverter\ECKey $private
     *
     * @return \SpomkyLabs\Jose\KeyConverter\ECKey
     */
    public static function toPublic(ECKey $private)
    {
        $data = $private->toArray();
        if (array_key_exists('d', $data)) {
            unset($data['d']);
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
            'kty' => 'EC',
            'crv' => $this->curve,
            'x'   => $this->x,
            'y'   => $this->y,
        ];
        if (true === $this->private) {
            $values['d'] = $this->d;
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

        $result = '-----'.($this->private ? 'BEGIN EC PRIVATE KEY' : 'BEGIN PUBLIC KEY').'-----'.PHP_EOL;
        $result .= $tmp.PHP_EOL;
        $result .= '-----'.($this->private ? 'END EC PRIVATE KEY' : 'END PUBLIC KEY').'-----'.PHP_EOL;

        return $result;
    }

    /**
     * @param string $curve
     *
     * @return string
     */
    private function getOID($curve)
    {
        switch ($curve) {
            case 'P-256':
                return '1.2.840.10045.3.1.7';
            case 'P-384':
                return '1.3.132.0.34';
            case 'P-521':
                return '1.3.132.0.35';
            default:
                throw new \InvalidArgumentException('Unsupported curve');
        }
    }

    /**
     * @param string $oid
     *
     * @return string
     */
    private function getCurve($oid)
    {
        switch ($oid) {
            case '1.2.840.10045.3.1.7':
                return 'P-256';
            case '1.3.132.0.34':
                return 'P-384';
            case '1.3.132.0.35':
                return 'P-521';
            default:
                throw new \InvalidArgumentException('Unsupported OID');
        }
    }
}
