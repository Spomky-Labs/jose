<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\KeyConverter;

use Base64Url\Base64Url;
use FG\ASN1\ExplicitlyTaggedObject;
use FG\ASN1\Object;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use Jose\JWKInterface;

final class ECKey extends Sequence
{
    /**
     * @var bool
     */
    private $private = false;

    /**
     * @var array
     */
    private $values = [];

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
        $this->private = isset($this->values['d']);
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
        $this->values = $jwk;
        if (array_key_exists('d', $jwk)) {
            $this->initPrivateKey();
        } else {
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
        $oid_sequence->addChild(new ObjectIdentifier($this->getOID($this->values['crv'])));
        $this->addChild($oid_sequence);

        $bits = '04';
        $bits .= bin2hex(Base64Url::decode($this->values['x']));
        $bits .= bin2hex(Base64Url::decode($this->values['y']));
        $this->addChild(new BitString($bits));
    }

    /**
     *
     */
    private function initPrivateKey()
    {
        $this->addChild(new Integer(1));
        $this->addChild(new OctetString(bin2hex(Base64Url::decode($this->values['d']))));

        $oid = new ObjectIdentifier($this->getOID($this->values['crv']));
        $this->addChild(new ExplicitlyTaggedObject(0, $oid));

        $bits = '04';
        $bits .= bin2hex(Base64Url::decode($this->values['x']));
        $bits .= bin2hex(Base64Url::decode($this->values['y']));
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

        $this->values['kty'] = 'EC';
        $this->values['crv'] = $this->getCurve($sub[1]->getContent());
        $this->values['x'] = Base64Url::encode(hex2bin(substr($bits, 2, (strlen($bits) - 2) / 2)));
        $this->values['y'] = Base64Url::encode(hex2bin(substr($bits, (strlen($bits) - 2) / 2 + 2, (strlen($bits) - 2) / 2)));
    }

    /**
     * @param \FG\ASN1\Object $children
     *
     * @throws \Exception
     */
    private function verifyVersion(Object $children)
    {
        if (!$children instanceof Integer || 1 !== (int) $children->getContent()) {
            throw new \Exception('Unable to load the key');
        }
    }

    /**
     * @param \FG\ASN1\Object $children
     * @param string|null     $x
     * @param string|null     $y
     *
     * @throws \Exception
     */
    private function getXAndY(Object $children, &$x, &$y)
    {
        if (!$children instanceof ExplicitlyTaggedObject) {
            throw new \Exception('Unable to load the key');
        }
        if (!$children->getContent() instanceof BitString) {
            throw new \Exception('Unable to load the key');
        }

        $bits = $children->getContent()->getContent();

        if (substr($bits, 0, 2) !== '04') {
            throw new \Exception('Unsupported key type');
        }

        $x = substr($bits, 2, (strlen($bits) - 2) / 2);
        $y = substr($bits, (strlen($bits) - 2) / 2 + 2, (strlen($bits) - 2) / 2);
    }

    /**
     * @param \FG\ASN1\Object $children
     *
     * @throws \Exception
     *
     * @return string
     */
    private function getD(Object $children)
    {
        if (!$children instanceof OctetString) {
            throw new \Exception('Unable to load the key');
        }

        return $children->getContent();
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
        $this->verifyVersion($children[0]);

        $x = null;
        $y = null;
        $d = $this->getD($children[1]);
        $this->getXAndY($children[3], $x, $y);

        if (!$children[2] instanceof ExplicitlyTaggedObject) {
            throw new \Exception('Unable to load the key');
        }
        if (!$children[2]->getContent() instanceof ObjectIdentifier) {
            throw new \Exception('Unable to load the key');
        }
        $curve = $children[2]->getContent()->getContent();

        $this->private = true;
        $this->values['kty'] = 'EC';
        $this->values['crv'] = $this->getCurve($curve);
        $this->values['d'] = Base64Url::encode(hex2bin($d));
        $this->values['x'] = Base64Url::encode(hex2bin($x));
        $this->values['y'] = Base64Url::encode(hex2bin($y));
    }

    /**
     * @return bool
     */
    public function isPrivate()
    {
        return $this->private;
    }

    /**
     * @param \Jose\KeyConverter\ECKey $private
     *
     * @return \Jose\KeyConverter\ECKey
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
        return $this->values;
    }

    /**
     * @return string
     */
    public function toPEM()
    {
        $result = '-----BEGIN '.($this->private ? 'EC PRIVATE' : 'PUBLIC').' KEY-----'.PHP_EOL;
        $result .= chunk_split(base64_encode($this->getBinary()), 64, PHP_EOL);
        $result .= '-----END '.($this->private ? 'EC PRIVATE' : 'PUBLIC').' KEY-----'.PHP_EOL;

        return $result;
    }

    /**
     * @param $curve
     *
     * @return string
     */
    private function getOID($curve)
    {
        $curves = $this->getSupportedCurves();
        $oid = array_key_exists($curve, $curves) ? $curves[$curve] : null;
        if (null === $oid) {
            throw new \InvalidArgumentException('Unsupported curve');
        }

        return $oid;
    }

    /**
     * @param string $oid
     *
     * @return string
     */
    private function getCurve($oid)
    {
        $curves = $this->getSupportedCurves();
        $curve = array_search($oid, $curves, true);
        if (false === $curve) {
            throw new \InvalidArgumentException('Unsupported OID');
        }

        return $curve;
    }

    private function getSupportedCurves()
    {
        return [
            'P-192' => '1.2.840.10045.3.1.1',
            'P-256' => '1.2.840.10045.3.1.7',
            'P-384' => '1.3.132.0.34',
            'P-521' => '1.3.132.0.35',
        ];
    }
}
