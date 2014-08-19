<?php

namespace SpomkyLabs\JOSE\Tests\Signature;

use SpomkyLabs\JOSE\Signature\ECDSA as Base;

class ECDSA extends Base
{
    private $values = array();

    public function setX($x)
    {
        $this->values['x'] = $x;
        return $this;
    }

    public function setY($y)
    {
        $this->values['y'] = $y;
        return $this;
    }

    public function setD($d)
    {
        $this->values['d'] = $d;
        return $this;
    }

    public function setCurve($crv)
    {
        switch ($crv) {
            case 'P-256':
                $this->values['alg'] = 'ES256';
                break;
            case 'P-384':
                $this->values['alg'] = 'ES384';
                break;
            case 'P-521':
                $this->values['alg'] = 'ES512';
                break;
            default:
                throw new \Exception("Curve $crv is not supported");
        }
        $this->values['crv'] = $crv;
        return $this;
    }

    public function getValue($key)
    {
        return isset($this->values[$key])?$this->values[$key]:null;
    }

    public function getValues()
    {
        return $this->values;
    }

    public function setValues(array $values)
    {
        $this->values = $values;
        return $this;
    }
}
