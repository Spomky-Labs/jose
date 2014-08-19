<?php

namespace SpomkyLabs\JOSE\Tests\Signature;

use SpomkyLabs\JOSE\Signature\Hmac as Base;

class Hmac extends Base
{
    private $values = array();

    public function setAlgorithm($alg)
    {
        $this->values['alg'] = $alg;

        return $this;
    }

    public function setKey($k)
    {
        $this->values['k'] = $k;

        return $this;
    }

    public function getValue($key)
    {
        return isset($this->values[$key]) ? $this->values[$key] : null;
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

    public function setValue($key, $value)
    {
        $this->values[$key] = $value;

        return $this;
    }
}
