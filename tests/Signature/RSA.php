<?php

namespace SpomkyLabs\JOSE\Tests\Signature;

use SpomkyLabs\JOSE\Signature\RSA as Base;

class RSA extends Base
{
    private $values;

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
