<?php

namespace SpomkyLabs\JOSE\Tests\Signature;

use SpomkyLabs\JOSE\Signature\None as Base;

class None extends Base
{
    public function getValue($key)
    {
        return null;
    }

    public function getValues()
    {
        return array();
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
