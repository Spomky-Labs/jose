<?php

namespace SpomkyLabs\JOSE\Algorithm;

interface unwrapKey
{
    public function unwrapKey($wrapped_cek, array $header = array());
}
