<?php

namespace SpomkyLabs\JOSE\Algorithm;

interface KeyUnwrapInterface
{
    public function unwrapKey($wrapped_cek, array $header = array());
}
