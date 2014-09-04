<?php

namespace SpomkyLabs\JOSE\Algorithm;

interface KeyWrapInterface
{
    public function wrapKey($cek, array &$header = array());
}
