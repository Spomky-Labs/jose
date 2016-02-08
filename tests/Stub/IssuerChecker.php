<?php

namespace Jose\Test\Stub;

use Jose\ClaimChecker\IssuerChecker as Base;

/**
 */
class IssuerChecker extends Base
{
    /**
     * {@inheritdoc}
     */
    protected function isIssuerAllowed($issuer)
    {
        return in_array($issuer, ['ISS1', 'ISS2']);
    }
}
