<?php

namespace Jose\Test\Stub;

use Jose\ClaimChecker\SubjectChecker as Base;

/**
 */
class SubjectChecker extends Base
{
    /**
     * {@inheritdoc}
     */
    protected function isSubjectAllowed($subject)
    {
        return in_array($subject, ['SUB1', 'SUB2']);
    }
}
