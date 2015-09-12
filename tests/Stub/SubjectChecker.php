<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Test\Stub;

use SpomkyLabs\Jose\Checker\SubjectChecker as Base;

/**
 */
class SubjectChecker extends Base
{
    /**
     * {@inheritdoc}
     */
    protected function isSubjectValid($subject)
    {
        return in_array($subject, ['SUB1', 'SUB2']);
    }
}
