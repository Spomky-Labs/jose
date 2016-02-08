<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Stub;

use Jose\ClaimChecker\AudienceChecker;
use Jose\ClaimChecker\ClaimCheckerManager as Base;

/**
 */
class ClaimCheckerManager extends Base
{
    /**
     * {@inheritdoc}
     */
    protected function getSupportedClaimCheckers()
    {
        return array_merge(
            parent::getSupportedClaimCheckers(),
            [
                new IssuerChecker(),
                new SubjectChecker(),
                new AudienceChecker('My Service'),
            ]
        );
    }
}
