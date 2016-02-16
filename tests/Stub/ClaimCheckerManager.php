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
    public function __construct()
    {
        parent::__construct();
        $this->addClaimChecker(new IssuerChecker());
        $this->addClaimChecker(new SubjectChecker());
        $this->addClaimChecker(new AudienceChecker('My Service'));
    }
}
