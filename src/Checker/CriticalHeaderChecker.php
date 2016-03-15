<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Checker;

class CriticalHeaderChecker implements HeaderCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkHeader(array $protected_headers, array $headers, array $checked_claims)
    {
        if (!array_key_exists('crit', $protected_headers)) {
            return;
        }

        if (!is_array($protected_headers['crit'])) {
            throw new \InvalidArgumentException('The parameter "crit" must be a list.');
        }

        $diff = array_diff($protected_headers['crit'], $checked_claims);
        if (!empty($diff)) {
            throw new \InvalidArgumentException(sprintf('One or more claims are marked as critical, but they are missing or have not been checked (%s).', json_encode(array_values($diff))));
        }
    }
}
