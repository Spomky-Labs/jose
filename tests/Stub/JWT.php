<?php

namespace SpomkyLabs\JOSE\Tests\Stub;

use SpomkyLabs\JOSE\JWT as Base;

/**
 * Class representing a JSON Web Signature.
 */
class JWT extends Base
{
	private $header;
	private $payload;

	public function getHeader()
	{
		return $this->header;
	}

	public function getPayload()
	{
		return $this->payload;
	}

	public function setHeader(array $header)
	{
		$this->header = $header;
		return $this;
	}

	public function setPayload(array $payload)
	{
		$this->payload = $payload;
		return $this;
	}
}
