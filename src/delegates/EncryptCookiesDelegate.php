<?php

namespace Hiraeth\Middleware;

use Hiraeth;

/**
 * {@inheritDoc}
 */
class EncryptCookiesDelegate extends AbstractDelegate
{
	/**
	 * {@inheritDoc}
	 */
	protected static $defaultOptions = [
		'bypass' => array()
	];


	/**
	 * {@inheritDoc}
	 */
	static public function getClass(): string
	{
		return EncryptCookies::class;
	}


	/**
	 * {@inheritDoc}
	 */
	public function __invoke(Hiraeth\Application $app): object
	{
		$options = $this->getOptions();

		return new EncryptCookies($app->getKey(), $options['bypass']);
	}
}
