<?php

namespace Hiraeth\Middleware;

use Hiraeth;

/**
 * {@inheritDoc}
 */
class EncryptCookiesDelegate implements Hiraeth\Delegate
{
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
		$middleware = $app->getConfig('*', 'middleware.class', NULL);
		$collection = array_search(EncryptCookies::class, $middleware);
		$options    = $app->getConfig($collection, 'middleware', [
			'bypass' => []
		]);

		return new EncryptCookies($app->getKey(), $options['bypass']);
	}
}
