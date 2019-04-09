<?php

namespace Hiraeth\Middleware;

use Hiraeth;
use Defuse\Crypto\Key;
use Ellipse\Cookies\EncryptCookiesMiddleware;

/**
 *
 */
class EncryptCookiesDelegate implements Hiraeth\Delegate
{
	/**
	 * Get the class for which the delegate operates.
	 *
	 * @static
	 * @access public
	 * @return string The class for which the delegate operates
	 */
	static public function getClass(): string
	{
		return EncryptCookiesMiddleware::class;
	}


	/**
	 * Get the instance of the class for which the delegate operates.
	 *
	 * @access public
	 * @param Hiraeth\Application $app The application instance for which the delegate operates
	 * @return object The instance of the class for which the delegate operates
	 */
	public function __invoke(Hiraeth\Application $app): object
	{
		$middleware = $app->getConfig('*', 'middleware.class', NULL);
		$collection = array_search(EncryptCookiesMiddleware::class, $middleware);
		$options    = $app->getConfig($collection, 'middleware', [
			'key'    => NULL,
			'bypass' => []
		]);

		return new EncryptCookiesMiddleware(
			$options['key'] ? Key::loadFromAsciiSafeString($options['key']) : Key::createNewRandomKey(),
			$options['bypass']
		);
	}
}
