<?php

namespace Hiraeth\Middleware;

use Hiraeth;

use Psr\Http\Server\MiddlewareInterface as Middleware;
use Psr\Http\Server\RequestHandlerInterface as Handler;

use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;

use Defuse\Crypto;
use Dflydev\FigCookies;

/**
 * {@inheritDoc}
 */
class EncryptCookies implements Middleware
{
	/**
	 * A list of cookie names not to encrypt/decrypt
	 *
	 * @var array
	 */
	protected $bypass = array();


	/**
	 * The key with which to encrypt cookies
	 *
	 * @var Crypto\Key|null
	 */
	protected $key = NULL;


	/**
	 * Create a new instance of the middleware
	 */
	public function __construct(Crypto\Key $key, array $bypass = array())
	{
		$this->key    = $key;
		$this->bypass = $bypass;
	}


	/**
	 * Encrypt a SetCookie
	 */
	public function encrypt(FigCookies\SetCookie $set_cookie): FigCookies\SetCookie
	{
		return $set_cookie->withValue(Crypto\Crypto::encrypt($set_cookie->getValue(), $this->key));
	}


	/**
	 * Decrypt a Cookie
	 */
	public function decrypt(FigCookies\Cookie $cookie): FigCookies\Cookie
	{
		try {
			return $cookie->withValue(Crypto\Crypto::decrypt($cookie->getValue(), $this->key));
		} catch (\Exception $e) {
			return $cookie->withValue('');
		}
	}


	/**
	 * {@inheritDoc}
	 */
	public function process(Request $request, Handler $handler): Response
	{
		foreach (FigCookies\Cookies::fromRequest($request) as $cookie) {
			if (!in_array($cookie->getName(), $this->bypass)) {
				$request = FigCookies\FigRequestCookies::modify(
					$request,
					$cookie->getName(),
					[$this, 'decrypt']
				);
			}
		}

		$response = $handler->handle($request);

		foreach (FigCookies\SetCookies::fromResponse($request) as $set_cookie) {
			if (!in_array($set_cookie->getName(), $this->bypass)) {
				$response = FigCookies\FigResponseCookies::modify(
					$response,
					$set_cookie->getName(),
					[$this, 'encrypt']
				);
			}
		}

		return $response;
	}
}
