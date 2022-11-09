<?php

namespace Hiraeth\Middleware;

use Psr\Http\Server\MiddlewareInterface as Middleware;
use Psr\Http\Server\RequestHandlerInterface as Handler;

use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;

use Defuse\Crypto;
use Dflydev\FigCookies;

use Exception;
use RuntimeException;

/**
 * {@inheritDoc}
 */
class EncryptCookies implements Middleware
{
	/**
	 * A list of cookie names not to encrypt/decrypt
	 *
	 * @var array<int, string>
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
	 *
	 * @param array<int, string> $bypass
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
		} catch (Exception $e) {
			return $cookie->withValue('');
		}
	}


	/**
	 * {@inheritDoc}
	 */
	public function process(Request $request, Handler $handler): Response
	{
		foreach (FigCookies\Cookies::fromRequest($request)->getAll() as $cookie) {
			if (!in_array($cookie->getName(), $this->bypass)) {
				$request = FigCookies\FigRequestCookies::modify(
					$request,
					$cookie->getName(),
					[$this, 'decrypt']
				);
			}
		}

		if (!$request instanceof Request) {
			throw new RuntimeException(sprintf(
				'Modification of cookies on server request resulted in conversion to request'
			));
		}

		$response = $handler->handle($request);

		foreach (FigCookies\SetCookies::fromResponse($response)->getAll() as $set_cookie) {
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
