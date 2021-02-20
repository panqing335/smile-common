<?php


namespace Smile\Common\Support\Middleware;


use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class CsrfMiddleware implements MiddlewareInterface
{
    public static function addCsrfHeaders(ResponseInterface $response): ResponseInterface
    {
        $csrfHeader = 'x-request-id, authorization, Origin, X-Requested-With, Content-Type, Accept';
        return $response
            ->withHeader('Access-Control-Allow-Headers', $csrfHeader);
//            ->withHeader('Access-Control-Allow-Origin', '*');
    }

    /**
     * @inheritDoc
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($request->getMethod() == 'OPTIONS') {
            return self::addCsrfHeaders(
                $handler
                    ->handle($request)
                    ->withStatus(200)
            );
        }

        return self::addCsrfHeaders($handler->handle($request));
    }
}