<?php


namespace Smile\Common\Support\Util;


use Hyperf\Utils\Context;
use Psr\Http\Message\ServerRequestInterface;
use Smile\Common\Support\Entity\SessionPayloadEntity;
use Smile\Common\Support\Middleware\LoginMiddleware;

class SessionUtil
{
    const VISITOR_ID = 'VISITOR';

    public static function getUserId(): string
    {
        /** @var ServerRequestInterface $request */
        $request = Context::get(ServerRequestInterface::class);

        if (empty($request)) {
            return self::VISITOR_ID;
        }

        /** @var SessionPayloadEntity $payload */
        $payload = $request->getAttribute(LoginMiddleware::PAYLOAD_KEY);

        if (empty($payload) || empty($payload->userId)) {
            return self::VISITOR_ID;
        }

        return $payload->userId;
    }

    public static function getProviderId(): int
    {
        /** @var ServerRequestInterface $request */
        $request = Context::get(ServerRequestInterface::class);

        if (empty($request)) {
            return 0;
        }

        /** @var SessionPayloadEntity $payload */
        $payload = $request->getAttribute(LoginMiddleware::PAYLOAD_KEY);

        if (empty($payload) || empty($payload->providerId)) {
            return 0;
        }

        return $payload->providerId;
    }
}