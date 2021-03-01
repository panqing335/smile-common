<?php


namespace Smile\Common\Support\Util;


use Hyperf\Contract\ConfigInterface;
use Hyperf\Utils\ApplicationContext;
use Hyperf\Utils\Context;
use Psr\Http\Message\ServerRequestInterface;
use Smile\Common\Support\Entity\SessionPayloadEntity;
use Smile\Common\Support\Exception\UnauthorizedException;
use Smile\Common\Support\Middleware\LoginMiddleware;

class SessionUtil
{
    const VISITOR_ID = 'VISITOR';

    protected static function _getUserId(): string
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

    public static function getUserId(bool $allowVisitor = false)
    {
        $userId = self::_getUserId();
        if (!$allowVisitor && $userId == self::VISITOR_ID) {
            /** @var ConfigInterface $config */
            $config = ApplicationContext::getContainer()->get(ConfigInterface::class);

            throw new UnauthorizedException(
                $config->get('smile.unauthorized_message', '请您登录后再进行操作'),
                $config->get('smile.unauthorized_code', 400)
            );
        }

        return $userId;
    }

    public static function _getProviderId(): int
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

    public static function getProviderId(): int
    {
        $providerId = self::_getProviderId();
        if ($providerId == 0) {
            /** @var ConfigInterface $config */
            $config = ApplicationContext::getContainer()->get(ConfigInterface::class);

            throw new UnauthorizedException(
                $config->get('smile.unauthorized_message', '您还不是服务商'),
                $config->get('smile.unauthorized_code', 400)
            );
        }

        return $providerId;
    }

    public static function _getStaffId(): int
    {
        /** @var ServerRequestInterface $request */
        $request = Context::get(ServerRequestInterface::class);

        if (empty($request)) {
            return 0;
        }

        /** @var SessionPayloadEntity $payload */
        $payload = $request->getAttribute(LoginMiddleware::PAYLOAD_KEY);

        if (empty($payload) || empty($payload->staffId)) {
            return 0;
        }

        return $payload->staffId;
    }

    public static function getStaffId(): int
    {
        $staff = self::_getStaffId();
        if ($staff == 0) {
            /** @var ConfigInterface $config */
            $config = ApplicationContext::getContainer()->get(ConfigInterface::class);

            throw new UnauthorizedException(
                $config->get('smile.unauthorized_message', '您还不是服务商员工'),
                $config->get('smile.unauthorized_code', 400)
            );
        }

        return $staff;
    }

    public static function isVisitor()
    {
        return self::_getUserId() == self::VISITOR_ID;
    }
}