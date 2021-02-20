<?php


namespace Smile\Common\Support\Middleware;


use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Utils\Context;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Smile\Common\Support\Entity\SessionPayloadEntity;
use Smile\Common\Support\Exception\UnauthorizedException;
use Smile\Common\Support\Util\SessionUtil;

class LoginMiddleware implements MiddlewareInterface
{
    const PAYLOAD_KEY = '';

    /**
     * @Inject()
     * @var ConfigInterface
     */
    protected ConfigInterface $config;

    /**
     * @inheritDoc
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $userId = $request->getHeader('X-User-Id')[0] ?? '';
        $providerId = $request->getHeader('X-Provider-Id')[0] ?? '';
        $params = $request->getQueryParams();

        if (array_key_exists('debugUser', $params) && env('APP_ENV') != 'production') {
            $userId = $params['debugUser'];
            $providerId = $params['debugProviderId'];
        }

        if (empty($userId)) {
            throw new UnauthorizedException(
                $this->config->get('smile.unauthorized_message', '请您登录后再进行操作'),
                $this->config->get('smile.unauthorized_code', 400)
            );
        }

        if ($request->getHeader('Is-Provider')) {
            if (empty($providerId)) {
                throw new UnauthorizedException(
                    $this->config->get('smile.unauthorized_message', '您还不是服务商'),
                    $this->config->get('smile.unauthorized_code', 400)
                );
            }
        }


        $sessionPayload = new SessionPayloadEntity();
        $sessionPayload->userId = $userId;
        $sessionPayload->providerId = $providerId;

        $request = Context::override(ServerRequestInterface::class, fn() => $request->withAttribute(self::PAYLOAD_KEY, $sessionPayload));

        return $handler->handle($request);
    }
}