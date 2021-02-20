<?php


namespace Smile\Common\Support\Aspect;


use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Annotation\Aspect;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Hyperf\Di\Exception\Exception;
use Smile\Common\Support\Annotation\CalledLog;
use Smile\Common\Support\Annotation\ShouldLogin;
use Smile\Common\Support\Exception\UnauthorizedException;
use Smile\Common\Support\Util\SessionUtil;

/**
 * Class CalledLogAspect
 * @package Smile\Common\Support\Aspect
 * @Aspect()
 */
class ShouldLoginAspect extends AbstractAspect
{
    /**
     * @Inject()
     * @var ConfigInterface
     */
    protected ConfigInterface $config;

    public $annotations = [
        ShouldLogin::class
    ];

    /**
     * @inheritDoc
     * @throws Exception
     */
    public function process(ProceedingJoinPoint $point)
    {
        if (SessionUtil::isVisitor()) {
            throw new UnauthorizedException(
                $this->config->get('smile.unauthorized_message', '请您登录后再进行操作'),
                $this->config->get('smile.unauthorized_code', 400)
            );
        }

        return $point->process();
    }
}