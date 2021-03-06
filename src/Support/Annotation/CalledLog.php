<?php


namespace Smile\Common\Support\Annotation;

use Doctrine\Common\Annotations\Annotation\Target;
use Hyperf\Di\Annotation\AbstractAnnotation;
use Hyperf\Di\Annotation\AnnotationCollector;
use Hyperf\HttpServer\Annotation\Middleware;
use Smile\Common\Support\Middleware\LoginMiddleware;

/**
 * @Annotation
 * @Target({"METHOD"})
 */
class CalledLog extends AbstractAnnotation
{
    public bool $result = false;
}
