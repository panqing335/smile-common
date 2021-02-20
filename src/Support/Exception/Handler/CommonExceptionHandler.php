<?php


namespace Smile\Common\Support\Exception\Handler;


use Hyperf\ExceptionHandler\ExceptionHandler;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\HttpServer\Response;
use Hyperf\Utils\ApplicationContext;
use Hyperf\Validation\ValidationException;
use Psr\Http\Message\ResponseInterface;
use Smile\Common\Support\Entity\Result;
use Smile\Common\Support\Exception\BusinessException;
use Smile\Common\Support\Exception\UnauthorizedException;
use Smile\Common\Support\Middleware\CsrfMiddleware;
use Smile\Common\Support\Util\Logger;
use Smile\Common\Support\Util\SessionUtil;
use Throwable;

class CommonExceptionHandler extends ExceptionHandler
{
    /**
     * @inheritDoc
     */
    public function handle(Throwable $throwable, ResponseInterface $response)
    {
        $hyperfResponse = CsrfMiddleware::addCsrfHeaders(new Response($response));
        $userId = SessionUtil::getUserId(true);

        $logData = [
            'exception' => get_class($throwable),
            'errorCode' => $throwable->getCode(),
            'trace' => $throwable->getTraceAsString(),
            'file' => $throwable->getFile(),
            'line' => $throwable->getLine(),
            'userId' => $userId,
        ];

        if ($throwable instanceof UnauthorizedException) {
            $this->stopPropagation();
            Logger::get()->warning($throwable->getMessage(), $logData);

            return $hyperfResponse->withStatus(401)->json(
                Result::error(
                    $throwable->getCode(),
                    $throwable->getMessage()
                )
            );
        } elseif ($throwable instanceof ValidationException) {
            $this->stopPropagation();
            Logger::get()->warning($throwable->getMessage(), $logData);

            $errorBody = $throwable->validator->errors()->first();
            return $hyperfResponse->withStatus(400)->json(
                Result::error(
                    400,
                    $errorBody
                )
            );
        } elseif ($throwable instanceof BusinessException) {
            $this->stopPropagation();
            Logger::get()->warning($throwable->getMessage(), $logData);

            return $hyperfResponse->withStatus(422)->json(
                Result::error(
                    $throwable->getCode(),
                    $throwable->getMessage()
                )
            );
        }

        /** @var RequestInterface $request */
        $request = ApplicationContext::getContainer()->get(RequestInterface::class);
        Logger::get()->error($throwable->getMessage(), $logData);
        return $hyperfResponse->withStatus(500)->json(
            Result::error(
                500,
                '系统错误，请稍后再试',
                $request->has('debug') ?
                    [
                        'error' => $throwable->getMessage(),
                    ] :
                    null
            )
        );
    }

    /**
     * @inheritDoc
     */
    public function isValid(Throwable $throwable): bool
    {
        return true;
    }
}