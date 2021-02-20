<?php


namespace Smile\Common\Support\Log;


use Smile\Common\Support\Util\SessionUtil;

class JsonFormatter extends \Monolog\Formatter\JsonFormatter
{
    public function format(array $record): string
    {
        $record['userId'] = SessionUtil::getUserId(true);
        return parent::format($record);
    }
}
