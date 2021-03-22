<?php


namespace Smile\Common\GraphQL\Definition\CommonType;

use Smile\Common\GraphQL\Definition\ObjectType;
use Smile\Common\GraphQL\Entity\GraphTypeAttrs;
use Smile\Common\GraphQL\Factory\GraphTypeFactory;

class TMutationResult extends ObjectType
{

    /**
     * @param GraphTypeAttrs $attrs
     */
    public function init(GraphTypeAttrs &$attrs): void
    {
        $attrs->name = 'TMutationResult';
        $attrs->desc = '公用返回类型';
    }

    public function fields(GraphTypeFactory $types): array
    {
        return [
            'message' => $types->fast($types->string()),
        ];
    }

    public function resolveMessage($val, array $args)
    {
        return "操作成功";
    }
}