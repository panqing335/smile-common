<?php

use App\Graph\Mutation\MRoot;
use App\Graph\Query\QRoot;
use App\Constants\ErrorCode;

return [
    'error_code_class' => ErrorCode::class,
    'success_code' => 0,
    'system_error_code' => 500,
    'graph' => [
        'query_root_class' => QRoot::class,
        'mutation_root_class' => MRoot::class,
    ],
    'redis_model_pool' => 'model'
];
