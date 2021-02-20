<?php


namespace Smile\Common\Support\Parent;


use Carbon\Carbon;
use Hyperf\Database\Model\Concerns\CamelCase;
use Hyperf\Database\Model\SoftDeletes;
use Hyperf\DbConnection\Model\Model;
use Hyperf\ModelCache\Cacheable;
use Hyperf\ModelCache\CacheableInterface;

/**
 * Class BaseModel
 * @package Smile\Common\Support\Parent
 * @property Carbon $createdTime
 * @property Carbon $updatedTime
 * @property Carbon $deletedTime
 */
class BaseModel extends Model implements CacheableInterface
{
    use Cacheable, CamelCase, SoftDeletes;

    const CREATED_AT = 'created_at';
    const UPDATED_AT = 'updated_at';
    const DELETED_AT = 'deleted_at';

    public function setPrimaryKey($key)
    {
        $this->primaryKey = $key;
    }
}
