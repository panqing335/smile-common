<?php


namespace Smile\Common\GraphQL\Factory;

use GraphQL\Type\Definition\ListOfType;
use GraphQL\Type\Definition\NonNull;
use GraphQL\Type\Definition\Type;
use Hyperf\Contract\ContainerInterface;
use Hyperf\Di\Annotation\Inject;
use Smile\Common\GraphQL\Definition\CommonType\TMutationResult;
use Smile\Common\GraphQL\Definition\CommonType\TPaginator;
use Smile\Common\GraphQL\Definition\ObjectType;
use Smile\Common\GraphQL\Definition\PriceType;

class GraphTypeFactory
{
    /**
     * @Inject()
     * @var ContainerInterface
     */
    protected ContainerInterface $container;

    public function __construct()
    {
    }

    public function get(string $class, string $name = '', array $params = [])
    {
        $paramsHash = count($params) > 0 ? md5(json_encode($params)) : '';
        $key = "__GRAPH_{$class}_{$name}_{$paramsHash}";
        if ($this->container->has($key)) {
            return $this->container->get($key);
        }

        $typeInstance = $this->container->make($class, [$params, $this]);
        $this->container->set($key, $typeInstance);
        return $typeInstance;
    }

    public function input(string $class, string $name = '')
    {
        /** @var ObjectType $type */
        $type = $this->get($class, $name);

        $key = "__GRAPH_{$class}_{$name}_input";
        if ($this->container->has($key)) {
            return $this->container->get($key);
        }

        $inputType = $type->buildInput($name);
        $this->container->set($key, $inputType);
        return $inputType;
    }

    public function boolean()
    {
        return Type::boolean();
    }

    public function float()
    {
        return Type::float();
    }

    public function id()
    {
        return Type::id();
    }

    public function paginator(string $className, string $description = '', array $args = [])
    {
        /** @var ObjectType $type */
        $type = $this->get($className);
        $paginationName = $type->typeName . 'Pagination';

        return $this->fast(
            $this->get(TPaginator::class, $paginationName, [
                'name' => $paginationName,
                'fields' => [
                    'items' => $this->listOf($type),
                ],
            ]), $description, null, array_merge([
                'page' => $this->fastInt('页码'),
                'pageSize' => $this->fastNullableInt('每页数量', 20),
            ], $args)
        );
    }

    /**
     * 变更返回类型
     * @return TMutationResult
     */
    public function result(): TMutationResult
    {
        return $this->get(TMutationResult::class);
    }

    /**
     * 带额外字段的返回类型
     * @param array $fields
     * @param string $name
     * @return TMutationResult
     */
    public function resultWithFields(string $name, array $fields)
    {
        $typeName = $name . 'Result';
        return $this->get(TMutationResult::class, $typeName, [
            'name' => $typeName,
            'fields' => $fields,
        ]);
    }

    public function int()
    {
        return Type::int();
    }

    public function string()
    {
        return Type::string();
    }

    public function nonNull($type)
    {
        if (gettype($type) == 'string') {
            return $this->nonNull($this->get($type));
        }

        return new NonNull($type);
    }

    public function nonNullInt()
    {
        return $this->nonNull($this->int());
    }

    public function nonNullString()
    {
        return $this->nonNull($this->string());
    }

    public function price()
    {
        return $this->get(PriceType::class);
    }

    public function fastPrice(string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fast($this->price(), $description, $defaultValue, $args);
    }

    public function fastNullablePrice(string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fastNullable($this->price(), $description, $defaultValue, $args);
    }

    /**
     * 快速定义类型
     * @param mixed $type
     * @param string $description
     * @param mixed $defaultValue
     * @param array $args
     * @return array
     */
    public function fastNullable($type, string $description = '', $defaultValue = null, $args = [])
    {
        if (gettype($type) == 'string') {
            $type = $this->get($type);
        }

        $type = [
            'type' => $type,
            'desc' => $description,
            'args' => $args,
        ];

        if ($defaultValue !== null) {
            $type['defaultValue'] = $defaultValue;
        }

        return $type;
    }

    /**
     * 快速定义非空类型
     * @param mixed $type
     * @param string $description
     * @param mixed $defaultValue
     * @param array $args
     * @return array
     */
    public function fast($type, string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fastNullable(
            $this->nonNull($type), $description, $defaultValue, $args
        );
    }

    public function fastNullableString(string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fastNullable($this->string(), $description, $defaultValue, $args);
    }

    public function fastNullableInt(string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fastNullable($this->int(), $description, $defaultValue, $args);
    }

    public function fastNullableId(string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fastNullable($this->id(), $description, $defaultValue, $args);
    }

    public function fastNullableBoolean(string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fastNullable($this->boolean(), $description, $defaultValue, $args);
    }

    public function fastNullableFloat(string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fastNullable($this->float(), $description, $defaultValue, $args);
    }

    public function fastString(string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fast($this->string(), $description, $defaultValue, $args);
    }

    public function fastInt(string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fast($this->int(), $description, $defaultValue, $args);
    }

    public function fastId(string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fast($this->id(), $description, $defaultValue, $args);
    }

    public function fastBoolean(string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fast($this->boolean(), $description, $defaultValue, $args);
    }

    public function fastFloat(string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fast($this->float(), $description, $defaultValue, $args);
    }

    public function fastResult(string $description = '', $args = [])
    {
        return $this->fast(
            $this->result(), $description, null, $args
        );
    }

    public function fastResultWithFields(string $name, string $description, array $args = [], array $fields = [])
    {
        return $this->fast(
            $this->resultWithFields($name, $fields), $description, null, $args
        );
    }

    public function listOf($type)
    {
        if (gettype($type) == 'string') {
            return $this->listOf($this->get($type));
        }

        return new ListOfType($type);
    }

    public function fastListOf($type, string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fast($this->listOf($type), $description, $defaultValue, $args);
    }

    public function fastNullableListOf($type, string $description = '', $defaultValue = null, $args = [])
    {
        return $this->fastNullable($this->listOf($type), $description, $defaultValue, $args);
    }

    public function enumValue($value, $description = '')
    {
        return [
            'value' => $value,
            'description' => $description,
        ];
    }
}
