<?php

namespace Config;

use App\Libraries\Catalogue;
use App\Models\ItemModel;
use CodeIgniter\Config\BaseService;

/**
 * The fixture's application services: CodeIgniter finds this class by name and calls it through
 * service('catalogue'), so a protected service locator is exercised, not just a protected class.
 */
class Services extends BaseService
{
    public static function catalogue(bool $getShared = true): Catalogue
    {
        if ($getShared) {
            return static::getSharedInstance('catalogue');
        }

        return new Catalogue(model(ItemModel::class));
    }
}
