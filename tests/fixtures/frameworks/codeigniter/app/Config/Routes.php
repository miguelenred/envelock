<?php

use CodeIgniter\Router\RouteCollection;

/** @var RouteCollection $routes */
$routes->get('/', 'Home::index');
$routes->get('ping', 'Probe::ping');
$routes->get('items', 'Probe::items');
$routes->post('items', 'Probe::create');
$routes->get('reflect', 'Probe::reflect');
