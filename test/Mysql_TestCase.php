<?php

include dirname(__DIR__) . '/vendor/autoload.php';

class Mysql_TestCase extends PHPUnit_Framework_TestCase {

    /** @var \Objectiveweb\Auth */
    public static $auth;

    public static function setUpBeforeClass()
    {
        $pdo = new PDO('mysql:dbname=objectiveweb;host=localhost', 'root', '');
        #$pdo = new PDO('mysql:dbname=objectiveweb;host=mysql', 'root', 'root');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec('drop table if exists ow_credentials');
        $pdo->exec('drop table if exists ow_user');
        $pdo->query('create table ow_user
            (`id` INT UNSIGNED PRIMARY KEY NOT NULL AUTO_INCREMENT,
                `name` VARCHAR(255),
                `image` VARCHAR(255),
                `scopes` VARCHAR(255),
                `created` DATETIME,
                `password` CHAR(60),
                `token` CHAR(32))');

        $pdo->query("create table ow_credentials
            (
                uid varchar(255) not null,
                provider varchar(32) not null,
                user_id int(11) unsigned not null,
                profile text null,
                modified datetime null,
                primary key (uid, provider),
                constraint credentials_ibfk_1
                    foreign key (user_id) references ow_user (id)

            )");

        try {
            self::$auth = new \Objectiveweb\Auth\MysqlAuth($pdo, array(
                'created' => 'created',
                'token' => 'token'
            ));
        } catch(\Throwable $ex) {
            echo $ex->getMessage();
            exit($ex->getTraceAsString());
        }
    }
}
