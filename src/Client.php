<?php
namespace attics\Lib\Soap;

class Client
{

    const CACHE_PREFIX = 'attics_soap_wsdl_cache_';

    const SOAP_CACHE_TTL = 31104000;

    const SOAP_CACHE_LIMIT = 100;

    private $wsdl_url;

    private $cache;

    private $http_options = [
        'maxredirects'  => 0,
        'timeout'       => 5,
        'sslcert'       => false,
        'sslpassphrase' => false
    ];

    private $soap_options = [
        'cache_wsdl' => WSDL_CACHE_NONE
    ];

    private $ssl_options = [
        'verify_peer'      => true,
        'verify_peer_name' => true,
    ];

    public function __construct($wsdl_url, $accept_compression = true)
    {
        if (!filter_var($wsdl_url, FILTER_VALIDATE_URL)) {
            throw new \Exception("Bad wsdl url");
        }

        $this->wsdl_url = $wsdl_url;

        if ($accept_compression) {
            $this->soap_options['compression'] = SOAP_COMPRESSION_ACCEPT;
        }
    }

    public function verifyPeer($verify = true)
    {
        $verify = boolval($verify);
        $this->ssl_options['verify_peer'] = $verify;
        $this->ssl_options['verify_peer_name'] = $verify;
    }

    public function setVersion($ver)
    {
        switch ((int)$ver) {
            case 1:
                $this->soap_options['soap_version'] = SOAP_1_1;
                break;
            case 2:
                $this->soap_options['soap_version'] = SOAP_1_2;
                break;
        }
    }

    public function setAgent($agent)
    {
        $this->soap_options['user_agent'] = $agent;

        return $this;
    }

    public function auth($login, $password)
    {
        if (empty($login)) {
            throw new \Exception("Empty login passed to auth method");
        }

        if (empty($password)) {
            throw new \Exception("Empty password passed to auth method");
        }

        $this->soap_options['login'] = $login;
        $this->soap_options['password'] = $password;

        $this->http_options['header'] = "Authorization: Basic " . base64_encode($login . ':' . $password);

        return $this;
    }

    public function setCache($cache)
    {
        $cache = (int)$cache;
        if (!$cache) {
            $this->soap_options['cache_wsdl'] = WSDL_CACHE_NONE;
        } else {
            $this->soap_options['cache_wsdl'] = $cache;
        }

        $this->cache = $cache;

        return $this;
    }

    public function setCertificate($path, $passphrase, $verifyPeer = null)
    {
        if (empty($path) || !is_readable($path)) {
            throw new \Exception("Certificate is not readable");
        }

        $this->ssl_options['local_cert'] = $path;

        if (!empty($passphrase)) {
            $this->ssl_options['passphrase'] = $passphrase;
        }

        if (!is_null($verifyPeer)) {
            $this->verifyPeer($verifyPeer);
        }

        return $this;
    }

    public function getHandler()
    {
        if ($this->cache) {
            ini_set("soap.wsdl_cache_enabled", 1);
            ini_set("soap.wsdl_cache", $this->cache);
            ini_set("soap.wsdl_cache_ttl", self::SOAP_CACHE_TTL);
            ini_set("soap.wsdl_cache_limit", self::SOAP_CACHE_LIMIT);
        } else {
            ini_set('soap.wsdl_cache_enabled', 0);
            ini_set('soap.wsdl_cache_ttl', 0);
            ini_set("soap.wsdl_cache_ttl", 0);
            ini_set("soap.wsdl_cache_limit", 0);
        }

        $wsdl_cache_path = sys_get_temp_dir() . '/' . self::CACHE_PREFIX . parse_url($this->wsdl_url,
                PHP_URL_HOST) . '-' . md5($this->wsdl_url);

        $stream_context = stream_context_create([
            'http' => $this->http_options,
            'ssl'  => $this->ssl_options
        ]);

        // Configuring http client to get wsdl via ssl with certificate
        if ($this->cache && file_exists($wsdl_cache_path)) {
            $wsdl = file_get_contents($wsdl_cache_path);
        } else {
            $wsdl = file_get_contents($this->wsdl_url, false, $stream_context);
        }

        if (empty($wsdl)) {
            throw new \Exception("Cannot get wsdl");
        }

        if (!@file_put_contents($wsdl_cache_path, $wsdl, LOCK_EX)) {
            throw new \Exception("Cannot save wsdl to cache: " . $wsdl_cache_path . " is not writable");
        }

        $this->soap_options['stream_context'] = $stream_context;

        $SoapClient = new \Zend\Soap\Client($wsdl_cache_path, $this->soap_options);

        return $SoapClient;
    }
}