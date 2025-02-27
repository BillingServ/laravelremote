<?php

namespace Collective\Remote;

use phpseclib\Net\SSH2;
use phpseclib\Crypt\RSA;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use phpseclib\System\SSH\Agent;
use Illuminate\Filesystem\Filesystem;

class SecLibGateway implements GatewayInterface
{
    /**
     * The host name of the server.
     *
     * @var string
     */
    protected $host;

    /**
     * The SSH port on the server.
     *
     * @var int
     */
    protected $port = 22;

    /**
     * The timeout for commands.
     *
     * @var int
     */
    protected $timeout = 10;

    /**
     * The authentication credential set.
     *
     * @var array
     */
    protected $auth;

    /**
     * The filesystem instance.
     *
     * @var \Illuminate\Filesystem\Filesystem
     */
    protected $files;

    /**
     * The SecLib connection instance.
     *
     * @var \phpseclib\Net\SSH2
     */
    protected $connection;

    /**
     * Create a new gateway implementation.
     *
     * @param string                            $host
     * @param array                             $auth
     * @param \Illuminate\Filesystem\Filesystem $files
     * @param                                   $timeout
     */
    public function __construct($host, array $auth, Filesystem $files, $timeout)
    {
        $this->auth = $auth;
        $this->files = $files;
        $this->setTimeout($timeout);
        $this->setHostAndPort($host);
    }

    /**
     * Set the host and port from a full host string.
     *
     * @param string $host
     *
     * @return void
     */
    protected function setHostAndPort($host)
    {
        $host = Str::replaceFirst('[', '', $host);
        $host = Str::replaceLast(']', '', $host);

        $this->host = $host;

        if (!filter_var($host, FILTER_VALIDATE_IP) && Str::contains($host, ':')) {
            $this->host = Str::beforeLast($host, ':');
            $this->port = (int) Str::afterLast($host, ':');
        }

        if (filter_var($this->host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $this->host = '[' . $this->host . ']';
        }
    }

    /**
     * Connect to the SSH server.
     *
     * @param string $username
     *
     * @return bool
     */
    public function connect($username)
    {
        return $this->getConnection()->login($username, $this->getAuthForLogin());
    }

    /**
     * Get the underlying SSH2 connection.
     *
     * @return \phpseclib\Net\SSH2
     */
    public function getConnection()
    {
        if ($this->connection) {
            return $this->connection;
        }

        return $this->connection = new SSH2($this->host, $this->port, $this->timeout);
    }

    /**
     * Get the authentication object for login.
     *
     * @throws \InvalidArgumentException
     *
     * @return \Crypt_RSA|\System_SSH_Agent|string
     */
    protected function getAuthForLogin()
    {
        if ($this->useAgent()) {
            return $this->getAgent();
        } elseif ($this->hasRsaKey()) {
            return $this->loadRsaKey($this->auth);
        } elseif (isset($this->auth['password'])) {
            return $this->auth['password'];
        }

        throw new \InvalidArgumentException('Password / key is required.');
    }

    /**
     * Determine if the SSH Agent should provide an RSA key.
     *
     * @return bool
     */
    protected function useAgent()
    {
        return isset($this->auth['agent']) && $this->auth['agent'] === true;
    }

    /**
     * Get a new SSH Agent instance.
     *
     * @return \phpseclib\System\SSH\Agent
     */
    public function getAgent()
    {
        return new Agent();
    }

    /**
     * Determine if an RSA key is configured.
     *
     * @return bool
     */
    protected function hasRsaKey()
    {
        $hasKey = (isset($this->auth['key']) && trim($this->auth['key']) != '');
        return $hasKey || (isset($this->auth['keytext']) && trim($this->auth['keytext']) != '');
    }

    /**
     * Load the RSA key instance.
     *
     * @param array $auth
     *
     * @return \Crypt_RSA
     */
    protected function loadRsaKey(array $auth)
    {
        with($key = $this->getKey($auth))->loadKey($this->readRsaKey($auth));

        return $key;
    }

    /**
     * Create a new RSA key instance.
     *
     * @param array $auth
     *
     * @return \Crypt_RSA
     */
    protected function getKey(array $auth)
    {
        with($key = $this->getNewKey())->setPassword(Arr::get($auth, 'keyphrase'));

        return $key;
    }

    /**
     * Get a new RSA key instance.
     *
     * @return \phpseclib\Crypt\RSA
     */
    public function getNewKey()
    {
        return new RSA();
    }

    /**
     * Read the contents of the RSA key.
     *
     * @param array $auth
     *
     * @return string
     */
    protected function readRsaKey(array $auth)
    {
        if (isset($auth['key'])) {
            return $this->files->get($auth['key']);
        }

        return $auth['keytext'];
    }

    /**
     * Get timeout.
     *
     * @return int
     */
    public function getTimeout()
    {
        return $this->timeout;
    }

    /**
     * Set timeout.
     *
     * Setting $timeout to false or 0 will mean there is no timeout.
     *
     * @param int $timeout
     */
    public function setTimeout($timeout)
    {
        $this->timeout = (int) $timeout;

        if ($this->connection) {
            $this->connection->setTimeout($this->timeout);
        }
    }

    /**
     * Determine if the gateway is connected.
     *
     * @return bool
     */
    public function connected()
    {
        return $this->getConnection()->isConnected();
    }

    /**
     * Run a command against the server (non-blocking).
     *
     * @param string $command
     *
     * @return void
     */
    public function run($command)
    {
        $this->getConnection()->exec($command, false);
    }

    /**
     * Get the next line of output from the server.
     *
     * @return string|null
     */
    public function nextLine()
    {
        $value = $this->getConnection()->_get_channel_packet(SSH2::CHANNEL_EXEC);

        return $value === true ? null : $value;
    }

    /**
     * Get the exit status of the last command.
     *
     * @return int|bool
     */
    public function status()
    {
        return $this->getConnection()->getExitStatus();
    }

    /**
     * Get the host used by the gateway.
     *
     * @return string
     */
    public function getHost()
    {
        return $this->host;
    }

    /**
     * Get the port used by the gateway.
     *
     * @return int
     */
    public function getPort()
    {
        return $this->port;
    }
}
