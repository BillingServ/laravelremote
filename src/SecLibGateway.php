<?php

namespace Collective\Remote;

use phpseclib\Net\SSH2;
use phpseclib\Crypt\RSA;
use phpseclib\System\SSH\Agent;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Illuminate\Filesystem\Filesystem;
use InvalidArgumentException;
use RuntimeException;
use BadMethodCallException;

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
     * The SecLib SSH connection instance.
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
     * @param int                               $timeout
     */
    public function __construct($host, array $auth, Filesystem $files, $timeout = 10)
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
     * Get the underlying SSH connection.
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
     * @return \phpseclib\Crypt\RSA|\phpseclib\System\SSH\Agent|string
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

        throw new InvalidArgumentException('Password / key is required.');
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
        return !empty($this->auth['key']) || !empty($this->auth['keytext']);
    }

    /**
     * Load the RSA key instance.
     *
     * @param array $auth
     *
     * @return \phpseclib\Crypt\RSA
     */
    protected function loadRsaKey(array $auth)
    {
        $key = $this->getNewKey();
        $key->loadKey($this->readRsaKey($auth));

        return $key;
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

    /**
     * Implement missing methods from GatewayInterface but disable SFTP.
     */
    
    public function get($remote, $local)
    {
        throw new BadMethodCallException('File download (get) is not supported in SSH mode.');
    }

    public function getString($remote)
    {
        throw new BadMethodCallException('File retrieval (getString) is not supported in SSH mode.');
    }

    public function put($local, $remote)
    {
        throw new BadMethodCallException('File upload (put) is not supported in SSH mode.');
    }

    public function putString($remote, $contents)
    {
        throw new BadMethodCallException('String upload (putString) is not supported in SSH mode.');
    }

    public function exists($remote)
    {
        throw new BadMethodCallException('File existence check (exists) is not supported in SSH mode.');
    }

    public function rename($remote, $newRemote)
    {
        throw new BadMethodCallException('File renaming (rename) is not supported in SSH mode.');
    }

    public function delete($remote)
    {
        throw new BadMethodCallException('File deletion (delete) is not supported in SSH mode.');
    }
}
