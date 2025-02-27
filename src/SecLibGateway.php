<?php

namespace Collective\Remote;

use phpseclib\Net\SSH2;
use BadMethodCallException;
use RuntimeException;

class SecLibGateway implements GatewayInterface
{
    /**
     * The SSH connection instance.
     *
     * @var SSH2
     */
    protected $connection;

    /**
     * The SSH host.
     *
     * @var string
     */
    protected $host;

    /**
     * The SSH port.
     *
     * @var int
     */
    protected $port;

    /**
     * The SSH username.
     *
     * @var string
     */
    protected $username;

    /**
     * The SSH password.
     *
     * @var string|null
     */
    protected $password;

    /**
     * Create a new SSH gateway instance.
     *
     * @param  string  $host
     * @param  string  $username
     * @param  string|null  $password
     * @param  int  $port
     */
    public function __construct($host, $username, $password = null, $port = 22)
    {
        $this->host = $host;
        $this->port = $port;
        $this->username = $username;
        $this->password = $password;

        $this->connect();
    }

    /**
     * Establish an SSH connection.
     *
     * @return void
     * @throws RuntimeException
     */
    public function connect()
    {
        $this->connection = new SSH2($this->host, $this->port);

        if (!$this->connection->login($this->username, $this->password)) {
            throw new RuntimeException("SSH login failed for {$this->username}@{$this->host}");
        }
    }

    /**
     * Run a command on the remote server.
     *
     * @param  string  $command
     * @return string
     */
    public function run($command)
    {
        return $this->connection->exec($command);
    }

    /**
     * Upload a local file to the remote server.
     *
     * @param  string  $local
     * @param  string  $remote
     * @return bool
     */
    public function put($local, $remote)
    {
        // ❌ If you don't need file uploads, keep this:
        throw new BadMethodCallException('File upload (put) is not supported in SSH mode.');

        // ✅ If you want to enable file uploads over SCP, replace the above with:
        /*
        $scpCommand = "scp -P {$this->port} {$local} {$this->username}@{$this->host}:{$remote}";
        return $this->run($scpCommand);
        */
    }

    /**
     * Close the SSH connection.
     *
     * @return void
     */
    public function disconnect()
    {
        $this->connection = null;
    }
}
