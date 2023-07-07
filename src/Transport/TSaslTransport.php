<?php
/*
#kerberos auth thrift server
#sasl service name:hbase
$socket = new \Thrift\Transport\TSocket('hdp27.com.cn',9090);
$socket->setSendTimeout(10000); // Ten seconds (too long for production, but this is just a demo ;)
$socket->setRecvTimeout(20000); // Twenty seconds
$transport = new TSaslClientTransport($socket,'hbase','GSSAPI','hdp27.com.cn');
$protocol = new \Thrift\Protocol\TBinaryProtocol($transport);
$client = new \Hbase\HbaseClient($protocol);
$transport->open();
$tables = $client->getTableNames();
sort($tables);
foreach ($tables as $name) {
    echo( "  table found: {$name}\n" );
}
$transport->close();


/*
 * @package thrift.transport
 */

namespace Thrift\Transport;

use Thrift\Exception\TException;
use Thrift\Transport\TTransport;
/**
 * @package thrift.transport
 */
class TSaslTransport extends TTransport
{
    const START = 1;
    const OK = 2;
    const BAD = 3;
    const ERROR = 4;
    const COMPLETE = 5;
    /**
     * @var TTransport
     */
    protected $transport_;
    protected $wbuffer_, $rbuffer_;
    protected $service_;
    protected $krb5_gssapi_;
    protected $server_;
    protected $mechanism_;

    public function __construct(TTransport $transport, $service, $mechanism, $server)
    {
        $this->transport_ = $transport;
        $this->wbuffer_ = '';
        $this->service_ = $service??"hbase";
        $this->server_ = $server;
        $this->mechanism_ = $mechanism??"GSSAPI";
        if (!extension_loaded('krb5')) {
            throw new TException("need krb5 extension!");
        }
        if (!extension_loaded('ds')) {
            throw new TException("need ds extension!");
        }
        $this->krb5_gssapi_ = new \GSSAPIContext();
        $credetials = $this->krb5_gssapi_->inquireCredentials();
        if (!is_array($credetials) || !isset($credetials['name'])) {
            throw new TException("you need run kinit:kinit -k -t yourkeytab yourusername");
        }
    }

    /**
     * Whether this transport is open.
     * @return boolean true if open
     */
    public function isOpen()
    {
        return $this->transport_->isOpen();
    }

    /**
     * Open the transport for reading/writing
     */
    public function open()
    {
        if (!$this->isOpen()) {
            $this->transport_->open();
        }
        #gssapi start
        #GSSAPI step 1
        $this->send_sasl_msg(self::START, $this->mechanism_);
        $target = sprintf('%s/%s', $this->service_, $this->server_);
        $ret = $this->krb5_gssapi_->initSecContext($target, null, GSS_C_MUTUAL_FLAG, null, $output_token, $output_flags, $output_times);
        $gss_token_0 = $output_token; #GSS_C_MUTUAL_FLAG for auth
        $this->send_sasl_msg(self::OK, $gss_token_0);
        @list($status, $payload) = $this->recv_sasl_msg();
        $gss_token_1 = $payload;
        #GSSAPI step 2
        $ret = $this->krb5_gssapi_->initSecContext($target, $gss_token_1, NULL, null, $output_token, $output_flags, $output_times);
        $gss_token_2 = $output_token;
        if (!$ret) {
            throw new TException("server return token not sec init!");
        }
        if (strlen($gss_token_2) != 0) {
            #goto step 2
            #pass
            throw new TException("gssapi init error,gss_token_2!");
        }
        #GSSAPI step 3,handshake final
        $this->send_sasl_msg(self::OK, '');
        while (true) {
            @list($status, $payload) = $this->recv_sasl_msg();
            if(self::OK == $status){
                #loop for client/server
                #only once loop
                $ret = $this->krb5_gssapi_->unwrap($payload, $challenge);
                $ret = $this->krb5_gssapi_->wrap($challenge, $gss_out_token, true);
                $this->send_sasl_msg(self::OK, $gss_out_token);
            }elseif (self::COMPLETE == $status) {
                break;
            }else{
                throw new TException(sprintf("Bad SASL negotiation status: %d (%s)", $status, $payload));
            }
        }
        return true;
    }

    /**
     * Close the transport.
     */
    public function close()
    {
        $this->transport_->close();
    }

    /**
     * Read some data into the array.
     *
     * @param int $len How much to read
     * @return string The data that has been read
     */
    
    public function read($len)
    {
        if ($this->rbuffer_&&$this->rbuffer_->count() > 0) {
            $arr=$this->rbuffer_->slice(0,$len);
            for($i=0;$i<$len;$i++){
                $this->rbuffer_->shift();
            }
            return $arr->join("");
        }
        $data = $this->transport_->readAll(4);
        $array = unpack('Nlength', $data);
        $length = $array['length'];
        $data = $this->transport_->readAll($length);
        $this->rbuffer_=new \Ds\Deque(str_split($data));
        $arr=$this->rbuffer_->slice(0,$len);
        for($i=0;$i<$len;$i++){
            $this->rbuffer_->shift();
        }
        return $arr->join("");
    }
    /**
     * Writes the given data out.
     *
     * @param string $buf The data to write
     */
    public function write($buf)
    {
        $this->wbuffer_ .= $buf;
    }

    public function flush()
    {
        $buffer = pack('N', strlen($this->wbuffer_)) . $this->wbuffer_;
        $this->send($buffer);
        $this->wbuffer_ = '';
    }

    public function send($buf)
    {
        $this->transport_->write($buf);
        $this->transport_->flush();
    }

    /**
     * sals send msg for thrift auth only
     * @param $status
     * @param $body
     */
    private function send_sasl_msg($status, $body)
    {
        $buffer = pack('CN', $status, strlen($body)) . $body;
        $this->transport_->write($buffer);
        $this->transport_->flush();
    }

    /**
     *  sasl recv msg for thrif auth only
     * @return array
     */
    private function recv_sasl_msg()
    {
        $data = $this->transport_->readAll(5);
        $arr = unpack('Cstatus/Nlength', $data);
        $length = $arr['length'];
        $status = $arr['status'];
        $payload = $this->transport_->readAll($length);
        return array($status, $payload);
    }
}

