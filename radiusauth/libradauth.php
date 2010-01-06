<?php

/*
Copyright (c) 2003, Michael Bretterklieber <michael@bretterklieber.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions 
are met:

1. Redistributions of source code must retain the above copyright 
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright 
   notice, this list of conditions and the following disclaimer in the 
   documentation and/or other materials provided with the distribution.
3. The names of the authors may not be used to endorse or promote products 
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The author of this file respectfully requests that you refrain from
relicensing it under the GPL, although the BSD license permits you to do so.

*/

class RadiusAuth
{
  var $radius;
  
  var $server = 'localhost';
  var $secret = 's3cr35SHH';
  var $port = 1812;
  
  function __construct($server, $secret, $port = 1812)
  {
    $this->radius = radius_auth_open();
    if ( !$this->radius )
    {
      throw new RadiusError("Could not get RADIUS resource");
    }
    
    $this->set_server_params($server, $secret, $port);
    $this->create_request();
  }
  
  function set_server_params($server, $secret, $port = 1812)
  {
    $this->server = $server;
    $this->secret = $secret;
    $this->port = $port;
  }
  
  function create_request()
  {
    if ( !radius_add_server($this->radius, $this->server, $this->port, $this->secret, 3, 3) )
      throw new RadiusError(radius_strerror($this->radius));
    
    if ( !radius_create_request($this->radius, RADIUS_ACCESS_REQUEST) )
      throw new RadiusError(radius_strerror($this->radius));
    
    if (!radius_put_string($this->radius, RADIUS_NAS_IDENTIFIER, isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost'))
      throw new RadiusError(radius_strerror($this->radius));
    
    /*
    if (!radius_put_int($this->radius, RADIUS_SERVICE_TYPE, RADIUS_FRAMED))
      throw new RadiusError(radius_strerror($this->radius));
      
    if (!radius_put_int($this->radius, RADIUS_FRAMED_PROTOCOL, RADIUS_PPP))
      throw new RadiusError(radius_strerror($this->radius));
    */
    
    if (!radius_put_string($this->radius, RADIUS_CALLING_STATION_ID, isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1'))
      throw new RadiusError(radius_strerror($this->radius));
  }
  
  function authenticate($username, $password, $method = 'pap')
  {
    //
    // Send the username
    //
    
    if ( !radius_put_string($this->radius, RADIUS_USER_NAME, $username) )
      throw new RadiusError("RADIUS_USER_NAME: " . radius_strerror($this->radius));
    
    //
    // Send the password, or complete the challenge process
    //
    
    switch ( $method )
    {
      case 'chap':
        
        //
        // CHAP
        //
        
        /* generate Challenge */
        mt_srand(time() * mt_rand());
        $chall = mt_rand();
    
        // FYI: CHAP = md5(ident + plaintextpass + challenge)
        $chapval = pack('H*', md5(pack('Ca*', 1, $password . $chall)));
        // Radius wants the CHAP Ident in the first byte of the CHAP-Password
        $pass_chap = pack('C', 1) . $chapval;
    
        if (!radius_put_attr($this->radius, RADIUS_CHAP_PASSWORD, $pass_chap))
          throw new RadiusError(radius_strerror($this->radius));
    
        if (!radius_put_attr($this->radius, RADIUS_CHAP_CHALLENGE, $chall))
          throw new RadiusError(radius_strerror($this->radius));
        
        break;
        
      case 'mschap':
        
        //
        // MS-CHAP v1
        //
        
        require_once(ENANO_ROOT . '/plugins/radiusauth/libradauth.php');

        $challenge = GenerateChallenge();
        
        if (!radius_put_vendor_attr($this->radius, RADIUS_VENDOR_MICROSOFT, RADIUS_MICROSOFT_MS_CHAP_CHALLENGE, $challenge))
          throw new RadiusError(radius_strerror($this->radius));
        
        $ntresp = ChallengeResponse($challenge, NtPasswordHash($password));
        $lmresp = str_repeat ("\0", 24);
        
        // Response: chapid, flags (1 = use NT Response), LM Response, NT Response
        $resp = pack('CCa48',1 , 1, $lmresp . $ntresp);
        
        if ( !radius_put_vendor_attr($this->radius, RADIUS_VENDOR_MICROSOFT, RADIUS_MICROSOFT_MS_CHAP_RESPONSE, $resp))
          throw new RadiusError(radius_strerror($this->radius));
        
        break;
        
      case 'mschapv2':
        
        //
        // MS-CHAP v2
        //
        
        require_once(ENANO_ROOT . '/plugins/radiusauth/libradauth.php');

        $authChallenge = GenerateChallenge(16);
        
        if (!radius_put_vendor_attr($this->radius, RADIUS_VENDOR_MICROSOFT, RADIUS_MICROSOFT_MS_CHAP_CHALLENGE, $authChallenge))
          throw new RadiusError(radius_strerror($this->radius));
    
        // we have no client, therefore we generate the Peer-Challenge
        $peerChallenge = GeneratePeerChallenge();
    
        $ntresp = GenerateNTResponse($authChallenge, $peerChallenge, $username, $password);
        $reserved = str_repeat ("\0", 8);
    
        // Response: chapid, flags (1 = use NT Response), Peer challenge, reserved, Response
        $resp = pack('CCa16a8a24',1 , 1, $peerChallenge, $reserved, $ntresp);
    
        if (!radius_put_vendor_attr($this->radius, RADIUS_VENDOR_MICROSOFT, RADIUS_MICROSOFT_MS_CHAP2_RESPONSE, $resp))
          throw new RadiusError(radius_strerror($this->radius));
        
        break;
        
      case 'pap':
      default:
        
        //
        // PAP
        //
        
        if ( !radius_put_string($this->radius, RADIUS_USER_PASSWORD, $password) )
          throw new RadiusError("RADIUS_USER_PASSWORD: " . radius_strerror($this->radius));
        
        break;
    }
    
    $req = radius_send_request($this->radius);
    if ( !$req )
      throw new RadiusError(radius_strerror($this->radius));
    
    switch($req)
    {
      case RADIUS_ACCESS_ACCEPT:
        return true;
      
      case RADIUS_ACCESS_REJECT:
        return false;
      
      default:
        echo "Unexpected return value:$req\n<br>";
        return false;
    }
  }
  
  function get_attrs()
  {
    $attrs = array();
    while ($resa = radius_get_attr($this->radius))
    {
      $attrs[ $resa['attr'] ] = $resa['data'];
    }
    
    return $attrs;
  }
  
  function get_authenticator()
  {
    if ( $authent = radius_request_authenticator($this->radius) )
      return $authent;
    
    throw new RadiusError(radius_strerror($this->radius));
  }
  
  function close()
  {
    radius_close($this->radius);
  }
}

class RadiusError extends Exception
{
  
}
