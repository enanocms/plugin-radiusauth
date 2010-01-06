<?php
/**!info**
{
  "Plugin Name"  : "RADIUS authentication",
  "Plugin URI"   : "http://enanocms.org/plugin/radiusauth",
  "Description"  : "Allows authentication to Enano via a RADIUS server.",
  "Author"       : "Dan Fuhry",
  "Version"      : "1.0",
  "Author URI"   : "http://enanocms.org/",
  "Auth plugin"  : true
}
**!*/

/*
 * RADIUS authentication plugin for Enano
 * (C) 2010 Dan Fuhry
 *
 * This program is Free Software; you can redistribute and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for details.
 *
 * Please note: the back-end RADIUS library files, libradauth.php and libmschap.php, are under the BSD license.
 */

if ( getConfig('radius_enable', 0) == 1 )
{
  $plugins->attachHook('login_process_userdata_json', 'return radius_auth_hook($userinfo, $req["level"], $req["remember"]);');
}

function radius_auth_hook($userinfo, $level, $remember)
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  
  // First try to just authenticate the user in RADIUS
  require_once(ENANO_ROOT . '/plugins/radiusauth/libradauth.php');
  
  $server = getConfig('radius_server', false);
  $port = getConfig('radius_port', 1812);
  $secret = getConfig('radius_secret', '');
  $method = getConfig('radius_method', 'pap');
  if ( empty($server) )
    // bad server? break out and continue the Enano auth chain
    return null;
    
  // We're ready to do a RADIUS auth attempt
  try
  {
    $radius = new RadiusAuth($server, $secret, $port);
    $auth_result = $radius->authenticate($userinfo['username'], $userinfo['password'], $method);
  }
  catch ( RadiusError $e )
  {
    return array(
        'mode' => 'error',
        'error' => "The RADIUS interface returned a technical error."
      );
  }
  
  if ( $auth_result )
  {
    // RADIUS authentication was successful.
    $username = $db->escape(strtolower($userinfo['username']));
    $q = $db->sql_query("SELECT user_id, password FROM " . table_prefix . "users WHERE " . ENANO_SQLFUNC_LOWERCASE . "(username) = '$username';");
    if ( !$q )
      $db->_die();
    if ( $db->numrows() < 1 )
    {
      // This user doesn't exist.
      // Is creating it our job?
      if ( getConfig('radius_disable_local_auth', 0) == 1 )
      {
        // Yep, register him
        $email = strtolower($userinfo['username']) . '@' . getConfig('radius_email_domain', 'localhost');
        $random_pass = md5(microtime() . mt_rand());
        // load the language
        $session->register_guest_session();
        $reg_result = $session->create_user($userinfo['username'], $random_pass, $email);
        if ( $reg_result != 'success' )
        {
          // o_O
          // Registration failed.
          return array(
              'mode' => 'error',
              'error' => 'Your username and password were valid, but there was a problem instanciating your local user account.'
            );
        }
        // Get user ID
        $q = $db->sql_query("SELECT user_id, password FROM " . table_prefix . "users WHERE " . ENANO_SQLFUNC_LOWERCASE . "(username) = '$username';");
        if ( !$q )
          $db->_die();
        if ( $db->numrows() < 1 )
          return array(
              'mode' => 'error',
              'error' => 'Your username and password were valid, but there was a problem getting your user ID.'
            );
        $row = $db->fetchrow();
        $db->free_result();
        // Quick - lock the account
        $q = $db->sql_query('UPDATE ' . table_prefix . "users SET password = 'Locked by RADIUS plugin', password_salt = 'Locked by RADIUS plugin' WHERE user_id = {$row['user_id']};");
        if ( !$q )
          $db->_die();
        
        $row['password'] = 'Locked by RADIUS plugin';
      }
      else
      {
        // Nope. Just let Enano fail it properly.
        return null;
      }
    }
    else
    {
      $row = $db->fetchrow();
      $db->free_result();
    }
    
    $session->register_session($row['user_id'], $userinfo['username'], $row['password'], $level, $remember);
    return true;
  }
  else
  {
    // RADIUS authentication failed.
    
    // Are local logons allowed?
    if ( getConfig('radius_disable_local_auth', 0) == 0 )
    {
      // Yes, allow auth to continue
      return null;
    }
    
    // Block the login attempt unless the username is a local admin.
    $username = $db->escape(strtolower($userinfo['username']));
    $q = $db->sql_query("SELECT user_level FROM " . table_prefix . "users WHERE " . ENANO_SQLFUNC_LOWERCASE . "(username) = '$username';");
    if ( !$q )
      $db->_die();
    if ( $db->numrows() > 0 )
    {
      // Well, the user exists...
      list($ul) = $db->fetchrow_num();
      $db->free_result();
      if ( $ul >= USER_LEVEL_ADMIN )
      {
        // They're an admin, allow local logon
        return null;
      }
    }
    $db->free_result();
    
    // User doesn't exist, or is not an admin, and users are not allowed to log on locally. Lock them out.
    $q = $db->sql_query('INSERT INTO ' . table_prefix . "lockout(ipaddr, timestamp, action, username)\n"
                      . "  VALUES('" . $db->escape($_SERVER['REMOTE_ADDR']) . "', " . time() . ", 'credential', '" . $db->escape($userinfo['username']) . "');");
    if ( !$q )
      $db->_die();
    
    return array(
        'mode' => 'error',
        'error' => 'Invalid RADIUS authentication credentials.'
      );
  }
}

// Registration blocking hook
if ( getConfig('radius_disable_local_auth', 0) == 1 )
{
  $plugins->attachHook('ucp_register_validate', 'radius_auth_reg_block($error);');
}

function radius_auth_reg_block(&$error)
{
  $error = 'Registration on this website is disabled because RADIUS authentication is configured. Please log in using a valid RADIUS username and password, and an account will be created for you automatically.';
}

//
// ADMIN
//

$plugins->attachHook('session_started', 'radius_session_hook();');

if ( getConfig('radius_disable_local_auth', 0) == 1 )
{
  $plugins->attachHook('common_post', 'radius_tou_hook();');
}

function radius_session_hook()
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  
  // Register the admin page
  $paths->addAdminNode('adm_cat_security', 'RADIUS Authentication', 'RadiusConfig');
  
  // Disable password change
  if ( getConfig('radius_disable_local_auth', 0) == 1 && $session->user_level < USER_LEVEL_ADMIN )
  {
    $link_text = getConfig('radius_password_text', false);
    if ( empty($link_text) )
      $link_text = false;
    $link_url = str_replace('%u', $session->username, getConfig('radius_password_url', ''));
    if ( empty($link_url) )
      $link_url = false;
    $session->disable_password_change($link_url, $link_text);
  }
}

function radius_tou_hook()
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  
  // Are we pending TOU acceptance?
  if ( $session->user_logged_in && !$session->on_critical_page() && trim(getConfig('register_tou', '')) != '' )
  {
    $q = $db->sql_query('SELECT account_active FROM ' . table_prefix . "users WHERE user_id = $session->user_id;");
    if ( !$q )
      $db->_die();
    
    list($active) = $db->fetchrow_num();
    $db->free_result();
    if ( $active == 1 )
    {
      // Pending TOU accept
      // Basically, what we do here is force the user to accept the TOU and record it by setting account_active to 2 instead of a 1
      // A bit of a hack, but hey, it works, at least in 1.1.8.
      // In 1.1.7, it just breaks your whole account, and $session->on_critical_page() is broken in 1.1.7 so you won't even be able
      // to go the admin CP and re-activate yourself. Good times... erhm, sorry.
      
      if ( isset($_POST['tou_agreed']) && $_POST['tou_agreed'] === 'I accept the terms and conditions displayed on this site' )
      {
        // Accepted
        $q = $db->sql_query('UPDATE ' . table_prefix . "users SET account_active = 2 WHERE user_id = $session->user_id;");
        if ( !$q )
          $db->_die();
        
        return true;
      }
      
      global $output, $lang;
      $output->set_title('Terms of Use');
      $output->header();
      
      ?>
      <p>Please read and accept the following terms:</p>
      
      <div style="border: 1px solid #000000; height: 300px; width: 60%; clip: rect(0px,auto,auto,0px); overflow: auto; background-color: #FFF; margin: 0 auto; padding: 4px;">
        <?php
        $terms = getConfig('register_tou', '');
        echo RenderMan::render($terms);
        ?>
      </div>
      
      <form method="post">
        <p style="text-align: center;">
          <label>
            <input tabindex="7" type="checkbox" name="tou_agreed" value="I accept the terms and conditions displayed on this site" />
            <b><?php echo $lang->get('user_reg_lbl_field_tou'); ?></b>
          </label>
        </p>
        <p style="text-align: center;">
          <input type="submit" value="Continue" />
        </p>
      </form>
      
      <?php
      
      $output->footer();
      
      $db->close();
      exit;
    }
  }
}

function page_Admin_RadiusConfig()
{
  // Security check
  global $db, $session, $paths, $template, $plugins; // Common objects
  if ( $session->auth_level < USER_LEVEL_ADMIN )
    return false;
  
  if ( isset($_POST['submit']) )
  {
    setConfig('radius_enable', isset($_POST['radius_enable']) ? '1' : '0');
    setConfig('radius_server', $_POST['radius_server']);
    setConfig('radius_port', intval($_POST['radius_port']) > 0 && intval($_POST['radius_port']) < 65535 ? intval($_POST['radius_port']) : 1812 );
    setConfig('radius_secret', $_POST['radius_secret']);
    setConfig('radius_disable_local_auth', isset($_POST['radius_disable_local_auth']) ? '1' : '0');
    setConfig('radius_password_text', $_POST['radius_password_text']);
    setConfig('radius_password_url', $_POST['radius_password_url']);
    setConfig('radius_email_domain', $_POST['radius_email_domain']);
    setConfig('radius_method', $_POST['radius_method']);
    
    echo '<div class="info-box">Your changes have been saved.</div>';
  }
  
  acp_start_form();
  ?>
  <div class="tblholder">
    <table border="0" cellspacing="1" cellpadding="4">
      <tr>
        <th colspan="2">
          RADIUS Authentication Configuration
        </th>
      </tr>
      
      <!-- RADIUS enable -->
      
      <tr>
        <td class="row2" style="width: 50%;">
          Enable RADIUS authentication:
        </td>
        <td class="row1" style="width: 50%;">
          <label>
            <input type="checkbox" name="radius_enable" <?php if ( getConfig('radius_enable', 0) ) echo 'checked="checked" '; ?>/>
            Enabled
          </label>
        </td>
      </tr>
      
      <!-- Server -->
      
      <tr>
        <td class="row2">
          RADIUS server:
        </td>
        <td class="row1">
          <input type="text" name="radius_server" value="<?php echo htmlspecialchars(getConfig('radius_server', '')); ?>" size="15" />
          Port:
          <input type="text" name="radius_port" value="<?php echo getConfig('radius_port', 1812); ?>" size="5" />
        </td>
      </tr>
      
      <!-- Secret -->
      
      <tr>
        <td class="row2">
          Shared secret:
        </td>
        <td class="row1">
          <input type="text" name="radius_secret" value="<?php echo htmlspecialchars(getConfig('radius_secret', '')); ?>" size="30" />
        </td>
      </tr>
      
      <!-- Auth method -->
      
      <tr>
        <td class="row2">
          Authentication method:
        </td>
        <td class="row1">
          <select name="radius_method">
          <?php
          $methods = array(
              'pap' => 'PAP',
              'chap' => 'CHAP',
              'mschap' => 'MS-CHAP v1',
              'mschapv2' => 'MS-CHAP v2'
            );
          foreach ( $methods as $method => $name )
          {
            $select = getConfig('radius_method', 'pap') == $method ? ' selected="selected"' : '';
            echo "<option value=\"$method\"{$select}>$name</option>";
          }
          ?>
          </select>
        </td>
      </tr>
      
      <!-- Block local auth -->
      
      <tr>
        <td class="row2">
          Enforce RADIUS for single-sign-on:<br />
          <small>Use this option to force RADIUS passwords and accounts to be used, regardless of local accounts, except for administrators.</small>
        </td>
        <td class="row1">
          <label>
            <input type="checkbox" name="radius_disable_local_auth" <?php if ( getConfig('radius_disable_local_auth', 0) ) echo 'checked="checked" '; ?>/>
            Enabled
          </label>
        </td>
      </tr>
      
      <!-- E-mail domain -->
      
      <tr>
        <td class="row2">
          E-mail address domain for autoregistered users:<br />
          <small>When a user is automatically registered, this domain will be used as the domain for their e-mail address. This way, activation e-mails will
                 (ideally) reach the user.</small>
        </td>
        <td class="row1">
          <input type="text" name="radius_email_domain" value="<?php echo htmlspecialchars(getConfig('radius_email_domain', '')); ?>" size="30" />
        </td>
      </tr>
      
      <!-- Site password change link -->
      
      <tr>
        <td class="row2">
          External password management link:<br />
          <small>Enter a URL here to link to from Enano's Change Password page. Leave blank to not display a link. The text "%u" will be replaced with the user's username.</small>
        </td>
        <td class="row1">
          Link text: <input type="text" name="radius_password_text" value="<?php echo htmlspecialchars(getConfig('radius_password_text', '')); ?>" size="30" /><br />
          Link URL:  <input type="text" name="radius_password_url" value="<?php echo htmlspecialchars(getConfig('radius_password_url', '')); ?>" size="30" />
        </td>
      </tr>
      
      <tr>
        <th class="subhead" colspan="2">
          <input type="submit" name="submit" value="Save changes" />
        </th>
      </tr>
    </table>
  </div>
  <?php
  echo '</form>';
}
