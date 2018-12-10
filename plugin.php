<?php
/* 
Plugin Name: TMBI HACKATHON( Spam Prevention & Login Lockdown )
Plugin URI: 
Version: 0.1
Author: Manjunatha Mariyappa
Description: I prevent useless spammers from coming in
*/

// Setup environment
add_action ( 'init' , 'setup_login_env' );

// Disallow the users with blocked IP address
add_action ( 'init' , 'block_invalid_users' );

// Process the comments to filter the data
add_filter( 'preprocess_comment' , 'preprocess_comment_handler' );

// Spam the comments who pocess invalid email
add_filter( 'pre_comment_approved' , 'filter_handler' , 99, 2 ); 

// Check for failed login attempts
add_action('wp_login_failed', 'failed_login_attempt');

// Admin section
add_action( 'admin_menu', 'create_admin_menu' );

// Unblocks the respective ips
if ( isset( $_REQUEST['unblock_ip'] ) ) {
	unblock_the_ip( $_REQUEST['unblock_ip'] );
}

// validates email by checking the DNS
function filter_handler( $approved , $commentdata ) {
	
    $approved = validate_email( $commentdata['comment_author_email']) ? 0 : 'spam' ;

	return $approved;
}

// Formats the comments and eliminates the junk data
function preprocess_comment_handler( $commentdata ) {

	// removes spam links from the content
	$commentdata['comment_content'] = filter_spam_url( $commentdata['comment_content'] );
	
	// removes predefined spam text from the content
	$commentdata['comment_content'] = filter_spam_text( $commentdata['comment_content']);
	
	//Checks if the website url is valid
	$commentdata['comment_content'] = validate_link( $commentdata['comment_author_url']) ? $commentdata['comment_content'] : $commentdata['comment_content'] . ' <br/>Note : This might be a spammer as the website information did not validate.';

	return $commentdata;
}

//Removes SPAM text
function filter_spam_text ( $content ){
	$bad = array("content-type","bcc:","to:","cc:","abuse_word");
	return str_replace($bad,"********",$content);
}

// Removes SPAM URL
function filter_spam_url( $content ){
	return preg_replace('/(http|ftp|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-])?/', '*****Spam Link******', $content);
}

// Validates the DNS of email
function validate_email( $user_email ){
 	// https://app.hubuco.com/email_verify
	$api_key = 'Oj81pf4YZCucnY4jYFLibXP2A';
	$url = 'https://api.hubuco.com/api/v3/?api=' . $api_key .'&email=' . $user_email . '&timeout=10';
	if ( !function_exists('curl_init') ){
		die('CURL not supported. (introduced in PHP 4.0.2)');
	}
	$api = $url;
	$request = curl_init($api);
	curl_setopt($request, CURLOPT_HEADER, 0);
	curl_setopt($request, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($request, CURLOPT_FOLLOWLOCATION, true);
	$response = (string)curl_exec($request);
	curl_close($request);
	if ( !$response ) {
    	die('Nothing was returned. Do you have a connection to Email Marketing server?');
	}
	$response = json_decode($response);
	if( $response->result == "invalid" ) {
	    return false;
	} else {
		return true;
	}
}

// Validates the website link provided
function validate_link( $link ) {
	// Remove all illegal characters from a url
	$link = filter_var($link, FILTER_SANITIZE_URL);

	// Validate url
	if (filter_var($link, FILTER_VALIDATE_URL) !== false) {
		return false;
	} else {
		return true;
	}
}

// Checks for a failed login attempt and updates the database
function failed_login_attempt($username){
    $referrer = (isset($_SERVER['HTTP_REFERER'])) ? $_SERVER['HTTP_REFERER'] : $_SERVER['PHP_SELF'];
    $referrer = add_query_arg('result', 'failed', $referrer);
    $referrer = add_query_arg('username', $username, $referrer);
    $client_details = get_client_geo( get_client_ip() );
    $client_ip = $client_details['ip'];
    $client_details = implode( " | ", $client_details['location']);
    update_failed_records( $client_ip, $client_details );
    return;
}

//Returns the ip address of the client using ipify api
function get_client_ip() {
	$url ='https://api.ipify.org/?format=json';
	if ( !function_exists('curl_init') ){
		die('CURL not supported. (introduced in PHP 4.0.2)');
	}
	$api = $url;
	$request = curl_init($api);
	curl_setopt($request, CURLOPT_HEADER, 0);
	curl_setopt($request, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($request, CURLOPT_FOLLOWLOCATION, true);
	$response = (string)curl_exec($request);
	curl_close($request);
	if ( !$response ) {
    	die('Nothing was returned. Do you have a connection to Email Marketing server?');
	}
	$response = json_decode($response);
	return $response->ip;
}

// Gets the geo location of the client using geo,ipify
function get_client_geo( $ipAddress ) {
	// https://geo.ipify.org/docs
	// https://geo.ipify.org/api/v1?apiKey=at_38xzTqr1FPWYKqpW3NClv8efMNiVP&ipAddress=103.205.216.173
	$api_key = 'at_38xzTqr1FPWYKqpW3NClv8efMNiVP';
	$url ='https://geo.ipify.org/api/v1?apiKey=' . $api_key . '&ipAddress=' . $ipAddress;

	if ( !function_exists('curl_init') ){
		die('CURL not supported. (introduced in PHP 4.0.2)');
	}

	$api = $url;
	$request = curl_init($api);
	curl_setopt($request, CURLOPT_HEADER, 0);
	curl_setopt($request, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($request, CURLOPT_FOLLOWLOCATION, true);
	$response = (string)curl_exec($request);
	curl_close($request);
	if ( !$response ) {
    	die('Nothing was returned. Do you have a connection to Email Marketing server?');
	

	$response = json_decode( $response, true );
	return $response;
}

// Displays the access denied message to the user
function block_invalid_users(){
	if ( get_blocked_ips( get_client_ip() ) ) {
		echo "<h1> Access Denied </h1>";
		echo "Sorry you cannot access this site, Please contact the administrator to ublock the access";
		echo "<br/> Email : admin@hackathon.com";
		wp_die();
	}
}

// Creates the environment for user login
function setup_login_env() {
	global $wpdb;
	$table_name = $wpdb->prefix . "failed_login";
	if( $wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name ) {
 		$sql = "CREATE TABLE " . $table_name . " (
			`id` bigint(20) NOT NULL AUTO_INCREMENT,
			`details` varchar(500) NOT NULL default '',
			`date` datetime NOT NULL default '0000-00-00 00:00:00',
			`ip` varchar(100) NOT NULL default '',
			PRIMARY KEY  (`id`)
			);";
		require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
		dbDelta($sql);
	}
}

// Updates the invalid login attempt to database
function update_failed_records( $ip, $details ) {
	global $wpdb;
	$table_name = $wpdb->prefix . "failed_login";
	$insert = "INSERT INTO " . $table_name . " ( details, date, ip) " .
				"VALUES ('%s', now(), '%s')";
	$insert = $wpdb->prepare( $insert, $details, $ip );
	$results = $wpdb->query($insert);
	return;
}

// Lists the blocked ips in the database
function get_blocked_ips( $ip ) {
	global $wpdb;
	$table_name = $wpdb->prefix . "failed_login";
	$failed_count = "SELECT COUNT(id) FROM $table_name " . 
					"WHERE ip LIKE '%s'";
	$failed_count_query = $wpdb->prepare( $failed_count, $ip );
	$numm_of_fails = $wpdb->get_var( $failed_count_query );
	if ( $numm_of_fails > 2 ) {
		return true;
	} else {
		return false;
	}
}

// Cerates a admin menu page
function create_admin_menu() {
	add_options_page(
		'TMBI SPAM PROTECTION ( HACKATHON )',
		'TMBI SPAM PROTECTION',
		'manage_options',
		'spam_protection',
		'spam_update_list'
	);
}

// Updates the spam list
function spam_update_list() {
	global $wpdb;
	$table_name = $wpdb->prefix . "failed_login";
	echo '<h1>TMBI SPAM PROTECTION - HACKATHON</h1>';
	echo '<h2>List of ip blocked</h2>';
	echo '<table width="75%" cellpadding="2" cellspacing="2" border="1">
		<tr>
			<td><b>ID</b></td>
			<td><b>IP</b></td>
			<td><b>Details</b></td>
			<td><b>DATE</b></td>
			<td><b>UNBLOCK <a href=http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] . '&unblock_ip=all>( <i>UNBLOCK ALL </i> ) </a></b></td>
		</tr>';
	$rows = $wpdb->get_results("SELECT * FROM $table_name WHERE 1 GROUP BY ip ORDER BY date DESC");
	$count = 1;
	foreach ($rows as $data) {
		echo '<tr>';
		echo '<td>' . $count++ . '</td>';
		echo '<td>' . $data->ip . '</td>';
		echo '<td>' . $data->details . '</td>';
		echo '<td>' . $data->date . '</td>';
		echo '<td> <a href=http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] . '&unblock_ip=' . $data->ip . ' >UNBLOCK ME </a> </td>';
		echo '</tr>';
	}	
	echo '</table>';
}

// Unblocks the ips requested
function unblock_the_ip( $ip ) {
	global $wpdb;
	$table_name = $wpdb->prefix . "failed_login";
	if ( $ip == "all" ) {
		$delete = "DELETE FROM " . $table_name . " where 1";
	} else {
		$delete = "DELETE FROM " . $table_name . " where ip = '%s'";
	}
 	$delete = $wpdb->prepare( $delete, $ip );
	$results = $wpdb->query($delete);
}