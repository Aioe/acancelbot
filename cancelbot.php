<?php

$configfile = "/usr/system/news/cancelbot/cancelbot.conf";

$conf = parse_ini_file($configfile, true);

$nocem 	= "";
$count 	= 0;
$ordnum = 0;

openlog("acancelbot", LOG_PID, LOG_NEWS);

$banlist = read_banlist($conf["Settings"]["banlist"]);
$tokenlist = read_news_spool($conf["Settings"]["spool"], $conf["Settings"]["ctlinnd"]);
$active = read_active_file($conf["Settings"]["active"]);

if ($conf["Settings"]["send_cancels"] == 1) $cancelfile = tempnam("/tmp", "acancelbotcancels");

if (count($tokenlist) < 1)
{
	log_string("notice", "No incoming messages, aborting");
	unlink($cancelfile);
	exit(0);
}

foreach($tokenlist as $token)
{
	$status = 0;
	$token_clear = preg_replace("/\t+|\ +|\n+/", "", $token );
	$article = get_article($token_clear, $conf["Settings"]["sm"]);
	if (!$article) 
	{
		log_string("notice", "Token $token_clear, message is missing");
		continue; // se l'articolo è già stato altrimenti cancellato
	}
	
	$ordnum++;
	$mid	= get_header($article, "Message-ID", 1);
	$groups = get_header($article, "Newsgroups", 1);
	log_string("notice", "Processing $ordnum: $token_clear ($mid - $groups)");

	if (($conf["Settings"]["check_tor"] == 1) and (check_tor($article)))
	{
		$nocem = add_nocem_entry($nocem, $article, "TOR Exit Node");
                if ($conf["Settings"]["send_cancels"] == 1) add_control_cancel($cancelfile, $article, "TOR Exit Node");
                log_string("notice", "Cancel message $mid: TOR Exit Node");
		continue;
	}

	$control 	= get_header($article, "Control", 1);
	if (strlen($control) > 0) 
	{
		log_string("notice", "Token $token_clear, message $mid include a control header ($control)... skipping");
		continue; // se è un control message
	}

        $newsgroups = array();
        if (preg_match("/,/", $groups ))
        {
                $newsgroups = explode(",", $groups);
        } else {
                $newsgroups[0] = $groups;
        }

        foreach($newsgroups as $group)
        {
		if (!isset($active[$group]))
		{
			log_string("notice", "Message $mid: missing group $group, skipping");
			continue;
		}
	        if (preg_match("/m/i", $active[$group]))
                {
			if (preg_match("/^it\./", $group))  // se è moderato ed appartiene alla gerarchia it
			{
				$approved 	= get_header($article, "Approved", 	1);
				$path		= get_header($article, "Path",	   	1);
				$xmailp		= get_header($article, "X-Mail-Path", 	1);

				if (
					($conf["Settings"]["check_moderation"] == 1) and 
					(check_moderation($article))
				   )
				{
 					$nocem = add_nocem_entry($nocem, $article, "Forged Moderation");
                			if ($conf["Settings"]["send_cancels"] == 1) add_control_cancel($cancelfile, $article, "Forged Moderation");
                			log_string("notice", "Cancel message $mid: Forged Moderation");
					log_string("notice", "Message $mid: Approved '$approved', X-Mail-Path '$xmailp', Path '$path'");
                			continue(2);
				}
			}
                        log_string("notice", "Message $mid was sent to $group, which is moderated, skipping");
                        continue(2);
                }
        }

	if (preg_match("/news\.lists/i", $groups))
	{
		log_string("notice", "Message $mid is a NOCem bag, skipping");
		continue;
	}

	log_string("debug", "Message $mid, analyzing banlist...");

	foreach($banlist as $key => $value )
	{
		$header 	= $banlist[$key]["Header"];
		$target         = $banlist[$key]["Groups"];
		$rule		= $banlist[$key]["Value"];
		$exception	= $banlist[$key]["Exclude"];
		$comment	= $banlist[$key]["Comment"];

		if (!preg_match($target, $groups))
		{
			log_string("debug", "Message $mid, rule $key: sent to $groups, outside target $target, skipping");
			continue;
		}

	 	if (preg_match($exception, $groups))
	        { 
                	log_string("notice", "Message $mid, rule $key: sent to $groups that matches whitelist $exception, skipping");
                        continue;
                }

		if (!preg_match("/body/i", $header))
		{
			$header_value = get_header($article, $header, 2);
			if (!$header_value) continue; 
			if (preg_match($rule, $header_value))
			{
				$nocem = add_nocem_entry($nocem, $article, $comment);
				if ($conf["Settings"]["send_cancels"] == 1) add_control_cancel($cancelfile, $article, $comment);
				log_string("notice", "Cancel $mid: header $header: $header_value matches $rule ($key:$comment)");
				$status = 1;
				$count++;
				continue;
			} 
		} else {
			$body = get_body($article);
			if (preg_match($rule, $body))
			{
				$nocem = add_nocem_entry($nocem, $article, $comment);
				if ($conf["Settings"]["send_cancels"] == 1) add_control_cancel($cancelfile, $article, $comment);
				log_string("notice", "Cancel $mid: body matches $rule ($key:$comment)");
				$status = 1;
				$count++;
				continue;
			}
		}
		if ($status == 1) break;
	}
}

log_string("notice", "Processed $ordnum tokens, $count cancellations");

if (($conf["Settings"]["send_cancels"] == 1) and ($count > 0)) // Bisogna *prima* spedire i cancel message poi la bag nocem perché altrimenti
{					      			// il server li rifiuta
        chown($cancelfile, "news");
        chmod($cancelfile, "777");
	$cli = $conf["Settings"]["rnews"] . " $cancelfile";
	exec($cli);
	log_string("notice", "Sent $count cancel messages");
	system("rm -rf $cancelfile");
} else system("rm -rf $cancelfile"); // il file è stato comunque creato e va cancellato

if ($count == 0)
{
        log_string("notice", "No messages to cancel, aborting");
        exit(0);
}

$id = substr(md5(rand()), 0, 7);
$nocem_bag = add_nocem_bag($count, $id, $conf["Settings"]["key"]);
$nocem_bag .= $nocem;
$nocem_bag .= "@@END NCM BODY\n";
$nocem_signed_bag = sign_bag($nocem_bag, $conf);
$usenet_message = build_nocem_message($nocem_signed_bag, $id, $count);
send_rnews($usenet_message, $conf);

//////////////////////////////////////////////////////////////////////////////////////////////

function build_nocem_message($nocem, $id, $count)
{
	$elem1 = rand(0, 999999);
	$elem2 = rand(0, 999999);
	$elem3 = rand(0, 999999);

	$subject = "";
	if ($count == 1) $subject = "(1 article)";
	else $subject = "($count articles)";

	$mid = "<$elem1$elem2$elem3@nocem.aioe.org>";

	$date = date("r");
	$str = <<<EOD
From: Aioe.org Public News Server (NOCEM Service) <nocem@aioe.org>
Newsgroups: aioe.news.nocem,news.lists.filters
Subject: @@NCM NoCeM notice $id aioe-spam/hide $subject
Date: $date
Path: not-for-mail
Followup-To: news.admin.net-abuse.usenet,aioe.news.helpdesk
Content-Type: text/plain; charset=utf-8
Message-ID: $mid

$nocem

EOD;

	return $str;

}



function add_nocem_bag($count, $id, $key)
{

	$str = <<<EOD
Aioe.org issues cancel messages in the NoCem format against USENET articles that 
include spam or other abuses posted on Italian groups or on the aioe.* hierarchy

The (public) GPG key needed to verify the signature of *all* cancels issued by 
aioe.org is available at http://news.aioe.org/hierarchy/nocem.txt

Those who need to report messages erroneously cancelled by the cancelbot should 
contact usenet@aioe.org

This message was signed using the following key:
$key


@@BEGIN NCM HEADERS
Version: 0.93
Issuer: nocem@aioe.org
Type: aioe-spam
Action: hide
Count: $count
Notice-ID: $id
@@BEGIN NCM BODY

EOD;

	return $str;
}



function add_nocem_entry($nocem, $article, $comment)
{
	$sender 	= get_header($article, "From", 		1);
	$date 		= get_header($article, "Date", 		1);
	$subject	= get_header($article, "Subject", 	1);
	$path		= get_header($article, "Path",		1);
	$groups		= get_header($article, "Newsgroups",	1);
	$mid		= get_header($article, "Message-ID", 	1);


	$elem = explode("!", $path);
	$rev_path = array_reverse($elem);
	$short_path = "";

	$num = count($elem);
	if ($num >= 4) $num = 4;
	$num--;

	for ($n = $num; $n >= 0; $n--) $short_path .= "!$rev_path[$n]";

	$nocem .= "#\tSender: $sender\n#\tDate: $date\n#\tSubject: $subject\n#\tPath: $short_path\n#\tReason: $comment\n$mid $groups\n";

	return $nocem;
}


function get_body($article)
{
	$body = "";
	$status = 0;

	foreach ($article as $line)
	{
		if ($status == 1) $body .= $line;
		if (strlen($line) < 3) $status = 1;
	}

	return $body;	
}


function read_news_spool($spool, $ctlinnd )
{
	$new_spool = "$spool.old";
	$cli = "mv $spool $new_spool";
	exec($cli);
	$cli = $ctlinnd . " flush cancelbot";
	exec($cli);
	sleep(1);
	$data = file($new_spool);
	unlink("$new_spool");	
	return $data;
}


function get_article($token, $sm)
{
	$cli = $sm . " -q $token";
	exec($cli, $output);
	if (count($output) > 0) return $output;
	else return FALSE;
}

function get_header($article, $header, $type)
{
        foreach($article as $line)
        {
                if (preg_match("/^([a-z\-]+)\:\ (.+)/i", $line, $match)) 
                {
                	$key = $match[1];
			$value  = rtrim($match[2]);
			if ($type == 1)
			{
				if (preg_match("/^$header/i", $key)) return $value;
			} else {
				if (preg_match($header, $key)) return $value;
			}
                }
        }
        return FALSE;
}

function read_banlist($file)
{
	$ini_array = parse_ini_file($file, true);

	foreach ($ini_array as $rule => $array)
	{
		if (isset($ini_array[$rule]["Header"])) $ini_array[$rule]["Header"] 	= generate_regexp($ini_array[$rule]["Header"]);
		else $ini_array[$rule]["Header"] = "/$./";
		if (isset($ini_array[$rule]["Value"])) $ini_array[$rule]["Value"] 	= generate_regexp($ini_array[$rule]["Value"]);
		else $ini_array[$rule]["Value"] = "/$./";
		if (isset($ini_array[$rule]["Groups"])) $ini_array[$rule]["Groups"] 	= generate_regexp($ini_array[$rule]["Groups"]);
		else $ini_array[$rule]["Groups"] = "/.+/"; // se il target non è indicato controlla tutto
		if (isset($ini_array[$rule]["Exclude"])) $ini_array[$rule]["Exclude"] 	= generate_regexp($ini_array[$rule]["Exclude"]);
		else $ini_array[$rule]["Exclude"] = "/$./";
		if (!isset($ini_array[$rule]["Comment"])) $ini_array[$rule]["Comment"] 	= "No comment available"; 
	}

	return $ini_array;	

}

function read_active_file($activepath)
{
        $active = array();
        $lines = file($activepath);
        if (!$lines)
        {
                log_string("err", "Unable to load $activepath, aborting");
                exit(5);
        }

        foreach( $lines as $line)
        {
                $elems = explode(" ", $line);
                $active[$elems[0]] = rtrim($elems[3]); 
        }

        return $active;
}

function generate_regexp($input)
{
	if (strlen($input) == 0) return "/$./";
	if (!preg_match("/^\//", $input)) $input = "/$input";
        if (
                        (!preg_match("/\/$/", $input)) and
                        (!preg_match("/\/i$/", $input))
                   ) $input = "$input/i"; 
	return $input;
}


function log_string($facility, $line)
{
	$syslog_facility = "";
	if ($facility == "notice") $syslog_facility = LOG_NOTICE;
	elseif ($facility == "debug") $syslog_facility = LOG_DEBUG;
	else $syslog_facility = LOG_ERR;
	syslog($syslog_facility, $line );
}

function sign_bag($bag, $conf)
{
        $filename = tempnam("/tmp", "acancelbotbag");
        $file = fopen($filename, "w+");
        if (!$file)
        {
                log_string("err", "Unable to create tmp file: $filename");
                exit(5);                
        }

        fputs($file, $bag);
        fclose($file);

        $cli = $conf["Settings"]["gpg"] . " $filename";
        exec($cli, $output, $retvalue);

        if ($retvalue != 0)
        {
                log_string("err", "Unable to execute $cli: error $retvalue, aborting");
                exit($retvalue);
        }

        $fileasc = $filename . ".asc";
        $signed_bag = file_get_contents($fileasc);
        unlink($filename);
        unlink($fileasc);

        return $signed_bag;
}

function send_rnews($message, $conf)
{
        $filename = tempnam("/tmp", "acancelbotrnews");
        $file = fopen($filename, "w+");
        if (!$file)
        {
                log_string("err", "Unable to create tmp file: $filename");
                exit(5);
        }
        fputs($file, $message);
        fclose($file);
	chown($filename, "news");
	chmod($filename, "777");
        $rnewscli = $conf["Settings"]["rnews"] . " $filename";
        exec($rnewscli);
	system("rm -rf $filename");
}

function add_control_cancel($cancelfile, $article, $comment)
{
	$file = fopen($cancelfile, "a+");
	if (!$file)
	{
		log_string("err", "Unable to append data to $cancelfile");
		return;
	}

	$groups 	= get_header($article, "Newsgroups", 1);
	$mid    	= get_header($article, "Message-ID", 1);
	$from   	= get_header($article, "From",	     1);
	$date   	= date("r");
	$subject 	= get_header($article, "Subject",    1);
	
	$newmid = $mid;

	$newmid = preg_replace("/</", "<cancel.", $newmid );

	$cancel = <<<EOD
Path: control.aioe.org!cyberspam!usenet!not-for-mail
Newsgroups: $groups
Message-ID: $newmid
Subject: cmsg cancel $mid
X-Original-Subject: $subject
Control: cancel $mid
From: Aioe.org Public News Server <usenet@aioe.org>
Sender: $from
Date: $date
References: $mid
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 8bit
Approved: nocem@aioe.org

This cancel message was generated by aioe.org (see 
https://news.aioe.org) to keep Italian usenet groups 
clean from spam and abuse.

Those who need to report messages erroneously cancelled 
by server should contact the address: usenet@aioe.org

Service is experimental at the moment.

Reason: $comment\n

EOD;

	$size = strlen($cancel);
	fputs($file, "#! rnews $size\n");
	fputs($file, $cancel);
	fclose($file);
}

function check_tor($article)
{
	$mid  = get_header($article, "Message-ID", 1); 
	$ntph = get_header($article, "NNTP-Posting-Host", 1);
	if (!$ntph) 
	{
		$ntph = get_header($article, "Injection-Info", 1);
		if (!$ntph)
		{
			log_string("debug", "Message $mid has no clear sender's IP");
			return FALSE;
		}
	
		if (preg_match("/posting\-host\=\"(.+)\";/i", $ntph, $match ))
		{
			$source = $match[1];
			if (!preg_match("/:/", $source)) $ntph = $source;
			else {
				$elem = explode(":", $source);
				if (count($elem) == 2) $ntph = $elem[1]; // INN FORMAT
				else $ntph = $source; // IPv6
			}
		} else {
			log_string("debug", "Message $mid has no clear sender's IP");
                        return FALSE;
		}
	}

	$nntp = gethostbyname($ntph);
	if (!filter_var($nntp, FILTER_VALIDATE_IP))
	{
		log_string("debug", "Message $mid has $nntp as sender's address which is unknown"); 
		return FALSE;
	}

	log_string("debug", "Message $mid: sender's address $nntp");

	if (preg_match("/^127\.0\.0\.1|^192\.168|^10\./", $nntp))
	{
		log_string("notice", "Message $mid, sender's IP $nntp is a local address, skipping tor check");
		return FALSE;
	}

	$dn = "";

	if (preg_match("/\./", $nntp)) // IPv4
	{
		$elem = explode(".", $nntp);
		$elem_rev = array_reverse($elem);
		foreach( $elem_rev as $entry) $dn .= "$entry.";
	}
	elseif (preg_match("/:/", $nntp)) // IPv6
	{
		$elem = explode(":", $nntp);
		$tmp = "";
		foreach($elem as $id) $tmp .= $id;
		$id_rev = strrev($tmp);
		$temp = str_split($id_rev);
		foreach($temp as $sgr) $dn .= "$sgr.";
	} 

	$dn = $dn . "torexit.dan.me.uk";
        $ip = gethostbyname($dn);
        log_string("debug", "Message $mid: IP $nntp, DNSBL $dn, result $ip"); 
        if ($ip != $dn) return TRUE;
	return FALSE;
}

function check_moderation($article)
{
	$mid 		= get_header($article, "Message-ID", 	1);
	$path		= get_header($article, "Path",		1);
	$approved	= get_header($article, "Approved",	1);
	$groups		= get_header($article, "Newsgroups",	1);
	$xmailp		= get_header($article, "X-Mail-Path",	1);

	if (preg_match("/it\.cultura\.filosofia\.moderato|it\.discussioni\.auto\.mod|it\.fan\.starwars|it\.scienza.astronomia|it\.sport\.calcio\.juventus|it\.test.\moderato/i", $groups))
	{
//  WebCepheus ha il suo cancelbot quindi non va protetto
		log_string("notice", "Message $mid: $groups is moderated by WebCepheus, which onwns a cancelbot, skipping");
		return FALSE;
	} else {
			if ((!preg_match("/robomod@news\.nic\.it\ \(1\.22\)/", $approved)) or
                           (!preg_match("/\!bofh\.it\!news\.nic\.it\!robomod/", $path)) or
                           (!isset($xmailp))) return TRUE;
			else return FALSE;
	}

	return FALSE;
}

?>
