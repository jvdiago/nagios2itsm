#!/usr/bin/perl -w
################################################################################
# BMC Service Desk Express Nagios Connector is developed by : Herve Roux under GPL Licence 2.0.
# Modified by Javier Vela to add ITSM integration and reopening of solved/closed incidents. 
#
# v1.0.3 - Herve Roux
# v2.0.0 - Javier Vela
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation ; either version 2 of the License.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <http://www.gnu.org/licenses>.
#
#
####################################################################################
#
# Help : ./itsm.pl -h
#
# IMPORTANT: Modify the function GetIncidents to specify the query(s) to search similar Incidents

my $CheckOnly;

sub print_success {printf "\e[60G\[\e[32m  OK  \e[m]\n";}
sub print_passed {printf "\e[60G\[\e[33mPASSED\e[m]\n";}
sub print_warning {printf "\e[60G\[\e[33mWARNING\e[m]\n";}
sub print_failure {printf "\e[60G\[\e[31mFAILED\e[m]\n";}


my $ARGSTRING = '';
foreach (@ARGV) {
	if ( $_ =~ / / ){
		$ARGSTRING = $ARGSTRING." '".$_."'";
	} else {
		$ARGSTRING = $ARGSTRING." ".$_;	
	}
}
 
BEGIN{
	foreach (@ARGV) {
 		if ( $_ eq "--check" ){
 			$CheckOnly = '1';
 		}
	} 
	
	if ( $CheckOnly ){
		
		my $CheckOK = 1;
		
		sub CheckMod {
			my @parms = @_;
			for (@parms) {
				print "    * Checking for perl Module \'$_\'";
				system ("/usr/bin/perl -m$_ -e 1 > 0 2>&1");
				if ($? == 0) {print_success} else {print_failure; $CheckOK = 0;}
			}
		}
		
		print "\nChecking PERL Modules availability:\n";
		CheckMod(	'Getopt::Long',
					'SOAP::Lite',
					'Time::Local',
					'Digest::SHA1',
					'MIME::Base64',
					'Sys::Hostname',
					'Socket',
					'Net::Domain',
					'Net::Address::IP::Local',
					'Data::UUID',
					'User::pwent',
					'File::stat',
					'POSIX',
					'Log::Log4perl',
					'DateTime::Format::Strptime',
					);			
		print "\n";
		
		if ($CheckOK == 0 ){exit 1}
		
	}
}

if ( ! @ARGV ){
	print_header();
	print_usage();
	exit 0;
}
	
use strict;
use Getopt::Long;
use SOAP::Lite maptype => {};
#, +trace => [ transport =>
#sub {  
#    my ($http_object) = @_;
#   
#    if (ref($http_object) eq "HTTP::Request") {
#      print 'SOAP XML sent:'.$http_object->content."\n";
#    }
#    elsif (ref($http_object) eq "HTTP::Response") { 
#      print 'SOAP XML Response:'.$http_object->content."\n";
#    }
#
#}];
use Time::Local;
use Digest::SHA1;
use MIME::Base64;
use Sys::Hostname;
use Socket;
use Net::Domain qw (hostfqdn hostdomain);
use Net::Address::IP::Local;
use Data::UUID;
use POSIX qw(strftime);
use Data::Dumper;
use Class::Struct;
use Log::Log4perl qw(get_logger :levels);
use DateTime::Format::Strptime;

#Bug, I don't why when called from NAGIOS this vars are not defined.
our $FATAL=5000;
our $ERROR=4000;
our $WARN=3000;
our $INFO=2000;
our $DEBUG=1000;

*default_nonce_generator = create_generator( "a value of ", int(1000*rand()) );

my $TIMEOUT = 15;
my %ERRORS=('OK'=>0,'WARNING'=>1,'CRITICAL'=>2,'UNKNOWN'=>3,'DEPENDENT'=>4);
my $ERROR_STRING='';
my @SOAP_ERRORS = ();

my $HCmessage='';
my $ShowHelp='';
my $Cust_Conf_File='';
my %Raw_SOAP_Param;

my $ng_State='';
my $ng_StateType='';
my $ng_Attempt='';
my $ng_FQDN='';
my $ng_CATEGORY='';
my $ng_GROUPASSIGNMENT='';
my $ng_HOSTADDRESS='';
my $ng_ALIAS='';	
my $ng_HOSTNAME='';
my $ng_SERVICENAME='';
my $ng_HOSTGROUPNAMES='';
my $ng_SERVICEGROUPNAMES='';
my $ng_EVENTID='';
my $ng_LASTEVENTID='';
my $ng_PROBLEMID='';	
my $ng_LASTPROBLEMID='';
my $ng_DATETIME='';
my $ng_OUTPUT='';
my $ng_LONG_OUTPUT='';
my $ng_DOWNTIME=0;
my $ng_DISABLE='';
my $ng_DISABLE_ACK='';
my $ng_NOTIFICATIONTYPE='';
my $ng_NOTIFICATIONNUMBER='';

Getopt::Long::Configure('bundling');
	GetOptions ('s:s' => \$ng_State,				'state=s'            => \$ng_State,
			't:s' => \$ng_StateType,			'type:s'             => \$ng_StateType,				
			'n:s' => \$ng_Attempt,				'attempt:s'          => \$ng_Attempt,
			'f:s' => \$ng_FQDN,					'fqdn:s'             => \$ng_FQDN,
			'C:s' => \$ng_CATEGORY,				'category:s'         => \$ng_CATEGORY,
			'G:s' => \$ng_GROUPASSIGNMENT,		'GroupAssignment:s'  => \$ng_GROUPASSIGNMENT,			
			'a:s' => \$ng_HOSTADDRESS,			'address:s'          => \$ng_HOSTADDRESS,
			'A:s' => \$ng_ALIAS,				'alias:s'            => \$ng_ALIAS,
			'H:s' => \$ng_HOSTNAME,				'host:s'             => \$ng_HOSTNAME,
			'S:s' => \$ng_SERVICENAME,			'service:s'          => \$ng_SERVICENAME,
			'h:s' => \$ng_HOSTGROUPNAMES,		'hostgroups:s'       => \$ng_HOSTGROUPNAMES,
			'g:s' => \$ng_SERVICEGROUPNAMES,	'servicegroups:s'    => \$ng_SERVICEGROUPNAMES,
			'i:s' => \$ng_EVENTID,				'eventid:s'          => \$ng_EVENTID,
			'I:s' => \$ng_LASTEVENTID,			'lasteventid:s'      => \$ng_LASTEVENTID,
			'p:s' => \$ng_PROBLEMID,			'problemid:s'        => \$ng_PROBLEMID,
			'P:s' => \$ng_LASTPROBLEMID,		'lastproblemid:s'    => \$ng_LASTPROBLEMID,
			'T:s' => \$ng_DATETIME,				'time:s'             => \$ng_DATETIME,
			'o:s' => \$ng_OUTPUT,				'output:s'           => \$ng_OUTPUT,
			'O:s' => \$ng_LONG_OUTPUT,			'longoutput:s'       => \$ng_LONG_OUTPUT,
			'w:s' => \$ng_DOWNTIME,				'downtime:s'         => \$ng_DOWNTIME,
			'd:s' => \$ng_DISABLE,				'disable:s'          => \$ng_DISABLE,
			'D:s' => \$ng_DISABLE_ACK,			'disableack:s'       => \$ng_DISABLE_ACK,
			'N:s' => \$ng_NOTIFICATIONTYPE,		'notificationtype:s' => \$ng_NOTIFICATIONTYPE,
			'c:s' => \$Cust_Conf_File,			'conf:s'             => \$Cust_Conf_File,
			'r:s' => \$ng_NOTIFICATIONNUMBER,		'renotification:s'   => \$ng_NOTIFICATIONNUMBER,
			'help' => \$ShowHelp,
			'check' => \$CheckOnly,
			'SOAPdata=s' =>\%Raw_SOAP_Param,
);

if ( $ShowHelp )
{
	print_help();
	exit 0;
}


if ( ! $Cust_Conf_File ){$Cust_Conf_File = "/etc/nagios/itsm/itsm.conf"}
if ( $ng_DATETIME ){$ng_DATETIME = timeConvert($ng_DATETIME)}


our $itsm_log_file;
our $itsm_uri;
our $itsm_url;
our $itsm_url_method;
our $itsm_url_query;
our $itsm_url_queryList;
our $itsm_url_query_method;
our $itsm_url_queryList_method;
our $itsm_url_recovery;
our $itsm_url_recovery_method;
our $itsm_ticket_link;
our $itsm_ws_security;
our $itsm_ws_login;
our $itsm_ws_password;
our $itsm_default_company;
our $itsm_default_firstName;
our $itsm_default_lastName;
our $itsm_default_source;
our $itsm_default_serviceType;
our $itsm_default_service_impact;
our $itsm_default_service_urgency;
our $itsm_default_host_impact;
our $itsm_default_host_urgency;
our $itsm_default_worknote_source;
our $itsm_default_worknote_locked;
our $itsm_default_worknote_access;
our $itsm_default_worknote_type;
our $itsm_default_worknote_summary;
our $send_mail_on_Recovery;
our $send_mail_on_worknote;
our $itsm_max_days;
our $reopen_on_notification;
our $ng_pipe;
our $ng_contact;
our $ng_set_acknowledge_on_ticket_creation;
our $ng_srv_uuid_file;
our $mailer;
our $ng_email_contact_to;
our $ng_email_contact_from;
our $ng_max_retry;
our $ng_wait_retry;
our $ng_cust_notification;
our $itsm_url_Recovery;
our $itsm_url_RecoveryQuery;
our $ngsrv_addr; 
our $ngsrv_fqdn;
our $itsm_timeout;
our $ng_use_hostname_as_fqdn;
our $ng_use_alias_as_fqdn;
our $send_Recovery_as_normal_event;
our $ignore_event_on_downtime;
our @filter_notification;

struct( WorkNote => {
       	Work_Info_Summary => '$', 
       	Work_Info_Notes => '$', 
       	Work_Info_Type => '$',
       	Work_Info_Date => '$', 
       	Work_Info_Source => '$', 
       	Work_Info_Locked => '$', 
       	Work_Info_View_Access => '$',
});

use User::pwent;
use File::stat;

sub Check_perm{
	my ($FileName, $User) = @_;
	
	my $fileinfo = stat($FileName);
	unless (defined $fileinfo){
		return 0;
	}
	my $NagiosUser = getpwnam("nagios");
	if ($NagiosUser){
		if ($fileinfo->uid == $NagiosUser->uid){
			return 1;
		} else {
			return 0;
		}
	}
	return 0;
}

# Load config File

if ( $CheckOnly ){print "Checking Configuration File:\n    * ";}
if ($Cust_Conf_File){
	if (-e $Cust_Conf_File){
		
		if ( $CheckOnly ){
			print "Checking Ownership";
			if (Check_perm($Cust_Conf_File, "nagios")){
				print_success;
			}else{
				print_warning;
				print "File '$Cust_Conf_File' is not owned by user 'nagios'. Consider changing permision!\n";
			}
			print "    * ";
		}
		
		if (open(TMP_Conf, "< $Cust_Conf_File")){
    		close(TMP_Conf);
    		do $Cust_Conf_File;
		} else {
			print "Cannot Read Configuration file";
			if ( $CheckOnly ){print_failure}else{print "\n";}
			exit 1;
		}
		
		if ($@) { print "Cannot parse configuration file"; if ( $CheckOnly ){print_failure}else{print "\n";} exit 1;}
		if ( $CheckOnly ){print "Configuration file loaded"; print_success}
	} else {
		print "Configuration file not found";
		if ( $CheckOnly ){print_failure}else{print "\n";}
		exit 1;
	}
}


# Setting Default Options #############################################################################
if ( ! $itsm_log_file ){
	my $logger = get_logger("nagios2itsm");
	$logger->level($INFO);

	# Appenders
	my $appender = Log::Log4perl::Appender->new(
     		"Log::Dispatch::File",
     		filename => "/var/log/nagios/itsm.log",
     		mode     => "append",
	);

	$logger->add_appender($appender);

	# Layouts
	my $layout =
  	Log::Log4perl::Layout::PatternLayout->new(
                 "%d %p> %F{1}:%L %M - %m%n");
	$appender->layout($layout);
} else { 
	Log::Log4perl->init($itsm_log_file);
}

my $DefaultOptionCritical;
if ( $CheckOnly ){
	my $HeaderPrinted;
	if ( ! $itsm_uri ){if(!$HeaderPrinted){print "Missing Mandatory Parameters in configuration file:\n";$HeaderPrinted=1;} print "    * Parameter '\$itsm_uri' not found"; print_warning }
	if ( ! $itsm_url_method ){if(!$HeaderPrinted){print "Missing Mandatory Parameters in configuration file:\n";$HeaderPrinted=1;} print "    * Parameter '\$itsm_url_method' not found"; print_warning }
	if ( ! $itsm_url ){if(!$HeaderPrinted){print "Missing Mandatory Parameters in configuration file:\n";$HeaderPrinted=1;} print "    * Parameter '\$itsm_url' not found"; print_warning }
	if ( ! $itsm_url_recovery ){if(!$HeaderPrinted){print "Missing Mandatory Parameters in configuration file:\n";$HeaderPrinted=1;} print "    * Parameter '\$itsm_url_recovery' not found"; print_warning }
	if ( ! $itsm_url_recovery_method ){if(!$HeaderPrinted){print "Missing Mandatory Parameters in configuration file:\n";$HeaderPrinted=1;} print "    * Parameter '\$itsm_url_recovery_method' not found"; print_warning }
	if ( ! $itsm_url_queryList ){if(!$HeaderPrinted){print "Missing Mandatory Parameters in configuration file:\n";$HeaderPrinted=1;} print "    * Parameter '\$itsm_url_queryList' not found"; print_warning }
	if ( ! $itsm_url_queryList_method ){if(!$HeaderPrinted){print "Missing Mandatory Parameters in configuration file:\n";$HeaderPrinted=1;} print "    * Parameter '\$itsm_url_queryList_method' not found"; print_warning }
	if ( ! $itsm_url_query ){if(!$HeaderPrinted){print "Missing Mandatory Parameters in configuration file:\n";$HeaderPrinted=1;} print "    * Parameter '\$itsm_url_query' not found"; print_warning }
	if ( ! $itsm_url_query_method ){if(!$HeaderPrinted){print "Missing Mandatory Parameters in configuration file:\n";$HeaderPrinted=1;} print "    * Parameter '\$itsm_url_query_method' not found"; print_warning }
} else {
	if ( ! $itsm_uri ){logEvent($ERROR,0,"Missing parameter '\$itsm_uri' in configuration file!\n"); $DefaultOptionCritical=1; }
	if ( ! $itsm_url ){logEvent($ERROR,0,"Missing parameter '\$itsm_url' in configuration file!\n"); $DefaultOptionCritical=1; }
	if ( ! $itsm_url_method ){logEvent($ERROR,0,"Missing parameter '\$itsm_url_method' in configuration file!\n"); $DefaultOptionCritical=1; }
	if ( ! $itsm_url_recovery ){logEvent($ERROR,0,"Missing parameter '\$itsm_url_recovery' in configuration file!\n"); $DefaultOptionCritical=1; }
	if ( ! $itsm_url_recovery_method ){logEvent($ERROR,0,"Missing parameter '\$itsm_url_recovery_method' in configuration file!\n"); $DefaultOptionCritical=1; }
	if ( ! $itsm_url_queryList ){logEvent($ERROR,0,"Missing parameter '\$itsm_url_queryList' in configuration file!\n"); $DefaultOptionCritical=1; }
	if ( ! $itsm_url_queryList_method ){logEvent($ERROR,0,"Missing parameter '\$itsm_url_queryList_method' in configuration file!\n"); $DefaultOptionCritical=1; }
	if ( ! $itsm_url_query ){logEvent($ERROR,0,"Missing parameter '\$itsm_url_query' in configuration file!\n"); $DefaultOptionCritical=1; }
	if ( ! $itsm_url_query_method ){logEvent($ERROR,0,"Missing parameter '\$itsm_url_query_method' in configuration file!\n"); $DefaultOptionCritical=1; }
}

if ( ! $itsm_ticket_link ){$itsm_ticket_link = '';}
if ( ! $itsm_ws_security ){$itsm_ws_security = '';}
if ( ! $itsm_ws_login ){$itsm_ws_login = '';}
if ( ! $itsm_ws_password ){$itsm_ws_password = '';}

if ( ! $ng_max_retry ){$ng_max_retry = 3;}
if ( ! $ng_wait_retry ){$ng_wait_retry = 30;}

if ( ! $ngsrv_addr ){$ngsrv_addr = Net::Address::IP::Local->public;}
if ( ! $ngsrv_fqdn ){$ngsrv_fqdn = hostfqdn();}
if ( ! $itsm_timeout ){$itsm_timeout = 60;}
if ( ! $ng_use_hostname_as_fqdn ){$ng_use_hostname_as_fqdn = 'no';}
if ( ! $ng_use_alias_as_fqdn ){$ng_use_alias_as_fqdn = 'no';}
if ( ! $ng_pipe ){$ng_pipe = '';}
if ( ! $mailer ){$mailer = '';}
if ( ! $ng_email_contact_to ){$ng_email_contact_to = '';}
if ( ! $ng_email_contact_from ){$ng_email_contact_from = '';}
if ( ! $ng_cust_notification ){$ng_cust_notification = -1;}
if ( ! $ng_contact ){$ng_contact = 'Supervisor';}
if ( ! $ng_set_acknowledge_on_ticket_creation ){$ng_set_acknowledge_on_ticket_creation = 'no';}
if ( ! $send_Recovery_as_normal_event ){$send_Recovery_as_normal_event = 'no';}
if ( ! $send_mail_on_worknote ){$send_mail_on_worknote = 'no';}
if ( ! $send_mail_on_Recovery ){$send_mail_on_Recovery = 'no';}
if ( ! $reopen_on_notification ){$reopen_on_notification = 'no';}
if ( ! $ignore_event_on_downtime ){$ignore_event_on_downtime = 'yes';}
if ( ! $ng_srv_uuid_file ){ $ng_srv_uuid_file = "/etc/nagios/itsm/ng_srv.uuid";}
if ( ! $itsm_max_days ) {$itsm_max_days = 30;}
if ( ! $itsm_default_service_impact ){$itsm_default_service_impact = '3-Moderate/Limited';}
if ( ! $itsm_default_service_urgency ){$itsm_default_service_urgency = '3-Medium';}
if ( ! $itsm_default_host_impact ){$itsm_default_host_impact = '3-Moderate/Limited';}
if ( ! $itsm_default_host_urgency ){$itsm_default_host_urgency = '2-High';}
if ( ! $itsm_default_worknote_source ){$itsm_default_worknote_source = 'Other';}
if ( ! $itsm_default_worknote_locked ){$itsm_default_worknote_locked = 'yes';}
if ( ! $itsm_default_worknote_access ){$itsm_default_worknote_access = 'Internal';}
if ( ! $itsm_default_worknote_type ){$itsm_default_worknote_type = 'General Information';}
if ( ! $itsm_default_worknote_summary ){$itsm_default_worknote_summary = 'Created By Nagios';}
if ( ! $itsm_default_company ){ $itsm_default_company = '';}
if ( ! $itsm_default_firstName ){ $itsm_default_firstName = '';}
if ( ! $itsm_default_lastName ){ $itsm_default_lastName = '';}
if ( ! $itsm_default_source ){ $itsm_default_source = 'Other';}
if ( ! $itsm_default_serviceType ){ $itsm_default_serviceType = 'User Service Restoration';}

#######################################################################################################


sub CheckUUIDOwner {
	if ( $CheckOnly ){
		print "    * Checking UUID file Ownership";
		if (Check_perm($ng_srv_uuid_file, "nagios")){
			print_success;
		}else{
			print_warning;
			print "File '$ng_srv_uuid_file' is not owned by user 'nagios'. Consider changing permision!\n";
		}
	}
}

my $serverUUID = '';
if ( $CheckOnly ){print "\nNagios Server UUID";}
if (-e $ng_srv_uuid_file){
	if ( open(TMP_UUID, "< $ng_srv_uuid_file") ){
		while (<TMP_UUID>)
	             {
	             $serverUUID="$_";
	             }
	    close(TMP_UUID);
	    if ( $CheckOnly ){print " - $serverUUID";print_success}
	    CheckUUIDOwner;
	} else {
		if ( $CheckOnly ){print " - "}
    	print "Cannot Read UUID File";
		if ( $CheckOnly ){print_failure}else{print "\n"}
		CheckUUIDOwner;
		exit $ERRORS{"CRITICAL"};
	}
    
} else {
	my $ug =new Data::UUID;
	$serverUUID = $ug->to_string($ug->create());
	if (open(TMP_UUID, "> $ng_srv_uuid_file")){
		print TMP_UUID "$serverUUID";
    	close(TMP_UUID);
    	if ( $CheckOnly ){print " - $serverUUID";print_success}
    	if (! Check_perm($ng_srv_uuid_file, "nagios")){`chown nagios:nagios $ng_srv_uuid_file > 0 2>1`;}
    	CheckUUIDOwner;
	} else {
    	if ( $CheckOnly ){print " - "}
    	print "Cannot Create UUID File";
    	if ( $CheckOnly ){print_failure}else{print "\n"}
    	exit $ERRORS{"CRITICAL"};
    }
}

if ( $CheckOnly ){
	print "    * fqdn - $ngsrv_fqdn\n";
	print "    * IP address - $ngsrv_addr\n\n";
	
	print "Checking nagios command pipe";
	if ( -e $ng_pipe){print_success}else{print_warning}
	print "Checking Mailer";
	my @tmp_mailer = split(/ /,$mailer);
	if ( -e $tmp_mailer[0]  ){print_success}else{print_warning}
	
	exit 0;
}
else {
	if($DefaultOptionCritical){exit 1}
}

# Setting FQDN if needed
if (lc($ng_use_hostname_as_fqdn) eq 'yes') {
	$ng_FQDN = $ng_HOSTNAME;
}
if (lc($ng_use_alias_as_fqdn) eq 'yes') {
	$ng_FQDN = $ng_ALIAS;
}
# ---

# Clean up custom Macro to blank if not implemented in nagios
if ( $ng_FQDN =~ /^\$/ && $ng_FQDN =~ /\$$/ ){$ng_FQDN=''}
if ( $ng_CATEGORY =~ /^\$/ && $ng_CATEGORY =~ /\$$/ ){$ng_CATEGORY=''}
if ( $ng_GROUPASSIGNMENT =~ /^\$/ && $ng_GROUPASSIGNMENT =~ /\$$/ ){$ng_GROUPASSIGNMENT=''}
if ( $ng_DISABLE =~ /^\$/ && $ng_DISABLE =~ /\$$/ ){$ng_DISABLE='no'}
if ( $ng_DISABLE_ACK =~ /^\$/ && $ng_DISABLE_ACK =~ /\$$/ ){$ng_DISABLE_ACK='no'}
if ( $ng_NOTIFICATIONTYPE =~ /^\$/ && $ng_NOTIFICATIONTYPE =~ /\$$/ ){$ng_NOTIFICATIONTYPE='no'}

# Nagios V2 Backward compatibility - Macro Clean up
if ( $ng_EVENTID =~ /^\$/ && $ng_EVENTID =~ /\$$/ ){$ng_EVENTID=''}
if ( $ng_LASTEVENTID =~ /^\$/ && $ng_LASTEVENTID =~ /\$$/ ){$ng_LASTEVENTID=''}
if ( $ng_PROBLEMID =~ /^\$/ && $ng_PROBLEMID =~ /\$$/ ){$ng_PROBLEMID=''}
if ( $ng_LASTPROBLEMID =~ /^\$/ && $ng_LASTPROBLEMID =~ /\$$/ ){$ng_LASTPROBLEMID=''}
if ( $ng_LONG_OUTPUT =~ /^\$/ && $ng_LONG_OUTPUT =~ /\$$/ ){$ng_LONG_OUTPUT=''}
if ( $ng_HOSTGROUPNAMES =~ /^\$/ && $ng_HOSTGROUPNAMES =~ /\$$/ ){$ng_HOSTGROUPNAMES=''}
if ( $ng_SERVICEGROUPNAMES =~ /^\$/ && $ng_SERVICEGROUPNAMES =~ /\$$/ ){$ng_SERVICEGROUPNAMES=''}

# Primary Filter of Events ********************************************************
# *********************************************************************************

# Log Call From Here
logEvent($DEBUG,0,"<CALL> ".$0.$ARGSTRING);

# Exit on SOFT Event
if ($ng_StateType eq 'SOFT'){exit 0};

# Filter notification Type
if ($ng_NOTIFICATIONTYPE eq 'ACKNOWLEDGEMENT'){
	if (lc($ng_set_acknowledge_on_ticket_creation) eq 'yes' ) {
		exit 0;
	}
}

if($ng_State eq "WARNING"){exit 0;}

# Filter notification Type Array loop
foreach (@filter_notification) {
	if ( $_ eq $ng_NOTIFICATIONTYPE ){
		exit 0;
	}
}
# Filter if the Event Handler is disable with custom Macro
if (lc($ng_DISABLE) eq 'yes'){
	logEvent($INFO,0,"<FILTER> "."ITSM Event Handler is disable using '_DISABLE_ITSM' custom macro. Last Event Filtered.");
	exit 0;
}

# Filter DownTime If needed
if ($ng_DOWNTIME>0 and lc($ignore_event_on_downtime) eq 'yes'){
	logEvent($INFO,0,"<FILTER> "."$ng_HOSTNAME is in downtime. Last Event Filtered.");
	exit 0;
}

# *********************************************************************************
# *********************************************************************************

# Checking mandatory Fields #####################################################
if ( ! $ng_FQDN ){logEvent($ERROR,0,"No FQDN Specified\n"); exit 1;}
if ( ! $ng_DATETIME ){logEvent($ERROR,0,"No valid Date Specified\n"); exit 1;}
#################################################################################


my @Raw_SOAP_data;
# Build of the Generic SOAP data Param 
while ( my ($key, $value) = each(%Raw_SOAP_Param) ) {
	if ( $value =~ /^\$/ && $value =~ /\$$/ ){$value=''}
	push(@Raw_SOAP_data, SOAP::Data->name($key => $value));
}

# DO the ACTUAL WEB SERVICES CALL ------------------------------------------------
#

sub CallProperWebService {
	my ($error, $itsm_opened_incidents) = GetIncidents("OPENED");
	
	if ($error != $ERRORS{"OK"}){ return $error; }

	if (@$itsm_opened_incidents) {
			return(SendNewStateMessage(\@Raw_SOAP_data, $itsm_opened_incidents));
	} else {
		if($ng_State eq "OK" or $ng_State eq "UP"){
			if (lc($send_Recovery_as_normal_event) eq 'yes') {
				return(SendEventMessage(@Raw_SOAP_data));
			} elsif (lc($send_mail_on_Recovery) eq 'yes') {
				return(SendSpecialRecoveryEmail());
			}
		} else {
			if ((defined($ng_NOTIFICATIONNUMBER) && $ng_NOTIFICATIONNUMBER == 1) || (! defined ($ng_NOTIFICATIONNUMBER))){
				return(SendEventMessage(@Raw_SOAP_data));
			} elsif (lc($reopen_on_notification) eq 'yes'){
				#With PROBLEMID equal to this->PROBLEMID and newer than X days
				my ($error, $itsm_solved_incidents) = GetIncidents("SOLVED");
				
				if ($error == $ERRORS{"OK"} && @$itsm_solved_incidents) {
					return (SendReopenMessage(\@Raw_SOAP_data,$itsm_solved_incidents));
				} else {
					my ($error_closed, $itsm_closed_incidents) = GetIncidents("CLOSED");
					if ($error == $ERRORS{"OK"} && @$itsm_closed_incidents) {
						return (SendRecreateMessage(\@Raw_SOAP_data,$itsm_closed_incidents));
					} else {
						return(SendEventMessage(@Raw_SOAP_data));
					}
				}

				

			}
		}

	}
}

my $RETRY_COUNTER;
for ($RETRY_COUNTER = 1; $RETRY_COUNTER <= $ng_max_retry ; $RETRY_COUNTER++){
	
	if(CallProperWebService() == $ERRORS{"OK"}){last;}
	
	if ($RETRY_COUNTER < $ng_max_retry){
		print "Retrying in $ng_wait_retry Seconds...\n";
		sleep $ng_wait_retry;
	} else {
		my $subject = "An error occurred trying to create/modify an ITSM incident from Nagios\n"; 
		my $nagios_body = CreateNagiosMailBody();
		my $mailbody = "Error: $ERROR_STRING\n"; 
		$mailbody = $mailbody.$nagios_body;

		SendNotification($subject,$mailbody,$ng_email_contact_from,$ng_email_contact_to);
		logEvent($ERROR,0,"<CallProperWebService>".$ERROR_STRING);
	}
}

exit $ERRORS{"OK"};



# Subs #####################################################################################################


# ----
# $error_string = Error String 2 Log
sub logEvent{
	my ($level, $nagios_log, $_error_string) = @_;

	print "$_error_string\n";
	my $logger = get_logger("nagios2itsm");
	
    	if ($level == $DEBUG) {$logger->debug($_error_string);}
    	if ($level == $INFO) {$logger->info($_error_string);}
    	if ($level == $WARN) {$logger->warn($_error_string);}
    	if ($level == $ERROR) {$logger->error($_error_string);}
    	if ($level == $FATAL) {$logger->fatal($_error_string);}

 	if ($nagios_log == 1){
		set_comment($_error_string);
        	$ERROR_STRING = $_error_string;
	}	
}

# ----
# handle Soap Errors
sub soapError {
	my $soap = shift;
	my $res = shift;
	my $err;
	eval {$err = $res->faultstring};
	if( $err ) {
		push( @SOAP_ERRORS, "<SOAP ERROR> $err");
	}
	else {
		
		eval {$err = $soap->transport->status};
		if ($err){
			push( @SOAP_ERRORS, "<TRANSPORT ERROR> $err");
		}
		else {
			push( @SOAP_ERRORS, "<Unknown ERROR> ");
		}
	}
	return new SOAP::SOM;
}
sub CloneIncident {
	my($incident_id) = @_;

	my @work_info_params = ();

	my $soap = SOAP::Lite
                        -> on_fault( \&soapError )
                    -> uri($itsm_uri)
                    -> on_action( sub { join '/', 'http://schemas.xmlsoap.org/soap/envelope/', $_[1] } )
                    -> proxy($itsm_url_query, timeout => $itsm_timeout);

        my $methodName = $itsm_url_query_method;
        my $method = SOAP::Data->name($methodName)
            ->attr({
                "xmlns" => 'http://schemas.xmlsoap.org/soap/envelope/',
                "xmlns:urn" => 'HPD_Cust_IncidentInterface_WS',
        });

        # ref http://www.wlp-systems.de/soap-lite-and-ws-security.html
        # ------------------------------------------------------------
        my $header;
        if (lc($itsm_ws_security) eq 'yes') {
                $header = ws_authen($itsm_ws_login,$itsm_ws_password);
        }


        my @params = ( $header,
                        SOAP::Data->name(Incident_Number => $incident_id),
        );

        my $result;
        $result = $soap->call($method => @params);

        if (scalar( @SOAP_ERRORS ) > 0){
                logEvent($ERROR,0,"<$methodName> ".pop(@SOAP_ERRORS));
                return ($ERRORS{"CRITICAL"}, \@work_info_params);
        }
        else
        {
                unless ($result->fault) {

                        if (defined ($result->valueof('//HasError')) && $result->valueof('//HasError') eq "true"){
                                logEvent($ERROR,0,"<$methodName> <Responce Has Error> ".$result->valueof('//ErrorMessage'));
                		return ($ERRORS{"CRITICAL"}, \@work_info_params);
                        }
                        else {
				my $reported_source = $result->valueof('//Reported_Source');
				if ( $reported_source eq 'Self Service') {
					$reported_source = 'Other';
		         	} 
				@work_info_params = (
			   		   SOAP::Data->name(Categorization_Tier_1 =>  $result->valueof('//Categorization_Tier_1')),
		                           SOAP::Data->name(Categorization_Tier_2 =>  $result->valueof('//Categorization_Tier_2')),
                		           SOAP::Data->name(Categorization_Tier_3 =>  $result->valueof('//Categorization_Tier_3')),
		                           SOAP::Data->name(Closure_Manufacturer =>  $result->valueof('//Closure_Manufacturer')),
		                           SOAP::Data->name(Closure_Product_Category_Tier1 =>  $result->valueof('//Closure_Product_Category_Tier1')),
		                           SOAP::Data->name(Closure_Product_Category_Tier2 =>  $result->valueof('//Closure_Product_Category_Tier2')),
                		           SOAP::Data->name(Closure_Product_Category_Tier3 =>  $result->valueof('//Closure_Product_Category_Tier3')),
		                           SOAP::Data->name(Closure_Product_Model_Version =>  $result->valueof('//Closure_Product_Model_Version')),
		                           SOAP::Data->name(Closure_Product_Name =>  $result->valueof('//Closure_Product_Name')),
		                           SOAP::Data->name(Company =>  $result->valueof('//Company')),
		                           SOAP::Data->name(Summary =>  $result->valueof('//Summary')),
		                           SOAP::Data->name(Notes =>  $result->valueof('//Notes')),
		                           SOAP::Data->name(Impact =>  $result->valueof('//Impact')),
		                           SOAP::Data->name(Manufacturer =>  $result->valueof('//Manufacturer')),
		                           SOAP::Data->name(Product_Categorization_Tier_1 =>  $result->valueof('//Product_Categorization_Tier_1')),
		                           SOAP::Data->name(Product_Categorization_Tier_2 =>  $result->valueof('//Product_Categorization_Tier_2')),
		                           SOAP::Data->name(Product_Categorization_Tier_3 =>  $result->valueof('//Product_Categorization_Tier_3')),
		                           SOAP::Data->name(Product_Model_Version =>  $result->valueof('//Product_Model_Version')),
		                           SOAP::Data->name(Product_Name =>  $result->valueof('//Product_Name')),
		                           SOAP::Data->name(Reported_Source => $reported_source),
		                           SOAP::Data->name(Resolution =>  $result->valueof('//Resolution')),
		                           SOAP::Data->name(Resolution_Category =>  $result->valueof('//Resolution_Category')),
		                           SOAP::Data->name(Resolution_Category_Tier_2 =>  $result->valueof('//Resolution_Category_Tier_2')),
		                           SOAP::Data->name(Resolution_Category_Tier_3 =>  $result->valueof('//Resolution_Category_Tier_3')),
		                           SOAP::Data->name(Resolution_Method => ''),
		                           SOAP::Data->name(Service_Type => $result->valueof('//Service_Type')),
		                           SOAP::Data->name(Status =>  $result->valueof('//Status')),
		                           SOAP::Data->name(Urgency =>  $result->valueof('//Urgency')),
		                           SOAP::Data->name(Action =>  "MODIFY"),
					   SOAP::Data->name(Work_Info_Summary => $result->valueof('//Work_Info_Summary')),
         				   SOAP::Data->name(Work_Info_Notes => $result->valueof('//Work_Info_Notes')),
         				   SOAP::Data->name(Work_Info_Type => $result->valueof('//Work_Info_Type')),
         				   SOAP::Data->name(Work_Info_Date => $result->valueof('//Work_Info_Date')),
         				   SOAP::Data->name(Work_Info_Source => $result->valueof('//Work_Info_Source')),
                                           SOAP::Data->name(Work_Info_Locked =>  $result->valueof('//Work_Info_Locked')),
         				   SOAP::Data->name(Work_Info_View_Access => $result->valueof('//Work_Info_View_Access')),	
         				   SOAP::Data->name(Incident_Number => $incident_id),	
		                           SOAP::Data->name(Status_Reason =>  $result->valueof('//Status_Reason')),
		                           SOAP::Data->name(ServiceCI =>  $result->valueof('//ServiceCI')),
		                           SOAP::Data->name(ServiceCI_ReconID =>  $result->valueof('//ServiceCI_ReconID')),
		                           SOAP::Data->name(HPD_CI =>  $result->valueof('//z1D_CI_FormName')),
		                           SOAP::Data->name(HPD_CI_ReconID =>  $result->valueof('//z1D_CI_FormName')),
		                           SOAP::Data->name(HPD_CI_FormName =>  $result->valueof('//z1D_CI_FormName')),
		                           SOAP::Data->name(z1D_CI_FormName =>  $result->valueof('//z1D_CI_FormName')),
				);
				logEvent($DEBUG,0,"<CloneIncident> Cloning incident $incident_id\n");
                		return ($ERRORS{"OK"}, \@work_info_params);
                        }

                } else {
                        logEvent($ERROR,0,"<$methodName> <".$result->faultcode."> ".$result->faultstring);
                	return ($ERRORS{"CRITICAL"}, \@work_info_params);
                }
        }
        return ($ERRORS{"CRITICAL"}, \@work_info_params);
	
}
sub CloneIncidentCreation {
	my($incident_id) = @_;

	my @soap_params = ();

	my $soap = SOAP::Lite
                        -> on_fault( \&soapError )
                    -> uri($itsm_uri)
                    -> on_action( sub { join '/', 'http://schemas.xmlsoap.org/soap/envelope/', $_[1] } )
                    -> proxy($itsm_url_query, timeout => $itsm_timeout);

        my $methodName = $itsm_url_query_method;
        my $method = SOAP::Data->name($methodName)
            ->attr({
                "xmlns" => 'http://schemas.xmlsoap.org/soap/envelope/',
                "xmlns:urn" => 'HPD_Cust_IncidentInterface_WS',
        });

        # ref http://www.wlp-systems.de/soap-lite-and-ws-security.html
        # ------------------------------------------------------------
        my $header;
        if (lc($itsm_ws_security) eq 'yes') {
                $header = ws_authen($itsm_ws_login,$itsm_ws_password);
        }


        my @params = ( $header,
                        SOAP::Data->name(Incident_Number => $incident_id),
        );

        my $result;
        $result = $soap->call($method => @params);

        if (scalar( @SOAP_ERRORS ) > 0){
                logEvent($ERROR,0,"<$methodName> ".pop(@SOAP_ERRORS));
                return ($ERRORS{"CRITICAL"}, \@soap_params);
        }
        else
        {
                unless ($result->fault) {

                        if (defined ($result->valueof('//HasError')) && $result->valueof('//HasError') eq "true"){
                                logEvent($ERROR,0,"<$methodName> <Responce Has Error> ".$result->valueof('//ErrorMessage'));
                		return ($ERRORS{"CRITICAL"}, \@soap_params);
                        }
                        else {
				my $reported_source = $result->valueof('//Reported_Source');
				if ( $reported_source eq 'Self Service') {
					$reported_source = 'Other';
		         	} 
				@soap_params = (
					   SOAP::Data->name(Assigned_Group => $result->valueof('//Assigned_Group')),
                       			   SOAP::Data->name(Assigned_Support_Company =>  $result->valueof('//Assigned_Support_Company')),
			   		   SOAP::Data->name(Categorization_Tier_1 =>  $result->valueof('//Categorization_Tier_1')),
		                           SOAP::Data->name(Categorization_Tier_2 =>  $result->valueof('//Categorization_Tier_2')),
                		           SOAP::Data->name(Categorization_Tier_3 =>  $result->valueof('//Categorization_Tier_3')),
		                           SOAP::Data->name(Closure_Manufacturer =>  $result->valueof('//Closure_Manufacturer')),
		                           SOAP::Data->name(Closure_Product_Category_Tier1 =>  $result->valueof('//Closure_Product_Category_Tier1')),
		                           SOAP::Data->name(Closure_Product_Category_Tier2 =>  $result->valueof('//Closure_Product_Category_Tier2')),
                		           SOAP::Data->name(Closure_Product_Category_Tier3 =>  $result->valueof('//Closure_Product_Category_Tier3')),
		                           SOAP::Data->name(Closure_Product_Model_Version =>  $result->valueof('//Closure_Product_Model_Version')),
		                           SOAP::Data->name(Closure_Product_Name =>  $result->valueof('//Closure_Product_Name')),
                       			   SOAP::Data->name(Department =>  $result->valueof('//Department_Name')),
                       			   SOAP::Data->name(First_Name =>  $result->valueof('//First_Name')),
                       			   SOAP::Data->name(Impact =>  $result->valueof('//Impact')),
                       			   SOAP::Data->name(Last_Name =>  $result->valueof('//Last_Name')),
		                           SOAP::Data->name(Product_Categorization_Tier_1 =>  $result->valueof('//Product_Categorization_Tier_1')),
		                           SOAP::Data->name(Product_Categorization_Tier_2 =>  $result->valueof('//Product_Categorization_Tier_2')),
		                           SOAP::Data->name(Product_Categorization_Tier_3 =>  $result->valueof('//Product_Categorization_Tier_3')),
		                           SOAP::Data->name(Product_Model_Version =>  $result->valueof('//Product_Model_Version')),
		                           SOAP::Data->name(Product_Name =>  $result->valueof('//Product_Name')),
                       			   SOAP::Data->name(Reported_Source =>  $reported_source),
		                           SOAP::Data->name(Resolution =>  $result->valueof('//Resolution')),
                       			   SOAP::Data->name(Service_Type =>  $result->valueof('//Service_Type')),
                       			   SOAP::Data->name(Status => 'New'),
                       			   SOAP::Data->name(Action => 'CREATE'),
                       			   SOAP::Data->name(Create_Request => 'No'),
                       			   SOAP::Data->name(Summary => $result->valueof('//Summary')),
                       			   SOAP::Data->name(Notes => $result->valueof('//Notes')),
                       			   SOAP::Data->name(Urgency => $result->valueof('//Urgency')),
					   SOAP::Data->name(Work_Info_Summary => $result->valueof('//Work_Info_Summary')),
         				   SOAP::Data->name(Work_Info_Notes => $result->valueof('//Work_Info_Notes')),
         				   SOAP::Data->name(Work_Info_Type => $result->valueof('//Work_Info_Type')),
         				   SOAP::Data->name(Work_Info_Date => $result->valueof('//Work_Info_Date')),
         				   SOAP::Data->name(Work_Info_Source => $result->valueof('//Work_Info_Source')),
                                           SOAP::Data->name(Work_Info_Locked =>  $result->valueof('//Work_Info_Locked')),
         				   SOAP::Data->name(Work_Info_View_Access => $result->valueof('//Work_Info_View_Access')),	
         				   SOAP::Data->name(Incident_Number => $incident_id),	
		                           SOAP::Data->name(Status_Reason =>  $result->valueof('//Status_Reason')),
		                           SOAP::Data->name(ServiceCI =>  $result->valueof('//ServiceCI')),
		                           SOAP::Data->name(ServiceCI_ReconID =>  $result->valueof('//ServiceCI_ReconID')),
		                           SOAP::Data->name(HPD_CI =>  $result->valueof('//z1D_CI_FormName')),
		                           SOAP::Data->name(HPD_CI_ReconID =>  $result->valueof('//z1D_CI_FormName')),
		                           SOAP::Data->name(HPD_CI_FormName =>  $result->valueof('//z1D_CI_FormName')),
		                           SOAP::Data->name(z1D_CI_FormName =>  $result->valueof('//z1D_CI_FormName')),
				);
				logEvent($DEBUG,0,"<CloneIncident> Cloning incident $incident_id\n");
                		return ($ERRORS{"OK"}, \@soap_params);
                        }

                } else {
                        logEvent($ERROR,0,"<$methodName> <".$result->faultcode."> ".$result->faultstring);
                	return ($ERRORS{"CRITICAL"}, \@soap_params);
                }
        }
        return ($ERRORS{"CRITICAL"}, \@soap_params);
	
}
sub GetIncidents {
	my ($query_type) = @_;

	my @Incidents = ();
	
	my $soap = SOAP::Lite
                        -> on_fault( \&soapError )
                    -> uri($itsm_uri)
                    -> on_action( sub { join '/', 'http://schemas.xmlsoap.org/soap/envelope/'} )
                    -> proxy($itsm_url_queryList, timeout => $itsm_timeout);

        my $methodName = $itsm_url_queryList_method;
        my $method = SOAP::Data->name($methodName)
            ->attr({
                "xmlns" => 'http://schemas.xmlsoap.org/soap/envelope/',
                "xmlns:urn" => 'HPD_Cust_IncidentInterface_WS',
        });

        # ref http://www.wlp-systems.de/soap-lite-and-ws-security.html
        # ------------------------------------------------------------
        my $header;
        if (lc($itsm_ws_security) eq 'yes') {
                $header = ws_authen($itsm_ws_login,$itsm_ws_password);
        }
	
	#Query must be tunned to get similar incidents. A new field should be added in ITSM	
	my $query;
	if ($query_type eq 'OPENED'){
		$query = "'Status'=\"Assigned\""; 
	} elsif ($query_type eq 'SOLVED'){ 
		$query = "'Status'=\"Solved\""; 
	} else {
		$query = "'Status'=\"Closed\""; 
	}

        my @params = ( $header,
			SOAP::Data->name(Qualification => "$query"),
                        SOAP::Data->name(startRecord => 0),
			SOAP::Data->name(maxLimit => 1),
        );
 	my $result;
        $result = $soap->call($method => @params);

        if (scalar( @SOAP_ERRORS ) > 0){
                logEvent($ERROR,0,"<$methodName> ".pop(@SOAP_ERRORS));
		return ($ERRORS{"CRITICAL"}, \@Incidents);
        }
        else
        {
                unless ($result->fault) {

                        if (defined ($result->valueof('//HasError')) && $result->valueof('//HasError') eq "true"){
                                logEvent($ERROR,0,"<$methodName> <Responce Has Error> ".$result->valueof('//ErrorMessage'));
                        }
                        else {
				my $index = 0;
                                my @all_incidents = $result->valueof('//Incident_Number');
                                my @Dates = $result->valueof('//Reported_Date');
				foreach my $incident (@all_incidents){
					if (ValidIncidentByDate($Dates[$index]) == 0){
						push (@Incidents, $incident);	
					} else {
						logEvent($DEBUG,0,"<GetExistentIncidents> Incident discarded by date: ".$incident);
					}
					$index += 1;	
				}
				logEvent($DEBUG,0,"<GetExistentIncidents> Incidents: ".map {"$_ "} @Incidents);
				return ($ERRORS{"OK"}, \@Incidents);
                        }

                } else {
                        logEvent($ERROR,0,"<$methodName> <".$result->faultcode."> ".$result->faultstring);
			return ($ERRORS{"CRITICAL"}, \@Incidents);
                }
        }
	return ($ERRORS{"CRITICAL"}, \@Incidents);
	

} #GetIncidents

sub ValidIncidentByDate{
	my ($date) = @_;

	my $strp = DateTime::Format::Strptime->new(
        	pattern   => '%Y-%m-%dT%H:%M:%S',
        	locale    => 'en_US',
        	time_zone => 'CET',
	);

	my @date_array = split('\+',$date);
	my $date_no_offset = $date_array[0];

	my $dt = $strp->parse_datetime($date_no_offset);
	$strp->format_datetime($dt);
	my $dt_epoch = $dt->epoch();

	my $dt_now = DateTime->now;
	my $dt_now_epoch = $dt_now->epoch();

	if (($dt_now_epoch - $dt_epoch) < $itsm_max_days){
		#Valid incident
		return 0;
	} else {
		return 1;
	}
}

sub SendSpecialRecoveryEmail {

	my $subject = "Recovery from Nagios without ITSM incident";
	
	my $nagios_body = CreateNagiosMailBody();
	my $mailbody = "A recovery event has been received from Nagios, but there isn't any corresponding ITSM incident\n";
	$mailbody = $mailbody."No action is taken. No new incident will be created\n";
	$mailbody = $mailbody.$nagios_body;

	SendNotification($subject,$mailbody,$ng_email_contact_from,$ng_email_contact_to);
        logEvent($WARN,0,"<SendSpecialRecoveryEmail>".$mailbody);

	return $ERRORS{"OK"}; 
}

sub CreateNagiosMailBody {
			my $mailbody = "";
			$mailbody = $mailbody."* Call Details \n\n";
                   	$mailbody = $mailbody." FQDN : $ng_FQDN \n";
                        $mailbody = $mailbody." CATEGORY : $ng_CATEGORY \n";
                        $mailbody = $mailbody." GROUPASSIGNEMENT : $ng_GROUPASSIGNMENT \n";
                        $mailbody = $mailbody." HOSTNAME : $ng_HOSTNAME \n";
                        $mailbody = $mailbody." HOSTADDRESS : $ng_HOSTADDRESS \n";
                        $mailbody = $mailbody." ALIAS : $ng_ALIAS \n";
                        $mailbody = $mailbody." SERVICENAME : $ng_SERVICENAME \n";
                        $mailbody = $mailbody." HOST GROUP NAMES : $ng_HOSTGROUPNAMES \n";
                        $mailbody = $mailbody." SERVICE GROUP NAMES : $ng_SERVICEGROUPNAMES \n";
                        $mailbody = $mailbody." State : $ng_State \n";
                        $mailbody = $mailbody." StateType : $ng_StateType \n";
                        $mailbody = $mailbody." Attempt : $ng_Attempt \n";
                        $mailbody = $mailbody." EVENTID : $ng_EVENTID \n";
                        $mailbody = $mailbody." LASTEVENTID : $ng_LASTEVENTID \n";
                        $mailbody = $mailbody." PROBLEMID : $ng_PROBLEMID \n";
                        $mailbody = $mailbody." LASTPROBLEMID : $ng_LASTPROBLEMID \n";
                        $mailbody = $mailbody." GMT DATE/TIME : $ng_DATETIME\n";
                        $mailbody = $mailbody." OUTPUT : $ng_OUTPUT \n";
                        $mailbody = $mailbody." LONG OUTPUT : $ng_LONG_OUTPUT \n";

			return $mailbody;
}

sub CreateNagioSubject {

	my $message = "";	

	if($ng_State eq "OK" or $ng_State eq "UP"){
                if ($ng_SERVICENAME eq ''){
                        $message = $message."Host $ng_HOSTNAME is UP\n";
                } else  {
                        $message = $message."Service $ng_SERVICENAME from host $ng_HOSTNAME is OK\n";
                }
        } else {
                if ($ng_SERVICENAME eq ''){
                        $message = $message."Host $ng_HOSTNAME is DOWN/UNREACHABLE\n";
                } else  {
                        $message = $message."Service $ng_SERVICENAME from host $ng_HOSTNAME is in CRITICAL state\n";
                }
        }
	return $message;
}
sub CreateNagiosMessage {

	my $message = CreateNagioSubject();

	$message = $message."Host: $ng_HOSTNAME\n";
	$message = $message."Service: $ng_SERVICENAME\n";
	$message = $message."State: $ng_State\n";
	$message = $message."Date: $ng_DATETIME\n";
	$message = $message."HostGroups: $ng_HOSTGROUPNAMES\n";
	$message = $message."ServiceGroups: $ng_SERVICEGROUPNAMES\n";
	$message = $message."Output:\n$ng_OUTPUT\n$ng_LONG_OUTPUT\n";

	return $message;
}
# *************************************************************************************************************

# ----
#
sub SendNewStateMessage {
	my ($soap_raw, $itsm_existent_incidents) = @_;

	my $message = CreateNagiosMessage();

	foreach my $incident_id (@$itsm_existent_incidents){
		my ($error, $soap_params) = CloneIncident($incident_id);

		@$soap_params[29] = SOAP::Data->name(Work_Info_Summary => $itsm_default_worknote_summary);
		@$soap_params[30] = SOAP::Data->name(Work_Info_Notes => $message);
		@$soap_params[31] = SOAP::Data->name(Work_Info_Type => $itsm_default_worknote_type);
		@$soap_params[32] = SOAP::Data->name(Work_Info_Date => '');
		@$soap_params[33] = SOAP::Data->name(Work_Info_Source => $itsm_default_worknote_source);
		@$soap_params[34] = SOAP::Data->name(Work_Info_Locked => $itsm_default_worknote_locked);
		@$soap_params[35] = SOAP::Data->name(Work_Info_View_Access => $itsm_default_worknote_access);

		if($error == $ERRORS{"OK"}){
			 my $soap = SOAP::Lite
                        		-> on_fault( \&soapError )
                    			-> uri($itsm_uri)
                    			-> on_action( sub { join '/', 'http://schemas.xmlsoap.org/soap/envelope/'} )
                    			-> proxy($itsm_url_recovery, timeout => $itsm_timeout);

        		my $methodName = $itsm_url_recovery_method;
        		my $method = SOAP::Data->name($methodName)
            			->attr({
                			"xmlns" => 'http://schemas.xmlsoap.org/soap/envelope/',
                			"xmlns:urn" => 'HPD_Cust_IncidentInterface_Create_WS',
        			});

        		# ref http://www.wlp-systems.de/soap-lite-and-ws-security.html
        		# ------------------------------------------------------------
        		my $header;
        		if (lc($itsm_ws_security) eq 'yes') {
                		$header = ws_authen($itsm_ws_login,$itsm_ws_password);
        		}

			my @params = ($header,
					@$soap_params,
					$soap_raw,
			);
        		my $result;
        		$result = $soap->call($method => @params);

        		if (scalar( @SOAP_ERRORS ) > 0){
                		logEvent($ERROR,1,"<$methodName> ".pop(@SOAP_ERRORS));
		 		return ($ERRORS{"CRITICAL"});	
        		} 
			else {
                		unless ($result->fault) {

                        		if (defined ($result->valueof('//HasError')) && $result->valueof('//HasError') eq "true"){
                                		logEvent($ERROR,1,"<$methodName> <Response Has Error> ".$result->valueof('//ErrorMessage'));
                                		#print $result->valueof('//StackTrace')."\n";
		 				return ($ERRORS{"CRITICAL"});	
                        		}
                        		else {	
						logEvent($INFO,0,"<$methodName> ITSM Incident Number".$incident_id." updated");

                            			my $ng_cust_msg = "An incident was updated in ITSM with id: ";
                            			if ($itsm_ticket_link){
                                			$ng_cust_msg=$ng_cust_msg."<A HREF=\'$itsm_ticket_link$incident_id\' target=\"_blank\">$incident_id</A>\n";
                            			} else {
                                			$ng_cust_msg=$ng_cust_msg."$incident_id\n";
                            			}

                            			# Set ACK or Comment with Nagios CMD
                                                if (lc($ng_set_acknowledge_on_ticket_creation) eq 'yes' ) {
                                                	if (lc($ng_DISABLE_ACK) eq 'yes'){
                                                		logEvent($INFO,0,"<Set_Acknowledge> "."Acknowledge is disable using '_DISABLE_ACK' custom macro. Simple comment will be set instead.");
                                                		set_comment($ng_cust_msg);
                                                	} else {
                                                		set_acknowledge($ng_cust_msg);
                                                	}
                                                } else {
                                                	set_comment($ng_cust_msg);
                                                }
						if (lc($send_mail_on_worknote) eq 'yes') {
							my $subject = "New WorkNote added to incident $incident_id";

							my $nagios_message = CreateNagiosMessage();
						        my $mailbody = "A new WorkNote hass been added to the ITSM incident $incident_id\n";
						        $mailbody = $mailbody.$nagios_message;

						        SendNotification($subject,$mailbody,$ng_email_contact_from,$ng_email_contact_to);
						}
					}
				} else {
					logEvent($ERROR,1,"<$methodName> <".$result->faultcode."> ".$result->faultstring);
		 			return($ERRORS{"CRITICAL"});	
				}	
			}	
		} else {
                        logEvent($ERROR,0,"<SendNewStateMessage>Incident number ".$incident_id." couldn't be cloned");
		 	return ($ERRORS{"CRITICAL"});	
		}	
	}
	return($ERRORS{"OK"});	
	
} # SendRecoveryMessage

sub SendReopenMessage{
	my ($soap_raw, $itsm_existent_incidents) = @_;

	foreach my $incident_id (@$itsm_existent_incidents){
		my ($error, $soap_params) = CloneIncident($incident_id);

		@$soap_params[26] = SOAP::Data->name(Status => 'Assigned');
		push (@$soap_params, SOAP::Data->name(Assignee => ''));

		if($error == $ERRORS{"OK"}){
			 my $soap = SOAP::Lite
                        		-> on_fault( \&soapError )
                    			-> uri($itsm_uri)
                    			-> on_action( sub { join '/', 'http://schemas.xmlsoap.org/soap/envelope/'} )
                    			-> proxy($itsm_url_recovery, timeout => $itsm_timeout);

        		my $methodName = $itsm_url_recovery_method;
        		my $method = SOAP::Data->name($methodName)
            			->attr({
                			"xmlns" => 'http://schemas.xmlsoap.org/soap/envelope/',
                			"xmlns:urn" => 'HPD_Cust_IncidentInterface_Create_WS',
        			});

        		# ref http://www.wlp-systems.de/soap-lite-and-ws-security.html
        		# ------------------------------------------------------------
        		my $header;
        		if (lc($itsm_ws_security) eq 'yes') {
                		$header = ws_authen($itsm_ws_login,$itsm_ws_password);
        		}

			my @params = ($header,
					@$soap_params,
					$soap_raw,
			);
        		my $result;
        		$result = $soap->call($method => @params);

        		if (scalar( @SOAP_ERRORS ) > 0){
                		logEvent($ERROR,1,"<$methodName> ".pop(@SOAP_ERRORS));
		 		return ($ERRORS{"CRITICAL"});	
        		} 
			else {
                		unless ($result->fault) {

                        		if (defined ($result->valueof('//HasError')) && $result->valueof('//HasError') eq "true"){
                                		logEvent($ERROR,1,"<$methodName> <Response Has Error> ".$result->valueof('//ErrorMessage'));
                                		#print $result->valueof('//StackTrace')."\n";
		 				return ($ERRORS{"CRITICAL"});	
                        		}
                        		else {	
						logEvent($INFO,0,"<$methodName> ITSM Incident Number".$incident_id." reopened");

                            			my $ng_cust_msg = "An incident was reopened in ITSM with id: ";
                            			if ($itsm_ticket_link){
                                			$ng_cust_msg=$ng_cust_msg."<A HREF=\'$itsm_ticket_link$incident_id\' target=\"_blank\">$incident_id</A>\n";
                            			} else {
                                			$ng_cust_msg=$ng_cust_msg."$incident_id\n";
                            			}

                            			# Set ACK or Comment with Nagios CMD
                                                if (lc($ng_set_acknowledge_on_ticket_creation) eq 'yes' ) {
                                                	if (lc($ng_DISABLE_ACK) eq 'yes'){
                                                		logEvent($INFO,0,"<Set_Acknowledge> "."Acknowledge is disable using '_DISABLE_ACK' custom macro. Simple comment will be set instead.");
                                                		set_comment($ng_cust_msg);
                                                	} else {
                                                		set_acknowledge($ng_cust_msg);
                                                	}
                                                } else {
                                                	set_comment($ng_cust_msg);
                                                }
					}
				} else {
					logEvent($ERROR,1,"<$methodName> <".$result->faultcode."> ".$result->faultstring);
		 			return($ERRORS{"CRITICAL"});	
				}	
			}	
		} else {
                        logEvent($ERROR,0,"<SendNewStateMessage>Incident number ".$incident_id." couldn't be cloned");
		 	return ($ERRORS{"CRITICAL"});	
		}	
	}
	return($ERRORS{"OK"});	
	
}

sub SendRecreateMessage{
	my ($soap_raw, $itsm_existent_incidents) = @_;

	foreach my $incident_id (@$itsm_existent_incidents){
		my ($error, $soap_params) = CloneIncidentCreation($incident_id);


		if($error == $ERRORS{"OK"}){
			my $soap = SOAP::Lite
				-> on_fault( \&soapError )
		    		-> uri($itsm_uri)
		    		-> on_action( sub { join '/', 'http://schemas.xmlsoap.org/soap/envelope/', $_[1] } )
		    		-> proxy($itsm_url, timeout => $itsm_timeout);

			my $methodName = $itsm_url_method;
			my $method = SOAP::Data->name($methodName)
	    			->attr({
					"xmlns" => 'http://schemas.xmlsoap.org/soap/envelope/',
					"xmlns:urn" => 'HPD_Cust_IncidentInterface_Create_WS',
			});
	
        		# ref http://www.wlp-systems.de/soap-lite-and-ws-security.html
        		# ------------------------------------------------------------
        		my $header;
        		if (lc($itsm_ws_security) eq 'yes') {
                		$header = ws_authen($itsm_ws_login,$itsm_ws_password);
        		}

			my @params = ($header,
					@$soap_params,
					$soap_raw,
			);
        		my $result;
        		$result = $soap->call($method => @params);

        		if (scalar( @SOAP_ERRORS ) > 0){
                		logEvent($ERROR,1,"<$methodName> ".pop(@SOAP_ERRORS));
		 		return ($ERRORS{"CRITICAL"});	
        		} 
			else {
                		unless ($result->fault) {

                        		if (defined ($result->valueof('//HasError')) && $result->valueof('//HasError') eq "true"){
                                		logEvent($ERROR,1,"<$methodName> <Response Has Error> ".$result->valueof('//ErrorMessage'));
                                		#print $result->valueof('//StackTrace')."\n";
		 				return ($ERRORS{"CRITICAL"});	
                        		}
                        		else {	
						logEvent($INFO,0,"<$methodName> ITSM Incident Number".$incident_id." reopened");

                            			my $ng_cust_msg = "An incident was reopened in ITSM with id: ";
                            			if ($itsm_ticket_link){
                                			$ng_cust_msg=$ng_cust_msg."<A HREF=\'$itsm_ticket_link$incident_id\' target=\"_blank\">$incident_id</A>\n";
                            			} else {
                                			$ng_cust_msg=$ng_cust_msg."$incident_id\n";
                            			}

                            			# Set ACK or Comment with Nagios CMD
                                                if (lc($ng_set_acknowledge_on_ticket_creation) eq 'yes' ) {
                                                	if (lc($ng_DISABLE_ACK) eq 'yes'){
                                                		logEvent($INFO,0,"<Set_Acknowledge> "."Acknowledge is disable using '_DISABLE_ACK' custom macro. Simple comment will be set instead.");
                                                		set_comment($ng_cust_msg);
                                                	} else {
                                                		set_acknowledge($ng_cust_msg);
                                                	}
                                                } else {
                                                	set_comment($ng_cust_msg);
                                                }
					}
				} else {
					logEvent($ERROR,1,"<$methodName> <".$result->faultcode."> ".$result->faultstring);
		 			return($ERRORS{"CRITICAL"});	
				}	
			}	
		} else {
                        logEvent($ERROR,0,"<SendNewStateMessage>Incident number ".$incident_id." couldn't be cloned");
		 	return ($ERRORS{"CRITICAL"});	
		}	
	}
	return($ERRORS{"OK"});	
	
}
#******************************************************************************************

sub SendEventMessage {
	
	my $soap = SOAP::Lite
			-> on_fault( \&soapError )
		    -> uri($itsm_uri)
		    -> on_action( sub { join '/', 'http://schemas.xmlsoap.org/soap/envelope/', $_[1] } )
		    -> proxy($itsm_url, timeout => $itsm_timeout);

	my $methodName = $itsm_url_method;
	my $method = SOAP::Data->name($methodName)
	    ->attr({
		"xmlns" => 'http://schemas.xmlsoap.org/soap/envelope/',
		"xmlns:urn" => 'HPD_Cust_IncidentInterface_Create_WS',
	});
	
	# ref http://www.wlp-systems.de/soap-lite-and-ws-security.html
	# ------------------------------------------------------------
	my $header;
	if (lc($itsm_ws_security) eq 'yes') {
		$header = ws_authen($itsm_ws_login,$itsm_ws_password);
	}

	my ($impact,$urgency) = compute_priority($ng_SERVICENAME, $ng_HOSTNAME);	
	my $summary = CreateNagioSubject();
	my $notes = CreateNagiosMessage();
	
	my @params = ( $header,
	               SOAP::Data->name(Assigned_Group => $ng_GROUPASSIGNMENT),
	               SOAP::Data->name(Assigned_Support_Company => $itsm_default_company),
	               SOAP::Data->name(First_Name => $itsm_default_firstName),
	               SOAP::Data->name(Impact => $impact),
	               SOAP::Data->name(Last_Name => $itsm_default_lastName),
	               SOAP::Data->name(Reported_Source => $itsm_default_source),
	               SOAP::Data->name(Service_Type => $itsm_default_serviceType),
	               SOAP::Data->name(Status => 'New'),
	               SOAP::Data->name(Action => 'CREATE'),
	               SOAP::Data->name(Create_Request => 'No'),
	               SOAP::Data->name(Summary => $summary),
	               SOAP::Data->name(Notes => $notes),
	               SOAP::Data->name(Urgency => $urgency),
	               @_,
	);

	my $result;
	$result = $soap->call($method => @params);
	
	if (scalar( @SOAP_ERRORS ) > 0){
		logEvent($ERROR,1,"<$methodName> ".pop(@SOAP_ERRORS));
		return $ERRORS{"CRITICAL"};
	}
	else
	{
		unless ($result->fault) {
			
			if (defined ($result->valueof('//HasError')) && $result->valueof('//HasError') eq "true"){
				logEvent($ERROR,1,"<$methodName> <Response Has Error> ".$result->valueof('//ErrorMessage'));
				#print $result->valueof('//StackTrace')."\n";
				return $ERRORS{"CRITICAL"};
			}
			else {
				my $itsm_caseID = '';
				#$itsm_caseID = $result->valueof('//IncidentList/Incident/IncidentNumber');
				my @Incidents = $result->valueof('//Incident_Number');
				print @Incidents;
				print "\n";
				foreach my $Incident (@Incidents)
				{
				   $itsm_caseID=$itsm_caseID." ".$Incident;
				}						
			    logEvent($INFO,0,"<$methodName> ITSM Incident Number".$itsm_caseID." created or updated");
			    
			    my $ng_cust_msg = "An incident was opened in ITSM with id: ";
			    if ($itsm_ticket_link){
			    	$ng_cust_msg=$ng_cust_msg."<A HREF=\'$itsm_ticket_link$itsm_caseID\' target=\"_blank\">$itsm_caseID</A>\n";	
			    } else {
			    	$ng_cust_msg=$ng_cust_msg."$itsm_caseID\n";
			    } 
			    
			    # Set ACK or Comment with Nagios CMD
			    if (lc($ng_set_acknowledge_on_ticket_creation) eq 'yes' ) {
			    	if (lc($ng_DISABLE_ACK) eq 'yes'){
						logEvent($INFO,0,"<Set_Acknowledge> "."Acknowledge is disable using '_DISABLE_ACK' custom macro. Simple comment will be set instead.");
						set_comment($ng_cust_msg);
					} else {
			    		set_acknowledge($ng_cust_msg);
					}
			    } else {
			    	set_comment($ng_cust_msg);
			    }
			}
			 
		} else {
			logEvent($ERROR,1,"<$methodName> <".$result->faultcode."> ".$result->faultstring);
		    return $ERRORS{"CRITICAL"};
		}
	}
	return $ERRORS{"OK"};
	
} # SendEventMessage

sub compute_priority {
	my ($service,$host) = @_;

	my $type = 'SERVICE';
	my $impact;
	my $urgency;

	if (!defined ($service) || $service eq '') {$type = 'HOST'};

	if ($type eq 'SERVICE') {
		$impact = $itsm_default_service_impact;
		$urgency = $itsm_default_service_urgency;	
	} else {
		$impact = $itsm_default_host_impact;
		$urgency = $itsm_default_host_urgency;	
	}
	
	return ($impact,$urgency);
}

sub SOAP::Transport::HTTP::Client::get_basic_credentials {
   return 'username' => 'password';
}

sub xml_quote {
    my ($value) = @_;
    $value =~ s/&/&amp;/;
    $value =~ s/</&lt;/;
    $value =~ s/>/&gt;/;
    $value;
}

sub _complex_type {
    my ($name,@childs) = @_;
    my $data = SOAP::Data->new( name => $name );
    $data->value( \SOAP::Data->value(@childs));
    #$data->value( \SOAP::Data->value($_[1], $_[2], $_[3], $_[4]));
    $data;
}

sub _typeless {
    my ($name,$value) = @_;
    my $data = SOAP::Data->new( name => $name );

    $value = xml_quote($value);

    $data->value( $value );
    $data->type( "" );
    $data;
}

sub timestamp {
    my ($sec,$min,$hour,$mday,$mon,$year,undef,undef,undef) = gmtime(time);
    $mon++;
    $year = $year + 1900;
    return sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ",$year,$mon,$mday,$hour,$min,$sec);
}
sub timeConvert {
	my ($TimeParam) = @_;
    my ($sec,$min,$hour,$mday,$mon,$year,undef,undef,undef) = gmtime($TimeParam);
    $mon++;
    $year = $year + 1900;
    return sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ",$year,$mon,$mday,$hour,$min,$sec);
}

sub create_generator {
    my ($name,$start_with) = @_;
    my $i = $start_with;
    return sub {  $name . ++$i; };
}

sub ws_authen {
    my($username,$passwort,$nonce_generator) = @_;
    if(!defined($nonce_generator)) {
        $nonce_generator = \&default_nonce_generator;
    }
    my $nonce = $nonce_generator->();
    my $timestamp = timestamp();

    my $pwDigest =  Digest::SHA1::sha1( $nonce . $timestamp . $passwort );
    my $passwortHash = MIME::Base64::encode_base64($pwDigest,"");
    my $nonceHash = MIME::Base64::encode_base64($nonce,"");

    my $auth = SOAP::Header->new( name => "AuthenticationInfo" );

    $auth->value( \SOAP::Data->value(
            _typeless("userName",$username),
            _typeless("password",$passwort),
       )
    );
    $auth;
}

# Here we acknowledge the problem in Nagios
sub set_acknowledge
{
	my ($NG_ACK_PARAM) = @_;
    my $NG_ACK_MSG="";
    
    if (-e $ng_pipe)
	{ 
	    if (open(NG_CMD, ">> $ng_pipe")){
	    
		    my $now = time();
		    if (!$ng_SERVICENAME) {
		       # ACKNOWLEDGE_HOST_PROBLEM;<host_name>;<sticky>;<notify>;<persistent>;<author>;<comment>
		       $NG_ACK_MSG="[$now] ACKNOWLEDGE_HOST_PROBLEM;$ng_HOSTNAME;1;1;1;$ng_contact;";
		    }
		    else {
		       # ACKNOWLEDGE_SVC_PROBLEM;<host_name>;<service_description>;<sticky>;<notify>;<persistent>;<author>;<comment>
		       $NG_ACK_MSG="[$now] ACKNOWLEDGE_SVC_PROBLEM;$ng_HOSTNAME;$ng_SERVICENAME;1;1;1;$ng_contact;";
		       
		    }
		    
		    if (!$NG_ACK_PARAM){
		    	$NG_ACK_MSG=$NG_ACK_MSG."(blank)";
		    } else {
		    	$NG_ACK_MSG=$NG_ACK_MSG.$NG_ACK_PARAM
		    }
		    logEvent($INFO,0,"<Set_Acknowledge> $NG_ACK_MSG");
			print NG_CMD "$NG_ACK_MSG";
		    close(NG_CMD);
	    }else{
	    	logEvent($ERROR,0,"<Set_Acknowledge> <ERROR> Cannot Open $ng_pipe for writing");
	    }
	}
}



# Here we add only a comment on the problem in Nagios in case we have trouble opening an incident in ITSM

sub set_comment
{
	my ($NG_COMMENT_PARAM) = @_;
    my $NG_COMMENT_MSG='';
 	 
    if (-e $ng_pipe)
	{ 
	    if (open(NG_CMD, ">> $ng_pipe")){
	  
		    my $now = time();
		    if (!$ng_SERVICENAME)
		    {
		       # ADD_HOST_COMMENT;<host_name>;<persistent>;<author>;<comment>
		       $NG_COMMENT_MSG="[$now] ADD_HOST_COMMENT;$ng_HOSTNAME;1;$ng_contact;";
		    } else {
		       # ADD_SVC_COMMENT;<host_name>;<service_description>;<persistent>;<author>;<comment>
		       $NG_COMMENT_MSG="[$now] ADD_SVC_COMMENT;$ng_HOSTNAME;$ng_SERVICENAME;1;$ng_contact;";
		    }
		       
		    if (!$NG_COMMENT_PARAM){
		    	$NG_COMMENT_MSG=$NG_COMMENT_MSG."(blank)";
		    } else {
		    	$NG_COMMENT_MSG=$NG_COMMENT_MSG.$NG_COMMENT_PARAM
		    }
		    logEvent($INFO,0,"<Set_Comment> $NG_COMMENT_MSG");
			print NG_CMD "$NG_COMMENT_MSG";
		    close(NG_CMD);
	    }else{
	    	logEvent($ERROR,0,"<Set_Comment> <ERROR> Cannot Open $ng_pipe for writing");
	    }
	}
}


sub SendNotification
{
	my ($subject,$body,$from,$to) = @_;	
	
	my $fullbody = "";
	$fullbody = $fullbody."Message from Nagios:\n";
	$fullbody = $fullbody."-------------------------------------------------------------------\n";
	$fullbody = $fullbody."$body\n";
	
	if ($to){
		SendManuaLeMail($subject,$fullbody,$from,$to);
	}
	if ( $ng_cust_notification >= 0 && $ng_cust_notification  <= 7 ){
		Send_cust_notification($fullbody);
	}
}

sub SendManuaLeMail
{
	my ($subject,$body,$from,$to) = @_;	

	if (open(MAIL, "|$mailer")){
	 
		# Mail Header
		print MAIL "To: $to\n";
		print MAIL "From: $from\n";
		print MAIL "Subject: $subject\n\n";
		
		# Mail Body
		print MAIL "$body\n";
		close(MAIL);
	} else {
		logEvent($ERROR,0,"<SendManuaLeMail> <ERROR> Cannot Open $mailer for writing");
	}
}

sub Send_cust_notification
{
	my ($NG_COMMENT_PARAM) = @_;
    my $NG_COMMENT_MSG='';
    
    if ($NG_COMMENT_PARAM){
	    if ($ng_pipe)
		{ 
		    if (open(NG_CMD, ">> $ng_pipe")){
		    
			    my $now = time();
			    if (!$ng_SERVICENAME)
			    {
			       # SEND_CUSTOM_HOST_NOTIFICATION;<host_name>;<options>;<author>;<comment>
			       $NG_COMMENT_MSG="[$now] SEND_CUSTOM_HOST_NOTIFICATION;$ng_HOSTNAME;$ng_cust_notification;$ng_contact;";
			    } else {
			       # SEND_CUSTOM_SVC_NOTIFICATION;<host_name>;<service_description>;<options>;<author>;<comment>
			       $NG_COMMENT_MSG="[$now] SEND_CUSTOM_SVC_NOTIFICATION;$ng_HOSTNAME;$ng_SERVICENAME;$ng_cust_notification;$ng_contact;";
			    }
			       
			    $NG_COMMENT_MSG=$NG_COMMENT_MSG.$NG_COMMENT_PARAM;	
			    
			    logEvent($INFO,0,"<Send_cust_notification> $NG_COMMENT_MSG");
				print NG_CMD "$NG_COMMENT_MSG";
			    close(NG_CMD);
			}else{
	    		logEvent($ERROR,0,"<Send_cust_notification> <ERROR> Cannot Open $ng_pipe for writing");
	    	}
		}
    }
}

sub print_usage
{
	print "\nUsage: itsm.pl -f|--fqdn <fqdn> -H|--host <host> -S|--service <service> -s|--state <nagios host/service current state> -t|--type <nagios state type> -n|--attempt <nagios current host/service check retry> -C|--category <ITSM category> -G|--GroupAssignment <ITSM Group Assignment> -a|--address <host address> -A|--alias <host alias> -h|--hostgroups <host groups> -g|--servicegroups <service groups> -p|--problemid <nagios problem ID> -P|--lastproblemid <nagios last problem ID> -T|--time <Nagios time stamp in time_t format> -o|--output <nagios output> -O|--longoutput <nagios long output> -c|--conf <configuration file>\n";
	print "or\n";
	print "Usage: itsm.pl --check to run checks.\n";
	print "or\n";
	print "Usage: itsm.pl --help for help.\n\n";
}

sub print_header
{
	print "BMC Service Desk Express Nagios Connector\n";
	print "Developed by: Herve Roux under GPL License 2.0.\n";
	print "Developed by: Javier Vela under GPL License 2.0.\n";
}

sub print_help
{
	print_header();
    print_usage();
    print "   -f, --fqdn                     * Fully qualified domain name of the host (mandatory)\n";
    print "                                       Nagios Custom HOST Macro '_FQDN'\n";
    print "                                       The FQDN will be used in ITSM to match with a CI\n";
    print "   -H, --host                     * Host causing the incident from Nagios (mandatory)\n";
    print "   -S, --service                    Service causing the incident from Nagios\n";
    print "   -a, --address                    Host Address in Nagios\n";
    print "   -A, --alias                      Host Alias in Nagios\n";
    print "   -h, --hostgroups                 Host Groups in Nagios\n";
    print "   -g, --servicegroups              Service Groups in Nagios\n";
    print "\n";
    print "   -C, --category                 * ITSM Category (mandatory)\n";
    print "                                       Nagios Custom HOST & SERVICE Macro '_ITSM_CATEGORY'\n";
    print "                                       The Category will be used in ITSM to map with Services\n";
    print "   -G, --GroupAssignment            ITSM Group Assignment\n";
    print "                                       Nagios Custom HOST & SERVICE Macro '_ITSM_GROUPASSIGNMENT'\n";
    print "                                       The Group Assignment will override the Category mapping\n";
    print "                                       directive in ITSM. As good practice, manage Group Assignment\n";
    print "                                       Mapping centrally from ITSM using Categories. This parameter\n";
    print "                                       is a commodity feature that should be used to manage exceptions.\n";
    print "\n";
    print "   -s, --state=state              * State from Nagios (mandatory)\n";
    print "                                       UP = Host up - will send a Recovery Message\n";
    print "                                       DOWN = Host down - Mapped to severity 1\n";
    print "                                       UNREACHABLE = Host unreachable - Mapped to severity 3\n";
    print "                                       OK = Service ok - will send a Recovery Message\n";
    print "                                       WARNING = Service Warning - Mapped to severity 2\n";
    print "                                       CRITICAL = Service critical- Mapped to severity 1\n";
    print "                                       UNKNOWN = Service unknown - Mapped to severity 3\n";
    print "\n";
    print "   -t, --type                     * State Type - SOFT|HARD (mandatory)\n";
    print "   -n, --attempt                    Current host|service check retry (optional)\n";
    print "   -p, --problemid                * Nagios problem ID (mandatory)\n";
    print "   -P, --lastproblemid            * Nagios last problem ID (mandatory)\n";
    print "   -i, --eventid                    Nagios event ID\n";
    print "   -I, --lasteventid                Nagios last event ID\n";
    print "   -w, --downtime                   Nagios downtime depth\n";
    print "   -r, --renotification             Nagios notification count\n";
    print "\n";
    print "   -d, --disable                    To disable the event, set '_DISABLE_ITSM' to 'yes'.\n";
    print "   -D, --disableack                 To disable acknowledge, set '_DISABLE_ACK' to 'yes'.\n";
    print "\n";
    print "   -T, --time                     * Nagios time stamp in time_t format (mandatory)\n";
    print "   -o, --output                     Nagios text output from the last check\n";
    print "   -O, --longoutput                 Nagios full text output from the last check\n";
    print "\n";
	print "   -N, --notificationtype           Nagios type of notification that is being sent.\n";
	print "                                       => Used when CALLED by Notification\n";
    print "\n";
    print "   --SOAPdata                       SOAP data Pass-through\n";
    print "                                       Allow to pass additional nagios macro to ITSM web services\n";
    print "                                       Format: --SOAPdata Key=Value --SOAPdata Key2=Value2 ...\n";
    print "\n";
    print "   -c, --conf                       Configuration File to use\n";
    print "                                       Default is '/etc/nagios/itsm/itsm.conf'\n";
    print "\n";
    print "   --check                          Run check list\n";
    print "\n";
    print "   --help                           Short help message\n";
    print "\n";
}
