nagios2itsm
===========

Conector to send alerts from Nagios to ITSM

Execute:

./itsm.pl -c /etc/nagios/itsm/itsm.conf -S dummy -H localhost -A localhost -a 127.0.0.1 -s CRITICAL -t HARD -n 4 -i 33 -I 32 -p 13 -P 12 -T 1380897136 -o 2 -O -h linux-servers -g -f localhost -C linux -G 'Service Desk' -w 0 -d no -D no -N -r 6 --SOAPdata Create_Request=YES

Nagios integration:

define command{
        command_name                    log-host-event-to-itsm
        command_line                    $USER1$/eventhandlers/itsm.pl -c /etc/nagios/sde/sde.conf -H '$HOSTNAME$' -A '$HOSTALIAS$' -a '$HOSTADDRESS$' -s '$HOSTSTATE$' -t '$HOSTSTATETYPE$' -n $HOSTATTEMPT$ -o '$HOSTOUTPUT$' -O '$LONGHOSTOUTPUT$' -T $TIMET$ -i $HOSTEVENTID$ -I $LASTHOSTEVENTID$ -p $HOSTPROBLEMID$ -P $LASTHOSTPROBLEMID$ -h '$HOSTGROUPNAMES$' -f '$_HOSTFQDN$' -C '$_HOSTSDE_CATEGORY$' -G '$_HOSTSDE_GROUPASSIGNMENT$' -w $HOSTDOWNTIME$ -d '$_HOSTDISABLE_SDE$' -D '$_HOSTDISABLE_ACK$' -N '$NOTIFICATIONTYPE$' -r '$HOSTNOTIFICATIONNUMBER$' --SOAPdata 'LastState=$LASTHOSTSTATE$'
}

# global_service_event_handler=log-service-event-to-sde

define command{
        command_name                    log-service-event-to-itsm
        command_line                    $USER1$/eventhandlers/itsm.pl -c /etc/nagios/sde/sde.conf -S '$SERVICEDESC$' -H '$HOSTNAME$' -A '$HOSTALIAS$' -a '$HOSTADDRESS$' -s '$SERVICESTATE$' -t '$SERVICESTATETYPE$' -n $SERVICEATTEMPT$ -i $SERVICEEVENTID$ -I $LASTSERVICEEVENTID$ -p $SERVICEPROBLEMID$ -P $LASTSERVICEPROBLEMID$ -T $TIMET$ -o '$SERVICEOUTPUT$' -O '$LONGSERVICEOUTPUT$' -h '$HOSTGROUPNAMES$' -g '$SERVICEGROUPNAMES$' -f '$_HOSTFQDN$' -C '$_SERVICESDE_CATEGORY$' -G '$_SERVICESDE_GROUPASSIGNMENT$' -w $SERVICEDOWNTIME$ -d '$_SERVICEDISABLE_SDE$' -D '$_SERVICEDISABLE_ACK$' -N '$NOTIFICATIONTYPE$' -r '$SERVICENOTIFICATIONNUMBER$' --SOAPdata 'LastState=$LASTSERVICESTATE$'
}

