#=============================================================================
#title           : whitelist-manager.bro
#description     : Manages global whitelist for bro scripts
#author		 : Rodrigo Kroll - Logstretch
#email		 : rodrigo.kroll@logstretch.com
#date            : 20190115
#version         : 1.0
#=============================================================================

module GlobalWhitelist;

export {
    global checkwhitelist: function(name: string,source_ip: addr,destination_ip: addr,destination_port: port): bool;
}

redef enum Log::ID += { LOG };
type Info: record {
    ts: time        &log;
    rulename: string     &log;
    source_ip: addr     &log;
    destination_ip: addr     &log;
    destination_port: port     &log;
};

redef record connection += {
    whitelisted: Info &optional;
};

type Idx: record {
        name: string;
};

type Val: record {
        sIP: set[addr];
        dIP: set[addr];
	dport: set[string];
	specific: set[string];
	debug: bool;
};

global buildwlist: table[string] of Val = table();

event bro_init() &priority=10 {
	Log::create_stream(LOG, [$columns=Info, $path="whitelist"]);
        Input::add_table([$source="./globalwhitelist.db", $name="buildwlist",$idx=Idx, $val=Val, $destination=buildwlist,$mode=Input::REREAD]);
        Input::remove("whitelist");
}

function checkconf(sdp: set[string],name: string, source_ip: addr, destination_ip:addr, destination_port:port, debug:bool): bool {
	#Validate if sdp is true
	for ( conf in sdp ) {
		local IPs: string_vec;
    		local rec: Info = [$ts=network_time(), $rulename=name, $source_ip=source_ip, $destination_ip=destination_ip, $destination_port=destination_port];
		IPs = split_string(conf, /:/);
		if ( source_ip == to_addr(IPs[0]) && destination_ip == to_addr(IPs[1]) &&
					     destination_port == to_port(IPs[2]) ) {

			if ( debug ) {
				Log::write(GlobalWhitelist::LOG, rec);
			}

			return T;
		}
		else 
			next;
	}
	return F;
}

function checkwhitelist(name: string,source_ip: addr,destination_ip: addr,
				destination_port: port): bool {

	local verdict: set[string];
    	local rec: Info = [$ts=network_time(), $rulename=name, $source_ip=source_ip, $destination_ip=destination_ip, $destination_port=destination_port];

	if ( name in buildwlist ) {	
		local dports: set[port];
		for ( dport in buildwlist[name]$dport ) {
			add dports[to_port(dport)];
		}

		#sdp -> Source IP, Destination IP and Destination Port
        	local sdp = buildwlist[name]$specific;

		#Check ports settings
		if ( |dports| == 1 && 0/tcp in dports) {
			if ( source_ip in buildwlist[name]$sIP || destination_ip in buildwlist[name]$dIP ) {

				if ( buildwlist[name]$debug ) {
					Log::write(GlobalWhitelist::LOG, rec);
				}
				return T;
			}
			else
				return checkconf(sdp,name,source_ip,destination_ip,destination_port,buildwlist[name]$debug);
			}
		else 
			#Check OR condition AND Port
			if (( source_ip in buildwlist[name]$sIP || destination_ip in buildwlist[name]$dIP ) 
								&& destination_port in dports ) {
				if ( buildwlist[name]$debug ) {
					Log::write(GlobalWhitelist::LOG, rec);
				}
				return T;
			}
			else
				return checkconf(sdp,name,source_ip,destination_ip,destination_port,buildwlist[name]$debug);
	}
}
