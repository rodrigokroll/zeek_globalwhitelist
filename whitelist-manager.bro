#=============================================================================
#title           :whitelist-manager.bro
#description     :Manages global whitelist for bro scripts
#author          :Rodrigo Kroll
#email           :rodrigo.kroll@logstretch.com
#date            :20190101
#version         :1.0
#usage           :bro whitelist-manager.bro or via broctl 
#=============================================================================

type Idx: record {
        name: string;
};

type Val: record {
        sIP: set[addr];
        dIP: set[addr];
        dport: set[string];
        specific: set[string];
        log: bool &optional;
};

global buildwlist: table[string] of Val = table();

event bro_init() &priority=10 {
        Input::add_table([$source="/opt/globalwhitelist.db", $name="buildwlist",$idx=Idx, $val=Val, $destination=buildwlist,$mode=Input::REREAD]);
        Input::remove("whitelist");
}

function checkconf(sdp: set[string],source_ip: addr, destination_ip:addr, destination_port:port): bool {
        #Validate if sdp is true
        for ( conf in sdp ) {
                local IPs: string_vec;
                IPs = split_string(conf, /:/);
                if ( source_ip == to_addr(IPs[0]) && destination_ip == to_addr(IPs[1]) &&
                                             destination_port == to_port(IPs[2]) ) {
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
                                return T;
                        }
                        else
                                return checkconf(sdp,source_ip,destination_ip,destination_port);
                        }
                else 
                        #Check OR condition AND Port
                        if (( source_ip in buildwlist[name]$sIP || destination_ip in buildwlist[name]$dIP ) 
                                                                && destination_port in dports ) {
                                return T;
                        }
                        else
                                return checkconf(sdp,source_ip,destination_ip,destination_port);
        }
}
