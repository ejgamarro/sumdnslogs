#!/usr/bin/python

######################################################################################################################
#
#   Name:       sumdnslogs
#
#   Scribe:     E.J. Gamarro
#
#   Version:    v0.1
#
######################################################################################################################

import sys
import os
import getopt
import logging
import time
import datetime
import math


class DnsLog:

    g_queries = 0
    g_types = {}
    g_views = {}
    g_domains = set ()
    g_clients = set ()

    t_clients = {}
    top_clients = {}
    t_clients_min = 0

    t_domains = {}
    top_domains = {}
    t_domains_min = 0

    t_queries = {}
    top_queries = {}
    t_queries_min = 0

    t_thresh = 10
    tot_entries = 0

    t_types = {}
    t_types_min = {}
    top_types = {}

    t_views = {}
    t_views_min = {}
    top_views = {}

    t_rcodes = {}
    t_rcodes_min = {}
    top_rcodes = {}

    t_rcodes_q = {}
    t_rcodes_q_min = {}
    top_rcodes_q = {}


    def basic(self, log_f):

        for t_line in sys.stdin.readlines():
            if not t_line:
                break
            elif log_f == "bind":
                self.parse_basic( self.bind(t_line) )
            elif log_f == "syslog":
                self.parse_basic( self.syslog(t_line) )
            elif log_f == "bro":
                if t_line.startswith("#"):
                    pass
                else:
                    t_lst = self.brolog(t_line)
                    if t_lst[3] != "-":
                        self.parse_basic( self.brolog(t_line) )

        self.print_basic( log_f )



    def print_basic(self, log_f):

        print "Total Queries: %s" % self.g_queries
        print "Total Domains: %s" % len(self.g_domains)
        print "Total Clients: %s" % len(self.g_clients)
        print "Query Types & Counts: "
        for key, val in (self.g_types).items():
            print "\t%s: %s" % (key, val)

        if log_f == "syslog":
            print "\nQuery Views & Counts: "
            for key, val in (self.g_views).items():
                print "\t%s: %s" % (key, val)


    def top(self, thresh, log_f):

        self.t_thresh = thresh

        for t_line in sys.stdin.readlines():
            if not t_line:
                break
            elif log_f == "bind":
                self.parse_top( self.bind(t_line) )

            elif log_f == "syslog":
                self.parse_top( self.syslog(t_line) )

            elif log_f == "bro":
                if t_line.startswith("#"):
                    pass
                else:
                    t_lst = self.brolog(t_line)
                    if t_lst[3] != "-":
                        self.parse_top( t_lst )

        self.print_top()


    def print_top(self):
        print "Clients: %s" % len(self.t_clients)
        self.print_top_clients()

        print "\n\n\nDomains: %s" % len(self.t_domains)
        self.print_top_domains()

        print "\n\n\nQueries: %s" % len(self.t_queries)
        self.print_top_queries()


    def get_top_clients(self, thresh, log_f):
        self.t_thresh = thresh

        for t_line in sys.stdin.readlines():
            if not t_line:
                break
            elif log_f == "bind":
                self.parse_top_clients( self.bind(t_line) )

            elif log_f == "syslog":
                self.parse_top_clients( self.syslog(t_line) )

            elif log_f == "bro":
                if t_line.startswith("#"):
                    pass
                else:
                    t_lst = self.brolog(t_line)
                    if t_lst[3] != "-":
                        self.parse_top_clients( t_lst )


        self.print_top_clients()


    def print_top_clients(self):
        tmp_output = list()
        for key, value in sorted( self.top_clients.iteritems(), key=lambda (k,v): (v,k) ):
            out_str = "%s: %s" % (key, value)
            tmp_output.append(out_str)

        print "Top Clients: "
        for i in reversed(tmp_output):
            print i


    def get_top_domains(self, thresh, mode, log_f):
        self.t_thresh = thresh

        for t_line in sys.stdin.readlines():
            self.tot_entries += 1

            if not t_line:
                break

            elif log_f == "bind":
                self.parse_top_domains( self.bind(t_line), mode)

            elif log_f == "syslog":
                self.parse_top_domains( self.syslog(t_line), mode)

            elif log_f == "bro":
                if t_line.startswith("#"):
                    pass
                else:
                    t_lst = self.brolog(t_line)
                    if t_lst[3] != "-":
                        self.parse_top_domains( t_lst, mode)

        self.print_top_domains()


    def print_top_domains(self):
        tmp_output = list()
        for key, value in sorted( self.top_domains.iteritems(), key=lambda (k,v): (v,k) ):
            out_str = "%s: %s" % (key, value)
            tmp_output.append(out_str)

        print "Top Domains: "
        for i in reversed(tmp_output):
            print i


    def get_top_queries(self, thresh, log_f):
        self.t_thresh = thresh

        for t_line in sys.stdin.readlines():
            if not t_line:
                break

            elif log_f == "bind":
                self.parse_top_queries( self.bind(t_line) )

            elif log_f == "syslog":
                self.parse_top_queries( self.syslog(t_line) )
            
            elif log_f == "bro":
                if t_line.startswith("#"):
                    pass
                else:
                    t_lst = self.brolog(t_line)
                    if t_lst[3] != "-":
                        self.parse_top_queries( t_lst )

        self.print_top_queries()


    def print_top_queries(self):
        tmp_output = list()
        for key, value in sorted( self.top_queries.iteritems(), key=lambda (k,v): (v,k) ):
            out_str = "%s: %s" % (key, value)
            tmp_output.append(out_str)

        print "Top Queries: "
        for i in reversed(tmp_output):
            print i


    def types(self, thresh, log_f):
        self.t_thresh = thresh

        for t_line in sys.stdin.readlines():
            if not t_line:
                break
            elif log_f == "bind":
                self.parse_types(self.bind(t_line))
            elif log_f == "syslog":
                self.parse_types(self.syslog(t_line))
            elif log_f == "bro":
                if t_line.startswith("#"):
                    pass
                else:
                    t_lst = self.brolog(t_line)
                    if t_lst[3] != "-":
                        self.parse_types(t_lst)

        self.print_types()


    def print_types(self):
        print "Types: %s" % len(self.t_types)
        for key, val in (self.t_types).items():
            print "[%s]:%s" % (key, len(val))
        
        print "Top Clients by Type: "
        for key, val in self.top_types.items():
            out_str = "\n[%s] " % key

            for key2, val2 in val.items():
                out_str += "%s=%s, " % (key2, val2)

            out_str = out_str[:-2]
            print out_str



    def views(self, thresh, log_f):
        self.t_thresh = thresh

        for t_line in sys.stdin.readlines():
            if not t_line:
                break
            elif log_f == "syslog":
                self.parse_views( self.syslog(t_line) )
            elif log_f == "bind":
                self.parse_views( self.bind(t_line) )

        self.print_views()


    def rcodes( self, thresh ):
        self.t_thresh = thresh

        for t_line in sys.stdin.readlines():
            if not t_line:
                break
            else:
                if t_line.startswith("#"):
                    pass
                else:
                    t_lst = self.brolog(t_line)
                    if (len(t_lst[1]) > 2) and (len(t_lst[4]) > 2) and t_lst[5] != "-":
                        self.parse_rcodes_domains( t_lst )
                        self.parse_rcodes_queries( t_lst )

        self.print_rcodes()


    def print_views(self):
        print "Views: %s" % len(self.t_views)
        for key, val in self.t_views.items():
            print "[%s]:%s" % (key, len(val))

        print "Top Clients by View: "
        for key, val in self.top_views.items():
            out_str = "\n[%s] " % key

            for key2, val2 in val.items():
                out_str += "%s=%s, " % (key2, val2)

            out_str = out_str[:-2]
            print out_str


    def print_rcodes(self):
        print "Response Codes: %s" % len(self.t_rcodes)
        for key, val in self.t_rcodes.items():
            print "[%s]:%s" % (key, len(val))

        print "\nTop Domains by Response Code: "
        for key, val in self.top_rcodes.items():
            out_str = "\n[%s] " % key

            for key2, val2 in val.items():
                out_str += "%s=%s, " % (key2, val2)

            out_str = out_str[:-2]
            print out_str

        print "\n\n\nTop Queries by Response Code: "
        for key, val in self.top_rcodes_q.items():
            out_str = "\n[%s] " % key

            for key2, val2 in val.items():
                out_str += "%s=%s, " % (key2, val2)

            out_str = out_str[:-2]
            print out_str


    def refactor_tclients(self, ip, count):
        if len(self.top_clients) <= self.t_thresh:
            self.top_clients[ip] = count

        elif count >= self.t_clients_min:
            self.top_clients[ip] = count


        if len(self.top_clients) > self.t_thresh:
            t_lst = self.top_clients.values()
            old_min = self.t_clients_min
            self.t_clients_min = self.new_min(t_lst)

            if self.t_clients_min > old_min:
                for key, val in (self.top_clients).items():
                    if val < self.t_clients_min:
                        del self.top_clients[key]


    def refactor_tdomains(self, name, count):
        if len(self.top_domains) <= self.t_thresh:
            self.top_domains[name] = count

        elif count >= self.t_domains_min:
            self.top_domains[name] = count


        if len(self.top_domains) > self.t_thresh:

            t_lst = self.top_domains.values()
            old_min = self.t_domains_min
            self.t_domains_min = self.new_min(t_lst)

            if self.t_domains_min > old_min:
                for key, val in (self.top_domains).items():
                    if val < self.t_domains_min:
                        del self.top_domains[key]


    def refactor_tqueries(self, query, count):
        if len(self.top_queries) <= self.t_thresh:
            self.top_queries[query] = count

        elif count >= self.t_queries_min:
            self.top_queries[query] = count

        if len(self.top_queries) > self.t_thresh:
            t_lst = self.top_queries.values()
            old_min = self.t_queries_min
            self.t_queries_min = self.new_min(t_lst)

            if self.t_queries_min > old_min:
                for key, val in (self.top_queries).items():
                    if val < self.t_queries_min:
                        del self.top_queries[key]


    def refactor_ttypes(self, type, ip, count):
        if ( len(self.t_types[type]) <= self.t_thresh ) or ( count >= self.t_types_min[type] ):
            try:
                test_type = self.top_types[type]
                self.top_types[type][ip] = count

            except KeyError:
                self.top_types[type] = {}
                self.top_types[type][ip] = count

        if len(self.top_types[type]) > self.t_thresh:
            t_lst = self.top_types[type].values()
            t_new_min, t_new_set = self.new_min2(t_lst)
            self.t_types_min[type] = t_new_min

            for key, val in self.top_types[type].items():
                if (val < self.t_types_min) and (val not in t_new_set):
                    del self.top_types[type][key]



    def refactor_tviews(self, view, ip, count):
        if ( len(self.t_views[view]) <= self.t_thresh ) or ( count >= self.t_views_min[view] ):
            try:
                test_view = self.top_views[view]
                self.top_views[view][ip] = count

            except KeyError:
                self.top_views[view] = {}
                self.top_views[view][ip] = count


        if len(self.top_views[view]) > self.t_thresh:
            t_lst = self.top_views[view].values()
            t_new_min, t_new_set = self.new_min2(t_lst)
            self.t_views_min[view] = t_new_min

            for key, val in self.top_views[view].items():
                if (val < self.t_views_min) and (val not in t_new_set):
                    del self.top_views[view][key]


    def refactor_trcodes_domains(self, rcode, domain, count):
        if ( len(self.t_rcodes[rcode]) <= self.t_thresh ) or ( count >= self.t_rcodes_min[rcode] ):
            try:
                test_rcode = self.top_rcodes[rcode]
                self.top_rcodes[rcode][domain] = count

            except KeyError:
                self.top_rcodes[rcode] = {}
                self.top_rcodes[rcode][domain] = count

        if len(self.top_rcodes[rcode]) > self.t_thresh:
            t_lst = self.top_rcodes[rcode].values()
            t_new_min, t_new_set = self.new_min2(t_lst)
            self.t_rcodes_min[rcode] = t_new_min

            for key, val in self.top_rcodes[rcode].items():
                if (val < self.t_rcodes_min) and (val not in t_new_set):
                    del self.top_rcodes[rcode][key]

    def refactor_trcodes_queries(self, rcode, domain, count):
        if ( len(self.t_rcodes_q[rcode]) <= self.t_thresh ) or ( count >= self.t_rcodes_q_min[rcode] ):
            try:
                test_rcode = self.top_rcodes_q[rcode]
                self.top_rcodes_q[rcode][domain] = count

            except KeyError:
                self.top_rcodes_q[rcode] = {}
                self.top_rcodes_q[rcode][domain] = count

        if len(self.top_rcodes_q[rcode]) > self.t_thresh:
            t_lst = self.top_rcodes_q[rcode].values()
            t_new_min, t_new_set = self.new_min2(t_lst)
            self.t_rcodes_q_min[rcode] = t_new_min

            for key, val in self.top_rcodes_q[rcode].items():
                if (val < self.t_rcodes_q_min) and (val not in t_new_set):
                    del self.top_rcodes_q[rcode][key]


    def new_min2(self, val_lst):

        val_lst.sort(reverse=True)

        try:
            ret_set = set(val_lst[0:(self.t_thresh - 1)])

        except KeyError:
            ret_set = set(val_lst[:])

        if len(val_lst) > self.t_thresh:
            return (val_lst[self.t_thresh - 1], ret_set)
        else:
            return (val_lst[-1], ret_set)


    def new_min(self, val_lst):
        val_lst.sort(reverse=True)

        if len(val_lst) > self.t_thresh:
            return val_lst[self.t_thresh - 1]
        else:
            return val_lst[-1]


    def parse_top( self, t_lst ):

        self.update_clients( t_lst[0] )
        self.update_queries( t_lst[1] )
        self.update_domains( t_lst[4] )


    def parse_top_clients( self, t_lst ):

        self.update_clients(t_lst[0])


    def parse_top_queries( self, t_lst ):

        self.update_queries(t_lst[1])


    def parse_top_domains( self, t_lst, mode ):
        domain = t_lst[4]
        query = t_lst[1]

        tmp_l = query.split(".")

        try:
            name = tmp_l[-2].lower()

            if mode == "norm":
                self.update_domains(domain)
            elif (mode == "long") and (len(domain) >= 33):
                self.update_domains(domain)
            elif (mode == "entropy") and (len(domain) >= 10):
                entro = self.entropy(domain)
                if entro > 3.9:
                    self.update_domains(domain)
            elif ( mode == "vowels" ) and ( name.isalpha() ) and (len(name) > 6) :
                find = 0
                t_name = set (name) 
                for vowel in ['a', 'e', 'i', 'o', 'u']:
                    if vowel in t_name:
                        find += 1

                if find < 1:
                    self.update_domains(domain)


        except IndexError:
            domain = query
            if mode == "norm":
                self.update_domains(domain)
            elif (mode == "long") and (len(domain) >= 33):
                self.update_domains(domain)


    def parse_types( self, t_lst ):
        ip = t_lst[0]
        type = t_lst[3]

        try:
            tmp_type = self.t_types[type]

            try:
                type_elem_c = self.t_types[type][ip]
                type_elem_c += 1
                self.t_types[type][ip] = type_elem_c

                if type_elem_c >= self.t_types_min[type]:
                    self.refactor_ttypes(type, ip, type_elem_c)

            except KeyError:
                self.t_types[type][ip] = 1

        except KeyError:
            self.t_types[type] = {}
            self.t_types[type][ip] = 1
            self.t_types_min[type] = 0


    def parse_views( self, t_lst ):
        ip = t_lst[0]
        view = t_lst[2]

        try:
            tmp_view = self.t_views[view]

            try:
                view_elem_c = self.t_views[view][ip]
                view_elem_c += 1
                self.t_views[view][ip] = view_elem_c

                if view_elem_c >= int(self.t_views_min[view]):
                    self.refactor_tviews(view, ip, view_elem_c)

            except KeyError:
                self.t_views[view][ip] = 1

        except KeyError:
            self.t_views[view] = {}
            self.t_views[view][ip] = 1
            self.t_views_min[view] = 0



    def parse_rcodes_domains( self, t_lst ):
        domain = t_lst[4]
        rcode = t_lst[5]

        try:
            tmp_rcode = self.t_rcodes[rcode]

            try:
                rcode_elem_c = self.t_rcodes[rcode][domain]
                rcode_elem_c += 1
                self.t_rcodes[rcode][domain] = rcode_elem_c

                if rcode_elem_c >= int(self.t_rcodes_min[rcode]):
                    self.refactor_trcodes_domains(rcode, domain, rcode_elem_c)
            except KeyError:
                self.t_rcodes[rcode][domain] = 1

        except KeyError:
            self.t_rcodes[rcode] = {}
            self.t_rcodes[rcode][domain] = 1
            self.t_rcodes_min[rcode] = 0

    def parse_rcodes_queries( self, t_lst):
        query = t_lst[1]
        rcode = t_lst[5]

        try:
            tmp_rcode = self.t_rcodes_q[rcode]

            try:
                rcode_elem_c = self.t_rcodes_q[rcode][query]
                rcode_elem_c += 1
                self.t_rcodes_q[rcode][query] = rcode_elem_c

                if rcode_elem_c >= int(self.t_rcodes_q_min[rcode]):
                    self.refactor_trcodes_queries(rcode, query, rcode_elem_c)

            except KeyError:
                self.t_rcodes_q[rcode][query] = 1

        except KeyError:
            self.t_rcodes_q[rcode] = {}
            self.t_rcodes_q[rcode][query] = 1
            self.t_rcodes_q_min[rcode] = 0


    def parse_basic( self, t_lst ):

        self.g_queries += 1
        self.update_type(t_lst[3])
        self.update_views(t_lst[2])
        (self.g_domains).add(t_lst[4])
        (self.g_clients).add(t_lst[0])


    def bind( self, t_log ):
        in_lst = t_log.split()
        out_lst = [] #ip, query, view, type, domain, <empty rcode>

        tmp = (in_lst[3]).split("#")
        out_lst.append(tmp[0])

        tmp = in_lst[4]
        query = tmp[1:]
        query = query[:-2]
        out_lst.append(query)

        view = in_lst[6]
        view = view[:-1]
        out_lst.append(view)

        out_lst.append(in_lst[10])

        tmp_l = query.split(".")
        try:
            domain = "%s.%s" % (tmp_l[-2], tmp_l[-1])
        except IndexError:
            domain = query

        out_lst.append(domain)
        out_lst.append("") #placeholder for rcode

        return out_lst



    def syslog( self, t_log ):
        in_lst = t_log.split()
        out_lst = [] #ip, query, view, type, domain, <empty rcode>

        tmp = (in_lst[6]).split("#")
        out_lst.append(tmp[0])

        tmp = in_lst[7]
        query = tmp[1:]
        query = query[:-2]
        out_lst.append(query)

        view = in_lst[9]
        view = view[:-1]
        out_lst.append(view)

        out_lst.append(in_lst[13])

        tmp_l = query.split(".")
        try:
            domain = "%s.%s" % (tmp_l[-2], tmp_l[-1])
        except IndexError:
            domain = query

        out_lst.append(domain)
        out_lst.append("") #placeholder for rcode

        return out_lst

    def brolog( self, t_log ):
        in_lst = t_log.split("\t")
        out_lst = [] #ip, query, <empty view>, type, domain, rcode

        out_lst.append(in_lst[2])#ip
        query = in_lst[8]
        out_lst.append(query)#query

        out_lst.append("")#placeholder for view

        tmp_l = query.split(".")
        try:
            domain = "%s.%s" % (tmp_l[-2], tmp_l[-1])
        except IndexError:
            domain = query

        out_lst.append(in_lst[12])#type
        out_lst.append(domain)#domain
        out_lst.append(in_lst[14])#rcode_name

        return out_lst


    def update_type(self, str ):
        if str in self.g_types.keys():
            t_count = self.g_types[str]
            self.g_types[str] = t_count + 1
        else:
            self.g_types[str] = 1


    def update_clients(self, ip):
        try:
            t_count = self.t_clients[ip]
            t_count += 1
            self.t_clients[ip] = t_count
            
            if( t_count >= self.t_clients_min):
                self.refactor_tclients(ip, t_count)

        except KeyError:
            self.t_clients[ip] = 1


    def update_domains(self, name):
        try:
            t_count = self.t_domains[name]
            t_count += 1
            self.t_domains[name] = t_count

            if (t_count >= self.t_domains_min):
                self.refactor_tdomains(name, t_count)

        except KeyError:
            self.t_domains[name] = 1



    def update_queries(self, query):
        try:
            t_count = self.t_queries[query]
            t_count += 1
            self.t_queries[query] = t_count

            if (t_count >= self.t_queries_min):
                self.refactor_tqueries(query, t_count)

        except KeyError:
            self.t_queries[query] = 1


    def update_views(self, str):
        if str in self.g_views.keys():
            t_count = self.g_views[str]
            self.g_views[str] = t_count + 1
        else:
            self.g_views[str] = 1


    def entropy(self, string):
        #(GPL) Borrowed from http://freecode.com/projects/revelation/
        #revelation-0.4.14/src/lib/util.py
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
        entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

        return entropy


    def test_format(self):
        t_rounds = 0
        syslog_errors = 0
        bro_errors = 0
        bind_errors = 0
        for t_line in sys.stdin.readlines():
            t_rounds += 1
            if (not t_line) or (t_rounds > (self.t_thresh + 5)):
                break
            elif not t_line.startswith("#"):
                t_lst = t_line.split()
                bro_lst = t_line.split("\t")

                try:
                    if ("client" == t_lst[2]) and ("#" in t_lst[3]) and ("view" == t_lst[5]) and ("query:" == t_lst[7]):
                        print "BIND log format supported (-i/--bind-format)..."
                except IndexError:
                    bind_errors += 1

                try:
                    if ("client" == t_lst[5]) and ("#" in t_lst[6]) and ("view" == t_lst[8]) and ("query:" == t_lst[10]):
                        print "BIND syslogged log format supported (-d/--syslg-format)..."
                except IndexError:
                   syslog_errors += 1 

                try:
                    if (len(t_lst) == 23) and (t_lst[3].isdigit()) and (t_lst[5].isdigit()) and (t_lst[6].isalpha()) and (t_lst[7].isdigit()):
                        print "Bro NSM log format supported (-r/--bro-format)..."
                except IndexError:
                    bro_errors += 1

                if syslog_errors > 0 or bro_errors > 0:
                    print "Sorry, this is an unsupported format.  Please contact author to add support for your logs."



#====================================

def valid_args(argv):
    help_msg = "\nUsage:\n\t./sumdnslogs.py <log format> <report option> <threshold>\
    \n\n\t-i/--bind-format\tSpecify BIND log format for input data.\n\t-d/--syslg-format\tSpecify BIND syslogged log format for input data.\
    \n\t-r/--bro-format\t\tSpecify Bro NSM log format for input data.\n\
    \n\t-b/--basic\t\tPrint a basic summary of DNS data observed.\n\t-t/--top-all\t\tPrint top talker counts.\
    \n\t-c/--top-clients\tPrint top clients only.\n\t-q/--top-queries\tPrint top queries only.\n\t-n/--top-domains\tPrint top domains only.\
    \n\n\t-l/--long-domains\tPrint report on unusually long domain names.\n\t-v/--no-vowels\t\tPrint report on names composed without vowels.\
    \n\t-e/--entropy\t\tPrint report on domains possibly created with a domain generation algorithm. (Slow performance)\
    \n\n\t-y/--types\t\tPrint DNS query types and their counts.\n\t-w/--views\t\tPrint DNS views and their counts (Works with --bind-format or --syslg-format).\
    \n\t-o/--rcodes\t\tPrint DNS response codes and their counts (Works with --bro-format only).\
    \n\n\t--threshold\t\tSet a threshold to limit output to the top count values (default: --threshold 10).\n\t-f\t\t\tTest DNS log format for issues.\
    \n\n\tDNS logs are read from standard input, such that additional manipulations can be performed before piping data.\n\n\tExamples: \n\n\t\tcat dns.log | ./sumdnslogs.py -f\
    \n\n\t\tgrep 'internal-in' dns.log | ./sumdnslogs.py --bind-format --top-clients --threshold 25\n" 

    opts_hash = {'format':'default', 'basic':0, 'top-all':0, 'clients':0, 'queries':0, 'domains':0, 'long':0, 'entropy':0, 'vowels':0, 'types':0, 'views':0, 'rcodes':0, 'thresh':0, 'threshold':10, 'test':0}

    try:
        l_args = ['help','basic','top-all','top-clients','top-queries','top-domains','long-domains',
                'no-vowels','types','views','threshold=','syslg-format', 'bro-format', 'bind-format', 'entropy', 'rcodes']

        opts, args = getopt.getopt(argv[1:], 'hbtyvcqlofdrneiw',l_args)

        if len(opts) < 1:
            print help_msg

        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print help_msg
                sys.exit()

            elif opt in ("-i", "--bind-format"):
                opts_hash['format']="bind"

            elif opt in ("-d", "--syslg-format"):
                opts_hash['format']="syslog"

            elif opt in ("-r", "--bro-format"): 
                opts_hash['format']="bro"

            elif opt in ("-b", "--basic"):
                opts_hash['basic']=1

            elif opt in ("-t", "--top-all"):
                opts_hash['top-all']=1

            elif opt in ("-c", "--top-clients"):
                opts_hash["clients"]=1

            elif opt in ("-q", "--top-queries"):
                opts_hash["queries"]=1

            elif opt in ("-n", "--top-domains"):
                opts_hash["domains"]=1

            elif opt in ("-l", "--long-domains"):
                opts_hash["long"]=1

            elif opt in ("-v", "--no-vowels"):
                opts_hash["vowels"]=1

            elif opt in ("-y", "--types"):
                opts_hash['types']=1

            elif opt in ("-w", "--views"):
                opts_hash['views']=1

            elif opt in ("-o", "--rcodes"):
                opts_hash['rcodes']=1

            elif opt in ("-e", "--entropy"):
                opts_hash['entropy']=1

            elif opt == "-f":
                opts_hash["test"]=1

            elif opt in ("--threshold"):
                opts_hash['thresh']=1

                if arg > 0:
                    opts_hash['threshold']=int(arg)

    except getopt.GetoptError:
        print help_msg

    return opts_hash


#===================

user_opts = valid_args(sys.argv)

if (user_opts['format'] == "default") and (user_opts["test"]==0):
    print "ERROR: Need to specify log format"
    sys.exit(-1)


if user_opts['basic'] == 1:
    DnsLog().basic( user_opts.get('format') )

elif user_opts['top-all'] == 1:
    DnsLog().top( user_opts.get('threshold'), user_opts.get('format') )

elif user_opts['clients'] == 1:
    DnsLog().get_top_clients( user_opts.get('threshold'), user_opts.get('format') )

elif user_opts['queries'] == 1:
    DnsLog().get_top_queries( user_opts.get('threshold'), user_opts.get('format') )

elif user_opts['domains'] == 1:
    DnsLog().get_top_domains( user_opts.get('threshold'), "norm", user_opts.get('format') )

elif user_opts['long']==1:
    DnsLog().get_top_domains( user_opts.get('threshold'), "long", user_opts.get('format') )

elif user_opts['vowels']==1:
    DnsLog().get_top_domains( user_opts.get('threshold'), "vowels", user_opts.get('format') )

elif user_opts['entropy']==1:
    DnsLog().get_top_domains( user_opts.get('threshold'), "entropy", user_opts.get('format') )

elif user_opts['types'] == 1:
    DnsLog().types( user_opts.get('threshold'), user_opts.get('format') )

elif user_opts['views'] == 1:
    if ( user_opts['format'] == "syslog") or (user_opts['format'] == "bind"):
        DnsLog().views( user_opts.get('threshold'), user_opts.get('format') )
    else:
        print "Views are only available in Syslogged DNS."

elif  user_opts['rcodes'] == 1:
    if user_opts['format'] == "bro":
        DnsLog().rcodes( user_opts.get('threshold') )
    else:
        print "Response codes (rcodes) only available in Bro NSM log format."

elif user_opts["test"] == 1:
    DnsLog().test_format()

else:
    sys.exit()


