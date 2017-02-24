Script:	sumdnslogs.py

Author:	E.J. Gamarro

Description:	A script to help summarize DNS logs.

Usage:
	./sumdnslogs.py <log format> <report option> <threshold>    

	-i/--bind-format	Specify BIND log format for input data.
	-d/--syslg-format	Specify BIND syslogged log format for input data.    
	-r/--bro-format		Specify Bro NSM log format for input data.
    
	-b/--basic		Print a basic summary of DNS data observed.
	-t/--top-all		Print top talker counts.    
	-c/--top-clients	Print top clients only.
	-q/--top-queries	Print top queries only.
	-n/--top-domains	Print top domains only.    

	-l/--long-domains	Print report on unusually long domain names.
	-v/--no-vowels		Print report on names composed without vowels.    
	-e/--entropy		Print report on domains possibly created with a domain generation algorithm. (Slow performance)    

	-y/--types		Print DNS query types and their counts.
	-w/--views		Print DNS views and their counts (Works with --bind-format or --syslg-format).    
	-o/--rcodes		Print DNS response codes and their counts (Works with --bro-format only).    

	--threshold		Set a threshold to limit output to the top count values (default: --threshold 10).
	-f			Test DNS log format for issues.    

	DNS logs are read from standard input, such that additional manipulations can be performed before piping data.

	Examples: 

		cat dns.log | ./sumdnslogs.py -f    

		grep 'internal-in' dns.log | ./sumdnslogs.py --bind-format --top-clients --threshold 25


