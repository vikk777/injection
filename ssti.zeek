@load ./inj.base


## SSTI detection
module SSTI;

export
{
	# redef INJ::looking_in_replay = F;
	# redef INJ::log_path = "ssti";
	# redef INJ::inj_type = "SSTI";
	# redef INJ::regex = /\{\{.+\}\}/;
}


event inj_init()
{
	INJ::injections += "ssti";
}