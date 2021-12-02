@load ./inj.base


## XSS detection
module XSS;

export
{
	redef enum Log::ID += { LOG };
	redef INJ::looking_in_replay = F;
	redef INJ::log_path = "ssti";
	redef INJ::inj_type = "SSTI";
	redef INJ::regex = /\{\{.+\}\}/;
}

