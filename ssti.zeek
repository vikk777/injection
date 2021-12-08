@load ./inj.base


# SSTI detection
module SSTI;

export
{
	redef enum Log::ID += { SSTI_LOG };
}


event inj_init()
{
	local cfg = INJ::Config
	(
		$log_id = SSTI_LOG,
		$looking_in_replay = F,
		$log_path = "ssti",
		$inj_type = "SSTI",
		$regex = /\{\{.+\}\}/
	);

	INJ::injections += cfg;
}