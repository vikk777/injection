@load ./inj.base


# XSS detection
module XSS;

export
{
	redef enum Log::ID += { XSS_LOG };
}

event inj_init()
{
	local cfg = INJ::Config
	(
		$log_id = XSS_LOG,
		$looking_in_replay = T,
		$log_path = "xss",
		$inj_type = "XSS",
		$regex = /<(\/)?script *>/
					| /(onerror|onfocus|onload|srcdoc) *=.*>?/
					| /(href|src) *= *['"]?javascript *:.*?['"]?/
					| (/[a-zA-Z_\-]+[\(`].*[\)`]/)
	);

	INJ::injections += cfg;
}