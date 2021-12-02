@load ./inj.base


## XSS detection
module XSS;

export
{
	redef enum Log::ID += { LOG };
	redef INJ::looking_in_replay = T;
	redef INJ::log_path = "xss";
	redef INJ::inj_type = "XSS";
	redef INJ::regex = /<(\/)?script *>/
					| /(onerror|onfocus|onload|srcdoc) *=.*>?/
					| /(href|src) *= *['"]?javascript *:.*?['"]?/
					| (/[a-zA-Z]+[\(`].*[\)`]/)
					;
}

