@load base/bif/plugins/Zeek_HTTP.events.bif
@load base/bif/plugins/Zeek_HTTP.functions.bif
@load base/utils/patterns
@load ./utils


## XSS detection
module INJ;

export
{
	# redef enum Log::ID += { LOG };
	global inj_init: event();

	type CFG: record
	{
		# bool looking_in_replay;
		# string log_path;
		inj_type: string;
		# pattern regex;
	};

	global injections: vector of string;
	option message = "[SECURITY] %s attack detected";

	type INJ_T: record
	{
		conn: string &default="";
		params: table[string] of string;
	};

	type Info: record
	{
		id: conn_id &log;
		method: string &log;
		uri: string &log;
		param: string &log;
		payload: string &log;
	};
}

global inj: INJ_T;


#  Looking for suspicios regex in parameters
function watch_dog(c: connection, params: table[string] of string)
{
	# for (key, val in params)
	# {
	# 	if (INJ::regex in unescape_URI(val))
	# 	{
	# 		inj$conn = c$uid;
	# 		inj$params[key] = val;
	# 	}
	# }
}


event zeek_init()
{
	# Log::create_stream(INJ::LOG, [$columns=Info, $path=INJ::log_path]);
	event inj_init();
	while (|injections| == 0)
	{
		
	}
	print injections;
	# for (i in injections)
	# {
	# 	print i;
	# }
}


#  Event calls when request from orig sended
# event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
# {
# 	local params = parser(original_URI);
# 	watch_dog(c, params);
# }


# #  Event calls when zeek starts parsing packet data
# event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
# {
# 	if (is_orig)
# 	{
# 		local params = parser(data);
# 		watch_dog(c, params);
# 	}
# 	else
# 	{
# 		if (c$uid == inj$conn)
# 		{
# 			for (key, val in inj$params)
# 			{
# 				local predicate = (looking_in_replay) ? (val in data) : (val !in data);
# 				if (predicate)
# 				{
# 					# print fmt(INJ::message, INJ::inj_type);

# 					# Log::write(INJ::LOG, [$id=c$id, $param=key, $payload=val,
# 					# 			$uri=c$http$uri, $method=c$http$method]);
# 				}
# 			}
# 		}

# 		inj$conn = "";
# 	}
# }