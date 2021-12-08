@load base/bif/plugins/Zeek_HTTP.events.bif
@load base/bif/plugins/Zeek_HTTP.functions.bif
@load base/utils/patterns
@load ./utils


## Injection detection
module INJ;

export
{
	global inj_init: event();

	type INJ_T: record
	{
		conn: string &default="";
		params: table[string] of string;
	};

	type Config: record
	{
		log_id: Log::ID;
		looking_in_replay: bool;
		log_path: string;
		inj_type: string;
		regex: pattern;
		inj: INJ_T;
	};

	global injections: vector of Config;
	option message = "[SECURITY] %s attack detected";

	type Info: record
	{
		id: conn_id &log;
		method: string &log;
		uri: string &log;
		param: string &log;
		payload: string &log;
	};
}

# global inj: INJ_T;


#  Looking for suspicios regex in parameters
function watch_dog(c: connection, params: table[string] of string)
{
	for (i in injections)
	{
		local obj = injections[i];
		for (key, val in params)
		{
			if (obj$regex in unescape_URI(val))
			{
				obj$inj$conn = c$uid;
				obj$inj$params[key] = val;
			}
		}
	}
}


event zeek_init()
{
	event inj_init();
	
	for (i in injections)
	{
		local obj = injections[i];
		Log::create_stream(obj$log_id, [$columns=Info, $path=obj$log_path]);
	}
}


#  Event calls when request from orig sended
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
	local params = parser(original_URI);
	watch_dog(c, params);
}


# #  Event calls when zeek starts parsing packet data
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
	if (is_orig)
	{
		local params = parser(data);
		watch_dog(c, params);
	}
	else
	{
		for (i in injections)
		{
			local obj = injections[i];
			if (c$uid == obj$inj$conn)
			{
				for (key, val in obj$inj$params)
				{
					local predicate = (obj$looking_in_replay) ? (val in data) : (val !in data);
					if (predicate)
					{
						print fmt(INJ::message, obj$inj_type);

						Log::write(obj$log_id, [$id=c$id, $param=key, $payload=val,
									$uri=c$http$uri, $method=c$http$method]);
					}
				}
			}

			obj$inj$conn = "";
		}
	}
}