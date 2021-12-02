#  Utils


global parse_params: function(data: string): table[string] of string;
global rm_html_entities: function(uri: string): string;
global sanitize_uri: function(uri: string): string;


#  Parser returns table of params from unescaped URI given
function parser(data: string): table[string] of string
{
	local query: string;
	local params: table[string] of string;

	if (/\?/ in data)
	{
		local splitted = split_string(data, /\?/);

		if (|splitted| > 1)
		{
			query = splitted[1];
		}
		else
		{
			return params;
		}
	}
	else
	{
		query = data;
	}

	local sanitized_uri = sanitize_uri(query);
	params = parse_params(sanitized_uri);

	return params;
}


#  Parsing parameters in URI form
function parse_params(data: string): table[string] of string
{
	local params: table[string] of string;
	local pairs = split_string(data, /&/);

	for (i in pairs)
	{
		local splitted = split_string1(pairs[i], /=/);

		if (|splitted| > 1)
		{
			local key = unescape_URI(splitted[0]);
			local val = unescape_URI(splitted[1]);

			params[key] = val;
		}

	}

	return params;
}


#  Convert HTML entities to URI bytes
function rm_html_entities(uri: string): string
{
	local slices: string_vec;
	local re = /&#x..;/;
	local out = "";

	slices = split_string_all(uri, re);

	for (i in slices)
	{
		local slice = slices[i];

		if (re in slice)
		{
			slice = gsub(slice, /&#x/, "%");
			slice = gsub(slice, /;/, "");
		}

		out += slice;
	}

	return out;
}


#  Convert '+' to spaces and convert HTML entities
function sanitize_uri(uri: string): string
{
	local repl = uri;

	repl = gsub(repl, /\+/, " ");

	repl = rm_html_entities(repl);

	return repl;
}