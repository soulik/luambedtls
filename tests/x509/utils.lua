function printf(fmt, ...) io.write(fmt:format(...)) end

function io.load(fname)
	local f = assert(io.open(fname))
	if f then
		local buffer = f:read("*a")
		f:close()
		return buffer
	else
		return false
	end
end

function io.save(fname,data)
	local f = assert(io.open(fname,"w"))
	if f then
		f:write(data)
		f:close()
		return true
	else
		return false
	end
end

function io.saveb(fname,data)
	local f = assert(io.open(fname,"wb"))
	if f then
		f:write(data)
		f:close()
		return true
	else
		return false
	end
end

function string.template(s,t)
	local out = string.gsub(s,"{{([%w_+-]+)}}",t)
	return out
end

function string.trim(s)
	if type(s)=="string" then
		local out = string.match(s,"^%s*(.-)%s*$")
		if out and string.len(out)>0 then
			return out
		else			
			return ""
		end
	else
		return
	end
end

local function kilo(n)
	return math.pow(1024,n)
end

function get_bytes_text(n)
	local fn = function(nn,fmt)
		local fmt = fmt or "%0.2f"
    	return string.format(fmt,nn)
	end
	if (n<kilo(1)) then
    	return fn(n,"%d").." B"
	elseif ((n>=kilo(1)) and (n<kilo(2))) then
		return fn(n/kilo(1)).." KiB"
	elseif ((n>=kilo(2)) and (n<kilo(3))) then
		return fn(n/kilo(2)).." MiB"
	elseif ((n>=kilo(3)) and (n<kilo(4))) then
		return fn(n/kilo(3)).." GiB"
	else
		return fn(n/kilo(4)).." TiB"
	end
end

function string.hex_dump(buf, options)
	local options = options or {}
	local first, last = options.first or 1, options.last or #buf
	local tabs = options.tabs or 0
	local tabsStr = ("\t"):rep(tabs)
	local prefix = options.prefix or ""
	local ti = table.insert
	local columns = 16
	local columnsHalf = columns/2
	local out = {}
	local function align(n) return math.ceil(n/columns) * columns end

	ti(out, ('%s%sLength: %dB\n'):format(prefix, tabsStr, #buf))

	for i=(align(first-columns)+1),align(math.min(last,#buf)) do
		if (i-1) % columns == 0 then
			ti(out,string.format('%s%08X  ', tabsStr, i-1))
		end
		
		table.insert(out, i > #buf and '   ' or string.format('%02X ', buf:byte(i)) )
		
		if i % columnsHalf == 0 then
			ti(out,' ')
		end
		
		if i % columns == 0 then
			ti(out,buf:sub(i-columns+1, i):gsub('%c','.')..'\n' )
		end
	end
	return table.concat(out)
end
