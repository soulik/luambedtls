return {
	wrap = function(t_fn)
		return function(options)
			local obj = t_fn(options)

			local mt = getmetatable(obj) or {}

			mt.__add = function(a, b)
				b.callbacks = {
					init = a.init,
					close = a.close,

					send = a.send,
					recv = a.recv,
					recvTimeout = a.recv,
				}
				return b
			end
			setmetatable(obj, mt)
			return obj
		end
	end,
}