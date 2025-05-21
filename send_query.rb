require "socket"
require_relative "./resolve"
require_relative "./parse_response"

sock = UDPSocket.new

sock.connect("8.8.8.8", 53)

query = get_query

sock.send(query, 0)

resp = sock.recvfrom(1024).first
io = StringIO.new(resp)
IO.write("resp.bin", resp)
parse_response(io)
