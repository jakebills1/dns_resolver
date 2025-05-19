require 'bindata'

class Label < BinData::Record
  uint8  :len,  value: -> { data.length }
  string :data, read_length: :len
end

class FlagsSection < BinData::Record
  bit1 :qr
  bit4 :opcode
  bit1 :aa
  bit1 :tc
  bit1 :rd
  bit1 :ra
  bit3 :z
  bit4 :rcode
end

class DNSQuery < BinData::Record
  endian :big
  uint16 :id
  flags_section :flags
  # 4 more 16-bit fields
  uint16 :qdcount
  uint16 :ancount
  uint16 :nscount
  uint16 :arcount
  # question section
  array :domain_names, initial_length: :qdcount do
    array :qname, type: :label, read_until: -> { element[:len] == 0 }
  end
  uint16 :qtype
  uint16 :qclass
end

io = File.open('query.bin', 'rb')

query = DNSQuery.read(io)

puts query

