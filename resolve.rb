require 'bindata'

class Label < BinData::Record
  uint8  :len,  value: -> { data.length }
  string :data, read_length: :len
end

class FlagsSection < BinData::Record
  endian :big
  bit1 :qr
  bit4 :opcode
  bit1 :aa
  bit1 :tc
  bit1 :rd
  bit1 :ra
  bit3 :z
  bit4 :rcode
end

class DNSHeader < BinData::Record
  endian :big
  uint16 :id
  flags_section :flags
  uint16 :qdcount
  uint16 :ancount
  uint16 :nscount
  uint16 :arcount
end

class QuestionSection < BinData::Record
  mandatory_parameter :question_count
  endian :big
  array :domain_names, initial_length: :question_count do
    # the zero length label is reserved for the root zone,
    # so marks the end of the parts of a domain name
    array :qname, type: :label, read_until: -> { element[:len] == 0 }
  end
  uint16 :qtype
  uint16 :qclass
end

class DNSQuery < BinData::Record
  endian :big
  dns_header :header_section
  # question section
  question_section :questions, question_count: -> { header_section.qdcount }
end

def get_query
  io = File.open("query.bin")
  query = DNSQuery.read(io)
  query.to_binary_s
end
