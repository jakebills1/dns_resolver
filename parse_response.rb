require "pry"
require "bindata"
require_relative "./resolve.rb"

class AnswerSection < BinData::Record
  # names can be compressed
  # if first byte read 2 msb are 11, the name is compressed
  #   - the lower 6 bits + the next byte are the pointer
  #   - the pointer tells the byte offset to read at
end

class DNSRecord < BinData::Record
  endian :big
  # header
  dns_header :header_section
  # question
  question_section :questions, question_count: -> { header_section.qdcount }
  # answer
  # - number of answers corresponds to ancount in the header field
  answer_section :answers, answer_count: -> { header_section.ancount }
end
def parse_response(io)
  record = DNSRecord.read(io)
  puts record
end
