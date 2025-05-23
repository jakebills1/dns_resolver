require 'stringio'
require 'socket'
require 'pry'

MAX_16_BIT = 2 ** 16 - 1
COMPRESSION_BITMASK = 0b1100_0000
LOWER_ORDER_SIX = ~COMPRESSION_BITMASK

TYPES = [
  nil,
  :A,
  :NS,
  :MD,
  :MF,
  :CNAME,
  :SOA,
  :MB,
  :MG,
  :MR,
  :NULL,
  :WKS,
  :PTR,
  :HINFO,
  :MINFO,
  :MX,
  :TXT
]

CLASSES = [nil, :IN, :CS, :CH, :HS]

Header = Data.define(:id, :flags, :qdcount, :ancount, :nscount, :arcount) do
  def initialize(id:, flags:, qdcount: 0, ancount: 0, nscount: 0, arcount: 0)
    super
  end
end

Question = Data.define(:name, :_type, :_class)

Answer = Data.define(:name, :_type, :_class, :ttl, :rdlength, :rdata)

def encode_header(header)
  header.deconstruct.pack('nnnnnn')
end

def encode_domain_name(name)
  encoded = "".force_encoding("ASCII-8BIT")
  name.split(".").each do |part|
    encoded += [part.length].pack("C")
    encoded += part.force_encoding("ASCII-8BIT")
  end
  encoded + "\x00"
end

def encode_question(question)
  encoded_name = encode_domain_name(question.name)
  encoded_name + [TYPES.index(question._type), CLASSES.index(question._class)].pack("nn")
end

def send_query(bytes)
  sock = UDPSocket.new
  sock.connect("8.8.8.8", 53)
  sock.send(bytes, 0)
  # DNS responses are specified to max 512 bytes
  resp = sock.recvfrom(1024).first
end

def get_address(domain_name)
  # build query from domain name
  # random non-negative integer representable in 16 bits
  id = rand(MAX_16_BIT + 1)
  # all bits in the flags should be 0, except the 9th from the right that indicates RECURSION_DESIRED
  header = Header.new(id:, flags: 1 << 8, qdcount: 1)
  header_bytes = encode_header(header)
  question = Question.new(name: domain_name, _type: :A, _class: :IN)
  question_bytes = encode_question(question)
  #
  # send over UDP
  # parse and display response
  resp = send_query(header_bytes + question_bytes)
  File.write("resp.bin", resp)
  # decode answer
  io = StringIO.new resp
  io.set_encoding("ASCII-8BIT")
  parse_response(io)
end

def decode_header(header_bytes)
  Header.new(*header_bytes.unpack("nnnnnn"))
end


def decode_question(io)
  name = decode_domain_name(io)

  Question.new(
    name: name,
    _type: TYPES[io.read(2).unpack1('n')],
    _class: CLASSES[io.read(2).unpack1('n')]
  )
end

def parse_rdata(io, answer_type, rdata_len)
  case answer_type
  when :CNAME
    decode_domain_name(io)
  when :A
    # ip address
    # rdata_len is bytes
    io.read(rdata_len).unpack('CCCC').join('.')
  else
    raise NotImplementedError
  end
end


def decode_answer(io)
  domain_name = decode_domain_name(io)
  ans_type = TYPES[io.read(2).unpack1('n')]
  ans_class = CLASSES[io.read(2).unpack1('n')]
  ans_ttl = io.read(4).unpack1('N')
  rdata_len = io.read(2).unpack1('n')
  Answer.new(
    name: domain_name,
    _type: ans_type,
    _class: ans_class,
    ttl: ans_ttl,
    rdlength: rdata_len,
    rdata: parse_rdata(io, ans_type, rdata_len)
  )
end

def decode_domain_name(io)
  # ai slop answer
  domain_name_parts = []

  loop do
    name_len_byte = io.read(1)
    return domain_name_parts.join(".") if name_len_byte.nil?

    name_len = name_len_byte.unpack1('C')

    # Check for compression (top 2 bits are 11)
    if (name_len & COMPRESSION_BITMASK) == COMPRESSION_BITMASK
      # This is a compression pointer
      second_byte = io.read(1)
      return domain_name_parts.join(".") if second_byte.nil?

      pointer = ((name_len & LOWER_ORDER_SIX) << 8) | second_byte.unpack1('C')

      # Save current position
      current_pos = io.pos

      # Jump to pointer location and read the rest
      io.pos = pointer
      remaining_name = decode_domain_name(io)

      # Restore position
      io.pos = current_pos

      # Add the remaining part and we're done (compression always ends the sequence)
      if remaining_name && !remaining_name.empty?
        if domain_name_parts.empty?
          return remaining_name
        else
          return (domain_name_parts + [remaining_name]).join(".")
        end
      else
        return domain_name_parts.join(".")
      end
    elsif name_len == 0
      # End of domain name
      break
    else
      # Normal label
      label = io.read(name_len)
      return domain_name_parts.join(".") if label.nil? || label.length != name_len
      domain_name_parts << label
    end
  end

  domain_name_parts.join(".")
end

# Remove the separate decode_compressed function since we handle it all in decode_domain_name now

def parse_response(io)
  header = decode_header(io.read(12))
  puts header
  # use header to decide number of questions and answers, etc
  questions = []
  header.qdcount.times do
    questions << decode_question(io)
  end
  puts questions
  answers = []
  header.ancount.times do
    answers << decode_answer(io)
  end
  puts answers
end

get_address "www.example.com".force_encoding("ASCII-8BIT")