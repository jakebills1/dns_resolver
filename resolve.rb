require 'stringio'
require 'socket'
require 'pry'

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

def get_address(domain_name)
  # build query from domain name
  id = rand(65536) # random non-negative integer representable in 16 bits
  # all bits in the flags should be 0, except the 9th from the right that indicates RECURSION_DESIRED
  header = Header.new(id:, flags: 1 << 8, qdcount: 1)
  header_bytes = encode_header(header)
  question = Question.new(name: domain_name, _type: :A, _class: :IN)
  question_bytes = encode_question(question)
  #
  # send over UDP
  # parse and display response
  sock = UDPSocket.new
  sock.connect("8.8.8.8", 53)
  sock.send(header_bytes + question_bytes, 0)
  # DNS responses are specified to max 512 bytes
  resp = sock.recvfrom(1024).first
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
  initial_name_len = io.read(1).unpack1('C')
  name = decode_domain_name(io, initial_name_len)

  Question.new(
    name: name,
    _type: TYPES[io.read(2).unpack1('n')],
    _class: CLASSES[io.read(2).unpack1('n')]
  )
end

def parse_rdata(io, answer_type, rdata_len)
  case answer_type
  when :CNAME
    decode_domain_name(io, io.read(1).unpack1('C'))
  when :A
    # ip address
    # rdata_len is bytes
    io.read(rdata_len).unpack('CCCC').join('.')
  else
    raise NotImplementedError
  end
end

def decode_answer(io)
  name_len_raw = io.read(1)
  name_len = name_len_raw.unpack1('C')
  if name_len_raw.to_i & 0b1100_0000 # using DNS compression
    second_byte = io.read(1)
    pointer = ((name_len & 0b0011_1111) << 8) | second_byte.unpack1('C')
    current_pos = io.tell
    io.pos = pointer
    domain_name = decode_domain_name(io, io.read(1).unpack1('C'))
    io.pos = current_pos
  else
    domain_name = decode_domain_name(io, name_len)
  end
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

def decode_domain_name(io, name_len)
  # todo labels can also be pointers ...
  domain_name_parts = []
  until name_len == 0
    domain_name_parts << io.read(name_len)
    name_len = io.read(1).unpack1('C')
  end
  domain_name_parts.join(".")
rescue NoMethodError => e
  binding.pry
end

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

get_address "example.com".force_encoding("ASCII-8BIT")