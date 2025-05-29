require 'stringio'
require 'socket'
require 'ipaddr'
require 'dns_resolver/header'
require 'dns_resolver/question'
require 'dns_resolver/answer'
require 'dns_resolver/response'

class DNSResolver

  def resolve(domain_name, query_type)
    query_type = query_type.upcase.to_sym
    nameserver = ROOT_NS_IP
    loop do
      puts "Querying #{nameserver} for #{domain_name}"
      response = get_address domain_name, query_type, nameserver
      answer = response.answers.first
      if answer
        return answer.rdata.to_s
      end
      ns_ip = response.addl_records.find { |record| record._type == :A }&.rdata&.to_s
      if ns_ip
        nameserver = ns_ip
      else # we don't have IP address for the nameserver that has this information
        ns = response.nameservers.first.rdata.to_s
        # use resolve to get IP address
        nameserver = resolve(ns, :A)
      end
    end
  end

  private
  
  MAX_16_BIT = 2 ** 16 - 1
  COMPRESSION_BITMASK = 0b1100_0000
  LOWER_ORDER_SIX = ~COMPRESSION_BITMASK
  ROOT_NS_IP = "198.41.0.4"

  TYPES = {
    1 => :A,
    2 => :NS,
    3 => :MD,
    4 => :MF,
    5 => :CNAME,
    6 => :SOA,
    7 => :MB,
    8 => :MG,
    9 => :MR,
    10 => :NULL,
    11 => :WKS,
    12 => :PTR,
    13 => :HINFO,
    14 => :MINFO,
    15 => :MX,
    16 => :TXT,
    28 => :AAAA
  }

  CLASSES = {
    1 => :IN,
    2 => :CS,
    3 => :CH,
    4 => :HS
  }

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
    encoded_name + [TYPES.key(question._type), CLASSES.key(question._class)].pack("nn")
  end

  def send_query(bytes, nameserver_ip)
    sock = UDPSocket.new
    sock.connect(nameserver_ip, 53)
    sock.send(bytes, 0)
    # DNS responses are specified to max 512 bytes
    sock.recvfrom(1024).first
  end

  def get_address(domain_name, query_type, nameserver_ip)
    # build query from domain name
    # random non-negative integer representable in 16 bits
    id = rand(MAX_16_BIT + 1)
    # all bits in the flags should be 0, except the 9th from the right that indicates RECURSION_DESIRED
    header = Header.new(id:, flags: 0, qdcount: 1)
    header_bytes = encode_header(header)
    question = Question.new(name: domain_name, _type: query_type, _class: :IN)
    question_bytes = encode_question(question)
    #
    # send over UDP
    # parse and display response
    resp = send_query(header_bytes + question_bytes, nameserver_ip)
    # File.write("resp.bin", resp)
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
    when :A, :AAAA
      IPAddr.new_ntoh(io.read(rdata_len))
    when :NS
      decode_domain_name(io)
    else
      raise NotImplementedError, "parsing rdata for #{answer_type} records is not implemented"
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

  def parse_response(io)
    header = decode_header(io.read(12))
    # puts header
    # use header to decide number of questions and answers, etc
    questions = []
    header.qdcount.times do
      questions << decode_question(io)
    end
    # puts questions
    answers = []
    header.ancount.times do
      answers << decode_answer(io)
    end
    # puts answers
    nameservers = []
    header.nscount.times do
      nameservers << decode_answer(io)
    end
    # puts nameservers
    addl_records = []
    header.arcount.times do
      addl_records << decode_answer(io)
    end
    # puts addl_records

    Response.new(
      header:,
      questions:,
      answers:,
      nameservers:,
      addl_records:
    )
    # algorithm for recursively finding A records
    # 1. if answers section including A records display answer
    # 2. if answers did not include A records:
    # 3. find IP address in addl_records corresponding to nameservers
    # 4. for each IP address (?)
    # 5. send original query over UDP to that IP addr
    # 6. goto 1
    #
  end
end
